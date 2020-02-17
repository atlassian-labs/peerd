#!/usr/bin/env python
"""
peerd: AWS VPC Peering Management Tool
"""

# Built-in libraries
import sys
import argparse
import logging
import logging.handlers
import time
import socket

# Third-party libraries
import yaml

try:
    import coloredlogs
except ImportError:
    pass

# peerd
import peerd.aws
from peerd.filters import chunk_list, filter_working_accounts, target_vpc_peerings
from peerd.aws import describe_vpc_cached
from peerd.core import accept_vpc_peerings, create_vpc_peerings, update_route_tables, delete_unneeded_peerings

# Logging
# Default loglevels.
# If this script is called as a script with --debug, this will be overridden.
LOGLEVEL = logging.INFO
# If you want a different level for any destination, you can set it here.
# 'False' means "don't override the default."
LOGLEVEL_STDOUT = False
LOGLEVEL_FILE = False
LOGLEVEL_SYSLOG = False
#
# File logging
# To disable logging to file, set this to False
LOGFILE = "./peerd.log"
#
# STDOUT logging
# To disable, set this to False
#
LOGSTDOUT = True
# Syslog
# To enable logging to syslog, set this to a valid address attribute for a
# logging.handlers.SysLogHandler object, e.g. '/dev/log' or
# `(logserver.example.com, 514)`.
# To send to syslog on the local host, just set this to True.
# For reference:
# https://docs.python.org/2/library/logging.handlers.html#logging.handlers.SysLogHandler
SYSLOGADDR = False


class CallCounted():
    """Decorator to determine number of calls for a method."""

    def __init__(self, method):
        self.method = method
        self.counter = 0

    def __call__(self, *args, **kwargs):
        self.counter += 1
        return self.method(*args, **kwargs)


class ContextFilter(logging.Filter):
    hostname = socket.gethostname()

    def filter(self, record):
        record.hostname = ContextFilter.hostname
        return True


def set_up_logging():
    """
    Generate a logger object that can be used by the other functions in this script
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(LOGLEVEL)
    f = ContextFilter()
    logger.addFilter(f)
    formatter = logging.Formatter(
        '%(asctime)s %(hostname)s peerd[%(process)d]: %(levelname)s %(message)s',
        '%b %d %H:%M:%S'
    )
    logging.Formatter.converter = time.gmtime

    # Count errors and warnings
    logger.error = CallCounted(logger.error)
    logger.warning = CallCounted(logger.warning)

    # STDOUT handler
    if LOGSTDOUT:
        stdout = logging.StreamHandler(sys.stdout)
        if LOGLEVEL_STDOUT:
            stdout.setLevel(LOGLEVEL_STDOUT)
        else:
            stdout.setLevel(LOGLEVEL)
        stdout.setFormatter(formatter)
        logger.addHandler(stdout)
    # File handler
    if LOGFILE:
        filelog = logging.FileHandler(LOGFILE)
        if LOGLEVEL_FILE:
            stdout.setLevel(LOGLEVEL_FILE)
        else:
            stdout.setLevel(LOGLEVEL)
        filelog.setFormatter(formatter)
        logger.addHandler(filelog)
    # Syslog handler
    if SYSLOGADDR:
        # Should we use the default address for the destination?
        if SYSLOGADDR is True:
            syslog_addr = ('localhost', 514)
        # Or should we accept what we're given?
        else:
            syslog_addr = SYSLOGADDR
        # Now create the handler
        syslog = logging.handlers.SysLogHandler(address=syslog_addr)
        # Set the level
        if LOGLEVEL_SYSLOG:
            stdout.setLevel(LOGLEVEL_SYSLOG)
        else:
            stdout.setLevel(LOGLEVEL)
        syslog.setFormatter(formatter)
        logger.addHandler(syslog)

    # Add colour formatting to terminal logging
    try:
        coloredlogs.install(
            fmt='%(asctime)s peerd: %(levelname)s %(message)s',
            level='DEBUG',
            logger=logger,
        )
    except BaseException:
        pass

    return logger


#
# Supporting functions
#
def parseargs():
    """
    Parse the command-line arguments, if this was invoked as a script.
    """
    arg_parser = argparse.ArgumentParser(description='AWS VPC Peering Management Tool')
    arg_parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help='Set log-level to DEBUG'
    )
    arg_parser.add_argument(
        '--config',
        '-c',
        action='store',
        default='./config.yaml',
        required=True,
        help='Path to configuration file',
    )
    arg_parser.add_argument(
        '--environment',
        '-e',
        action='store',
        required=True,
        help='Only execute the script on this environment',
    )
    arg_parser.add_argument(
        '--dryrun',
        '-d',
        action='store_true',
        default=False,
        help='Only check for peerings which might be created or deleted. No changes made to mesh.',
    )
    # arg_parser.add_argument(
    #     '--delete',
    #     '-d',
    #     action='store_true',
    #     default=False,
    #     help='Allows the script to delete superfluous peerings. Otherwise no cleanup is done.',
    # )
    return arg_parser.parse_args()


#
# Main
#
def main(args):
    """
    App entrypoint.
    """
    logger = set_up_logging()
    # Set logging level depending on arguments
    if args.debug:
        logger.setLevel(logging.DEBUG)
    logger.info('peerd: AWS VPC Peering Management Tool')

    # Read the configuration file
    # The configuration file is a YAML file containing the regions, accounts, environments
    # and VPCs to be peered with one another
    with open(args.config, 'r') as fh:
        config_file = yaml.safe_load(fh)

    # Assemble the metadata
    metadata = config_file['metadata']
    # Add the chosen environment name to the metadata
    metadata['environment'] = args.environment
    raw_config = config_file['environments'][args.environment]

    # Set required variables from metadata:
    peerd.aws.COMMON_PRINCIPAL_NAME = metadata['common_principal_name']
    peerd.aws.ROLE_SESSION_NAME = metadata['role_session_name']

    # Filter the configuration for only working AWS Account Ids
    filtered_config = filter_working_accounts(raw_config)
    # Filter for only VPCs which exist
    filtered_config[:] = [x for x in filtered_config if describe_vpc_cached(**x)]

    # Get the peerings which should exist in this environment
    target_peerings = target_vpc_peerings(filtered_config)

    # Create and accept vpc peerings.
    # We must chunk the target_peerings into 25 as no single VPC may have more then 25
    # outstanding peering requests.
    for chunked_peerings in chunk_list(target_peerings, 25):
        pending_acceptance_peerings = create_vpc_peerings(chunked_peerings, metadata, args.dryrun)
        accept_vpc_peerings(pending_acceptance_peerings, metadata, args.dryrun)

    # Manage the route tables for the peerings
    update_route_tables(target_peerings, metadata, args.dryrun)

    # Delete unneeded peerings
    # We pass in the unfiltered config here to avoid a situation where we remove peerings
    # just because the role is unavailable temporarily.
    # i.e We do not want to delete peerings just because an IAM policy is broken.
    # We want to delete peerings when they are unconfigured from the raw, original configuration.
    delete_unneeded_peerings(raw_config, metadata, args.dryrun)

    # Print out the number of warnings or errors, if any.
    logger.info(f'Number of warnings: {logger.warning.counter}')
    logger.info(f'Number of errors: {logger.error.counter}')
    if logger.error.counter > 0:
        logger.error('Number of errors greater than one. Setting non-zero exit code. Inspect logs.')
        sys.exit(1)


if __name__ == '__main__':
    # Run the main function of the program.
    main(parseargs())
