# Built in
from datetime import timedelta
import json
import sys
from time import sleep
from typing import Any, List, Mapping, Optional

# Third Party
import boto3
import botocore
from botocore.config import Config
import cachetools

# Local
from peerd import LOGGER, nested_dict
from peerd.decorators import memoize

# Global data structures

# Global variablees
COMMON_PRINCIPAL_NAME: Optional[str] = None
ROLE_SESSION_NAME: Optional[str] = None


# The sts client and credentials are generally valid for 60 minutes
# We use 55 minutes here to be safe
@cachetools.cached(cachetools.TTLCache(10000, 55*60))
def aws_sts_client() -> Any:
    """
    Uses default boto credentials locations, such as the instance metadata
    to return a sts client connection and caches it as a global variable for reuse.

    :returns: AWS STS client connection
    """

    sts_client = boto3.client('sts', config=Config(retries=dict(max_attempts=10)))
    LOGGER.info(f'Found the following STS identity:\n{json.dumps(sts_client.get_caller_identity(), indent=2)}')
    return sts_client


# We cache the iam role credentials for less time than the client to avoid 
# creating new clients with old credentials
@cachetools.cached(cachetools.TTLCache(10000, 29*60))
def get_role_credentials(account: str, sts_client: Any) -> dict:
    """
    Assumes a role and returns credentials for said role.
    Requires the COMMON_PRINCIPAL_NAME to be set, usually from metadata.

    Example returned dictionary:
    ```
    {
        "Expiration": "2020-01-27T11:55:44Z",
        "Token": "abc123",
        "SecretAccessKey": "def456",
        "AccessKeyId": "ABCDEF123",
        "Type": "AWS-SOMETHING",
        "LastUpdated": "2020-01-27T10:55:45Z",
        "Code": "Success"
    }

    :param account: An AWS account id number
    :type account: str
    :param sts_client: an aws client connection to the sts service
    :type resource: boto3 client
    :returns: Dictionary containing the credentials from the assume role action
    :rtype: dict
    """
    try:
        arn = f'arn:aws:iam::{account}:role/{COMMON_PRINCIPAL_NAME}'
        LOGGER.info(f'Attempting to tokenise into: {arn}')
        credentials = sts_client.assume_role(RoleArn=arn, RoleSessionName=ROLE_SESSION_NAME)['Credentials']
        LOGGER.info(f'Successfully tokenised into: {arn}')
        return credentials
    except BaseException:
        LOGGER.warning("Unexpected error: %s", sys.exc_info()[1], exc_info=True)
        return {}


# AWS Clients, via associated credentials, are valid for 60 minutes. To be safe we use 30.
@cachetools.cached(cachetools.TTLCache(10000, 30*60))
def aws_client(account: str, service: str, region: str) -> Any:
    """
    Initialises a sts client, gets assume role credentials
    and initialises a AWS client connection to a requested resource.
    Returns the AWS product/resource client connection.
    Caches the client connection for re-use.
    For reference: http://boto3.readthedocs.io/en/latest/guide/configuration.html

    :param account: An AWS account id number
    :type account: str
    :param service: An AWS service e.g. ec2
    :type service: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    """

    # In this block we get credentials for the target account by assuming
    # into the given account using a sts client connection
    # If we can't we return none and cache none.
    if not (credentials := get_role_credentials(account, aws_sts_client())):
        LOGGER.warning(f'Unable to tokenise into {account} for service {service} in region {region}. Moving on')
        return None

    # In this block we use the account credentials we got above, to create and cache a client
    # connection to an AWS service.
    try:
        client =  boto3.client(
            service,
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            config=Config(retries=dict(max_attempts=10)))
        LOGGER.debug('Obtained fresh client connection.')
        return client
    except BaseException:
        LOGGER.error(f'Unexpected error: {sys.exc_info()[1]}', exc_info=True)


def tag_resource(client: Any, resource: str, tags: Mapping, dryrun: bool = False) -> None:
    """
    Tags an AWS resource with the provided tags.

    Example Usage:
    ```
    ec2_client = aws_client(account_id, 'ec2', region)
    tags = {'peerd_support': 'me@email.com',
            'peerd_datetime': str(datetime.now())}
    tag_resource(ec2_client, peerding_id, tags)
    ```
    :param client: An AWS boto3 client connection to an AWS resource
    :type client: boto3 client
    :param resource: The name of the resource e.g. rt-abc123
    :type resource: string
    :param tags: Dictionary of tags to apply to a resource
    :type tags: dict
    :returns: Nothing
    :raises BaseException: Raises an exception if there was some problem tagging the resource
    """
    tags_aws = [{'Key': key, 'Value': value} for (key, value) in tags.items()]

    for x in range(5):
        try:
            LOGGER.debug(f'Tagging {resource}')
            client.create_tags(Resources=[resource], Tags=tags_aws, DryRun=dryrun)
            LOGGER.debug(f'Tagging {resource} successful')
            return
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'DryRunOperation':
                LOGGER.debug(f'Tagging {resource} successful')
                return
            LOGGER.info(f'Tagging {resource} encountered error: {err.response["Error"]["Message"]}. Will retry.')
            sleep(1)
            continue
        except BaseException:
            LOGGER.warning("Unexpected error: %s", sys.exc_info()[1], exc_info=True)

    raise Exception(f'Could not tag resource {resource}')


@memoize()
def check_iam_role_capability(account_id: str) -> bool:
    """
    Check that we can assume a role in each account and perform an ec2 action to validate it.
    Allows us to filter out accounts which do not work for the script and inform the user.

    :param account_id: An AWS Account Id
    :type account_id: str
    :returns: True if the role and EC2 client works. False otherwise.
    :rtype: bool
    """
    try:
        if ec2_client := aws_client(account_id, 'ec2', 'us-east-1'):
            ec2_client.describe_vpcs()
            LOGGER.info(f'Able to assume role in {account_id} and access the EC2 API.')
            return True
        LOGGER.warning(f'Unable to assume role in {account_id} and access the EC2 API.')
    except BaseException:
        LOGGER.warning(f'Unable to assume role in {account_id} and access the EC2 API.')
        LOGGER.error(f'Unexpected error: {sys.exc_info()[1]}', exc_info=True)
    return False


@memoize()
def describe_account_vpcs_cached(account_id: str, region: str) -> List[dict]:
    """
    Describe all the VPCs in a given account in a given region and return them as a list of descriptions
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs

    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    :returns: A list of dictionaries representing all the VPCs for a given account and region.
    :rtype: list
    """
    LOGGER.info(f'Fetching description of all VPCs for account {account_id} in region {region}')
    ec2_client = aws_client(account_id, 'ec2', region)
    return ec2_client.describe_vpcs()['Vpcs']


@memoize()
def describe_vpc_cached(vpc_id: str, account_id: str, region: str, **kwargs) -> Optional[dict]:
    """
    Describe a specific VPC from our cache of VPC descriptions for a given account and region
    Return a dict if things go as expected.

    We accept additional arguments here to handle the case where the arguments are given as
    a dictionary with additional keys. Such as when filtering the main config for only VPCs
    which actually exist.

    :param vpc_id: A vpc id e.g. vpc-abc123
    :type vpc_id: str
    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    :param **kwargs: Handle trailing arguments in case where dictionary of arguments is provided.
    :type **kwargs: dict
    :returns: A list of dictionaries representing all the VPCs for a given account and region.
    :rtype: list
    """
    LOGGER.debug(f'Fetching description of VPC {vpc_id} for account {account_id} in region {region}')
    vpcs = describe_account_vpcs_cached(account_id, region)
    if vpc_dict := next((x for x in vpcs if x['VpcId'] == vpc_id), None):
        return vpc_dict

    LOGGER.warning(f'VPC {vpc_id} for account {account_id} in region {region} does not exist')
    return {}


@memoize()
def list_vpc_cidrs(vpc_id: str, account_id: str, region: str) -> List[str]:
    """
    Returns a list of vpc cidrs associated with a given vpc.
    Example use cases:
    1. Get the CIDRs to install on other side of a peering.
    2. See if there are any common CIDRs between two VPCs

    :param vpc_id: A vpc id e.g. vpc-abc123
    :type vpc_id: str
    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    :returns: A list of CIDRs associated with a given VPC.
    :rtype: list
    """
    vpc = describe_vpc_cached(vpc_id, account_id, region)
    return [x['CidrBlock'] for x in vpc['CidrBlockAssociationSet']]


@memoize()
def get_all_peerings(account_id: str, region: str, filters: list = []) -> List[dict]:
    """
    Return a list of all the peerings for a given account, region and filter
    Caches the result.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections

    Example of filters
    ```
    filters = [{'Name': 'tag:peerd_created', 'Values': ['true']},
                   {'Name': 'tag:peerd_environment', 'Values': [metadata['environment']]},
                   {'Name': 'status-code', 'Values': ['active']}]\
    ```

    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    :returns: A list containing all peering dictionaries for an account-region.
    :rtype: list
    """
    ec2_client = aws_client(account_id, 'ec2', region)
    vpc_peerings = ec2_client.describe_vpc_peering_connections(Filters=filters)['VpcPeeringConnections']
    return [x for x in vpc_peerings if x['Status']['Code'] not in ['deleted', 'rejected']]


def get_vpc_peering(vpc_id: str, remote_vpc_id: str, account_id: str, region: str, filters: list = []) -> Optional[dict]:
    """
    Returns a dictionary describing a specific VPC peering between two VPCs
    From the perspective of a given account.
    Note: Same peering can have slightly different content based on perspective account.
    Note: This function is greedy in the sense that the requester does not have to be
    the requester as AWS defines it in https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html
    This function will match peerings even when the remote_vpc_id is the requester.

    Example usage:
    ```
    filters = [{'Name': 'tag:peerd_created', 'Values': ['true']},
                   {'Name': 'tag:peerd_environment', 'Values': [metadata['environment']]},
                   {'Name': 'status-code', 'Values': ['active']}]
        if not (peering := get_vpc_peering(vpc_id, remote_vpc_id, account_id, region, filters)):
            LOGGER.warning(f'No active peering between {vpc_id} and {remote_vpc_id} for this environment'
                           f' {metadata["environment"]}. It may exist as part of another environment.')
            continue
    ```


    :param vpc_id: A vpc id e.g. vpc-abc123
    :type vpc_id: str
    :param remote_vpc_id: A vpc id e.g. vpc-abc123
    :type remote_vpc_id: str
    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region. e.g. us-east-1
    :type region: str
    :param filters: A standard list of boto3 filters (list of dics).
    :type filters: list
    :returns: A list containing all peering dictionaries for an account-region.
    :rtype: list
    """
    vpc_peerings = get_all_peerings(account_id, region, filters)
    for peering in vpc_peerings:
        if peering['AccepterVpcInfo']['VpcId'] in [vpc_id, remote_vpc_id]:
            if peering['RequesterVpcInfo']['VpcId'] in [vpc_id, remote_vpc_id]:
                LOGGER.debug(f"Found peering {peering['VpcPeeringConnectionId']} between {vpc_id} and {remote_vpc_id}")
                return peering
    LOGGER.debug(f"No active peering between {vpc_id} and {remote_vpc_id} for given filters {filters}")
    return None


@memoize()
def account_route_tables(account_id: str, region: str) -> list:
    """
    Return a list of all route tables for a given account and region
    Caches the result to avoid uneccessary additional api calls.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html
    Important: Always filters for only peerd_eligible true tagged tables.

    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    :returns: A list containing all route tables for an account-region.
    :rtype: list
    """
    ec2_client = aws_client(account_id, 'ec2', region)
    filters = [{'Name': 'tag:peerd_eligible', 'Values': ['true']}]
    return ec2_client.describe_route_tables(Filters=filters)['RouteTables']


def vpc_route_tables(vpc_id: str, account_id: str, region: str) -> list:
    """
    Return a list of all route tables (peerd_eligible:true) for a given vpc in an account region.
    Note: The reason we don't do this via a filtered api call is to avoid additional api calls
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html

    :param vpc_id: A vpc id e.g. vpc-abc123
    :type vpc_id: str
    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    :returns: A list containing all route tables for the vpc
    :rtype: list
    """
    return [x for x in account_route_tables(account_id, region) if x.get('VpcId', '') == vpc_id]
