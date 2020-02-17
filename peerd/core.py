# Built in
from copy import deepcopy
from datetime import datetime
from time import sleep
from typing import Mapping, Sequence
import sys

# Third Party
from botocore.exceptions import ClientError

# Local
from peerd import LOGGER
from peerd.aws import (aws_client, get_vpc_peering, list_vpc_cidrs, tag_resource,
                       vpc_route_tables)
from peerd.filters import (filter_working_accounts, get_all_env_peerings, get_deletable_peerings,
                           list_dict_values)


def create_vpc_peerings(target_peerings: Sequence, metadata: Mapping, dryrun: bool) -> None:
    """
    Loops through a list of peerings to create them.
    Requests, accepts and tags them.
    Repairs any half open peerings.

    Example target_peerings:
    ```
    [
        [
        {
            "account_id": 415432961280,
            "vpc_id": "vpc-e08fb484",
            "region": "ap-southeast-2",
            "cidr_overrides": [
                "10.53.101.0/27"
            ],
            "peering_tags": [
                {
                "peerd_az_affinity": "0"
                }
            ]
        },
        {
            "account_id": 415432961280,
            "vpc_id": "vpc-7a83b81e",
            "region": "ap-southeast-2"
        }
        ]
    ]
    ```

    :param target_peerings: A list of lists representing the requester and accepter for each peering.
    :type target_peerings: list
    :param metadata: A dictionary with the environment, owner, etc for tagging
    :type metadata: list
    """
    pending_acceptance_peerings = []
    for peering_descriptor in target_peerings:

        # Unpack some common variables
        account_id = peering_descriptor[0]['account_id']
        vpc_id = peering_descriptor[0]['vpc_id']
        region = peering_descriptor[0]['region']
        local_tags = peering_descriptor[0].get('peering_tags', {})

        remote_account_id = peering_descriptor[1]['account_id']
        remote_vpc_id = peering_descriptor[1]['vpc_id']
        remote_region = peering_descriptor[1]['region']
        remote_tags = peering_descriptor[1].get('peering_tags', {})

        # Create a VPC peering request
        try:
            ec2_client = aws_client(account_id, 'ec2', region)
            # If the peering doesn't exist, create it
            if not (peering := get_vpc_peering(vpc_id, remote_vpc_id, account_id, region)):
                LOGGER.info(f"Creating peering request between {account_id} {vpc_id} {region}"
                            f" and {remote_account_id} {remote_vpc_id} {remote_region}")
                try:
                    ec2_peering_response = ec2_client.create_vpc_peering_connection(
                        VpcId=vpc_id,
                        PeerVpcId=remote_vpc_id,
                        PeerOwnerId=remote_account_id,
                        PeerRegion=remote_region,
                        DryRun=dryrun)['VpcPeeringConnection']
                except ClientError as err:
                    if err.response['Error']['Code'] == 'DryRunOperation':
                        continue
                    raise
                peering_id = ec2_peering_response['VpcPeeringConnectionId']
                # Wait for the vpc peering to exist before moving on
                LOGGER.info(f'Waiting for peering {peering_id} to exist...')
                ec2_client.get_waiter('vpc_peering_connection_exists').wait(
                    VpcPeeringConnectionIds=[peering_id], WaiterConfig={'Delay': 5})
            # If the peering exists and is active, do nothing.
            elif peering['Status']['Code'] == 'active':
                LOGGER.info(f"Active peering {peering['VpcPeeringConnectionId']} between {account_id} {vpc_id} {region}"
                            f" and {remote_account_id} {remote_vpc_id} {remote_region}")
                continue
            # If the peering is pending acceptance move to tagging and acceptance
            # Only the remote account can accept the VPC peering.
            elif peering['Status']['Code'] == 'pending-acceptance' and peering['RequesterVpcInfo']['VpcId'] == vpc_id:
                peering_id = peering['VpcPeeringConnectionId']
                LOGGER.warning(f"Pending-Acceptance peering {peering_id} between {account_id} {vpc_id} {region}"
                               f" and {remote_account_id} {remote_vpc_id} {remote_region}. Will attempt recovery.")
            # We're in some weird state and need to report to a human
            else:
                LOGGER.warning(f"Peering between {account_id} {vpc_id} {region}"
                               f" and {remote_account_id} {remote_vpc_id} {remote_region}"
                               f" is in state {peering['Status']['Code']}.")
                continue
            # Tag the VPC Peering
            tags = {
                'Name': f'peerd peering to {remote_account_id} {remote_vpc_id} {remote_region}',
                'resource_owner': metadata['resource_owner'],
                'business_unit': metadata['business_unit'],
                'service_name': metadata['service_name'],
                'peerd_created': 'true',
                'peerd_support': metadata['support'],
                'peerd_datetime': str(datetime.now()),
                'peerd_role': 'requester',
                'peerd_environment': metadata['environment']
            }
            for key, value in local_tags.items():
                tags[key] = value
            for key, value in remote_tags.items():
                tags[key] = value
            tag_resource(ec2_client, peering_id, tags, dryrun=dryrun)

            # Add the peering to the list of peerings that we will need to accept
            peering_descriptor_copy = deepcopy(peering_descriptor)
            peering_descriptor_copy[1]['peering_id'] = peering_id
            peering_descriptor_copy[1]['tags'] = tags
            pending_acceptance_peerings.append(peering_descriptor_copy)

        except BaseException:
            LOGGER.error("Unexpected error: %s", sys.exc_info()[1], exc_info=True)
            continue

        LOGGER.info(f"Successfully created peering request {peering_id} between {account_id} {vpc_id} "
                    f"{region} and {remote_account_id} {remote_vpc_id} {remote_region}")

    # Return the list of peerings that need to be accepted.
    return pending_acceptance_peerings


def accept_vpc_peerings(target_peerings: list, metadata: dict, dryrun: bool):
    """
    Loops through a list of peerings, with existing peering id, to accept them.
    Requests, accepts and tags them.
    Repairs any half open peerings.

    Example target_peerings:
    ```
    [
        [
        {
            "account_id": "415432961280",
            "peering_id": "pcx-41u5h345h2",
            "vpc_id": "vpc-e08fb484",
            "region": "ap-southeast-2",
            "cidr_overrides": [
                "10.53.101.0/27"
            ],
            "peering_tags": [
                {
                "peerd_az_affinity": "0"
                }
            ]
        },
        {
            "account_id": 415432961280,
            "peering_id": "pcx-41u5h345h2",
            "vpc_id": "vpc-7a83b81e",
            "region": "ap-southeast-2"
        }
        ]
    ]
    ```

    :param target_peerings: A list of lists representing the requester and accepter for each peering.
    :type target_peerings: list
    :param metadata: A dictionary with the environment, owner, etc for tagging
    :type metadata: list
    """
    for peering_descriptor in target_peerings:

        # Unpack some common variables
        account_id = peering_descriptor[0]['account_id']
        vpc_id = peering_descriptor[0]['vpc_id']
        region = peering_descriptor[0]['region']
        local_tags = peering_descriptor[0].get('peering_tags', {})

        remote_account_id = peering_descriptor[1]['account_id']
        remote_vpc_id = peering_descriptor[1]['vpc_id']
        remote_region = peering_descriptor[1]['region']
        remote_tags = peering_descriptor[1].get('peering_tags', {})
        peering_id = peering_descriptor[1]['peering_id']
        tags = peering_descriptor[1]['tags']

        try:
            # Accept the VPC Peering
            LOGGER.info(f"Accepting peering request {peering_id} between {account_id} {vpc_id} {region} and "
                        f"{remote_account_id} {remote_vpc_id} {remote_region}")
            ec2_client = aws_client(remote_account_id, 'ec2', remote_region)
            # Wait until the peering exists
            # The AWS API is eventually consistent and we need to wait.
            LOGGER.info(f'Waiting for peering to exist...')
            ec2_client.get_waiter('vpc_peering_connection_exists').wait(
                VpcPeeringConnectionIds=[peering_id], WaiterConfig={'Delay': 5})
            # Tag the VPC Peering
            tags['Name'] = f'peerd peering to {account_id} {vpc_id} {region}'
            tags['peerd_role'] = 'accepter'
            tag_resource(ec2_client, peering_id, tags, dryrun=dryrun)
            # Accept the peering
            try:
                ec2_client.accept_vpc_peering_connection(VpcPeeringConnectionId=peering_id, DryRun=dryrun)
            except ClientError as err:
                if err.response['Error']['Code'] == 'DryRunOperation':
                    continue
                raise
        except BaseException:
            LOGGER.error("Unexpected error: %s", sys.exc_info()[1], exc_info=True)
            continue

        LOGGER.info(f"Successfully accepted peering {peering_id} between {account_id} {vpc_id} "
                    f"{region} and {remote_account_id} {remote_vpc_id} {remote_region}")


def update_route_tables(target_peerings: list, metadata: Mapping, dryrun: bool) -> None:
    """
    Loops through a list of peerings and updates the route tables on each side.

    Example target_peerings:
    ```
    [
        [
        {
            "account_id": 415432961280,
            "vpc_id": "vpc-e08fb484",
            "region": "ap-southeast-2",
            "cidr_overrides": [
                "10.53.101.0/27"
            ],
            "peering_tags": [
                {
                "peerd_az_affinity": "0"
                }
            ]
        },
        {
            "account_id": 415432961280,
            "vpc_id": "vpc-7a83b81e",
            "region": "ap-southeast-2"
        }
        ]
    ]
    ```

    :param target_peerings: A list of lists representing the requester and accepter for each peering.
    :type target_peerings: list
    :param metadata: A dictionary with the environment, owner, etc for tagging
    :type metadata: list
    """

    # We need to handle both sides of the peerings so we append reverse of each peering.
    # This means every side of every peering will be seen by a single loop.
    # We do this to avoid extra code handling the AWS concept of "accepter" and "requester"
    # We also construct our route table cache by account and region, which means if we looped
    # by requester and accepter we could cache stale route table contents.
    target_peerings.extend([x[::-1] for x in target_peerings])

    # Loop through the target peerings
    for peering_descriptor in target_peerings:
        # Unpack some common variables
        account_id = peering_descriptor[0]['account_id']
        vpc_id = peering_descriptor[0]['vpc_id']
        region = peering_descriptor[0]['region']

        remote_account_id = peering_descriptor[1]['account_id']
        remote_vpc_id = peering_descriptor[1]['vpc_id']
        remote_region = peering_descriptor[1]['region']
        # Get the remote CIDRs from the AWS VPC API, or use the overrides in the config if they exist.
        remote_cidrs = peering_descriptor[1].get('cidr_overrides', list_vpc_cidrs(remote_vpc_id, remote_account_id, remote_region))

        LOGGER.info(f"Inspecting route tables in {account_id} {vpc_id} "
                    f"{region}, peer: {remote_account_id} {remote_vpc_id} {remote_region}")

        # Initialise a ec2 client connection
        ec2_client = aws_client(account_id, 'ec2', region)

        # Get active VPC peering if one exists, else continue
        # We want to avoid adding routes for inactive peerings.
        filters = [{'Name': 'tag:peerd_created', 'Values': ['true']},
                   {'Name': 'tag:peerd_environment', 'Values': [metadata['environment']]},
                   {'Name': 'status-code', 'Values': ['active', 'provisioning']}]
        if not (peering := get_vpc_peering(vpc_id, remote_vpc_id, account_id, region, filters)):
            # Since we filter for the peerd environment, remind the user that there could be a peering
            # But that it might exist as part of another environment, and thus we won't be touching it.
            LOGGER.warning(f'No active peering between {vpc_id} and {remote_vpc_id} for this environment'
                           f' {metadata["environment"]}. It may exist as part of another environment.')
            continue
        peering_id = peering['VpcPeeringConnectionId']

        # Wait until the peering is active, not provisioning (boto waiter doesn't accept filters for vpc peering api)
        # We must wait for active state to install routes, otherwise the peering will be ignored.
        # Note, usually this step takes a few seconds, but can sometimes take up to a minute or two in rare cases.
        if peering['Status']['Code'] == 'provisioning':
            while not ec2_client.describe_vpc_peering_connections(
                    Filters=[
                        {'Name': 'status-code', 'Values': ['active']},
                        {'Name': 'vpc-peering-connection-id', 'Values': [peering_id]}]
                    )['VpcPeeringConnections']:
                LOGGER.info(f'Waiting for peering {peering_id} to become active...')
                sleep(5)

        # Get the route tables for the local vpc relevant to the peering.
        # The vpc_route_tables function will only return peerd_eligible:true tables
        # Since we will have cases where RTs should not be altered.
        if not (route_tables := vpc_route_tables(vpc_id, account_id, region)):
            LOGGER.warning(f'No peerd_eligible route tables in VPC {vpc_id}')
            continue

        # For each route table in the vpc
        for route_table in route_tables:
            route_table_id = route_table['RouteTableId']
            route_table_modified = False
            for cidr in remote_cidrs:
                for route in route_table['Routes']:
                    # Find any existing route for this cidr
                    # Handle case the route is not a ipv4 route, e.g. S3 endpoint
                    if route.get('DestinationCidrBlock', None) == cidr:
                        # Handle some edge cases
                        # Delete the cidr if it points at a blackhole
                        if route['State'] == 'blackhole':
                            LOGGER.warning(f'Blackhole in: {account_id} {vpc_id} {route_table_id} for {cidr}. Deleting.')
                            try:
                                ec2_client.delete_route(RouteTableId=route_table_id,
                                                        DestinationCidrBlock=route['DestinationCidrBlock'],
                                                        DryRun=dryrun)
                            except ClientError as err:
                                if err.response['Error']['Code'] != 'DryRunOperation':
                                    raise
                            # We continue here instead of breaking so that we install the correct route.
                            continue
                        # Break if the cidr is not pointing at a peering id
                        if 'VpcPeeringConnectionId' not in route:
                            LOGGER.warning(f'CIDR {cidr} not pointing at VPC peering in {account_id} {vpc_id} {route_table_id}')
                            break
                        # Break if the cidr is pointing at a different peering id
                        if route['VpcPeeringConnectionId'] != peering_id:
                            LOGGER.warning(f'Peering for {cidr} not pointing at correct peering in {account_id} {vpc_id} {route_table_id}')
                            break
                        # The cidr already exists and is pointing at the correct peering
                        LOGGER.debug(f'{account_id} {vpc_id} {route_table_id} {cidr} pointing at correct peering {peering_id}')
                        break
                else:
                    # This block is only executed if we did not break in the above for loop
                    # Install peering route in route table
                    LOGGER.info(f'Intalling cidr {cidr} via {peering_id} to {remote_vpc_id} in {account_id} {vpc_id} {route_table_id}')
                    try:
                        ec2_client.create_route(RouteTableId=route_table_id,
                                                VpcPeeringConnectionId=peering_id,
                                                DestinationCidrBlock=cidr,
                                                DryRun=dryrun)
                    except ClientError as err:
                        # Handle the case where sometimes the AWS API is eventually consistent
                        if err.response['Error']['Code'] == 'RouteAlreadyExists':
                            LOGGER.warning(f'AWS API believes cidr {cidr} for {peering_id} already in {account_id} {vpc_id} {route_table_id}.'
                                           'May be due to eventual consistency. Rerun tool or inspect manually.')
                            continue
                        # Handle the case where the route table has reached its maximum number of routes
                        # https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html
                        if err.response['Error']['Code'] == 'RouteLimitExceeded':
                            LOGGER.error(f'Could not install route. Route limit exceeded for {account_id} {vpc_id} {route_table_id}. Request route limit increase.')
                            break
                        if err.response['Error']['Code'] != 'DryRunOperation':
                            raise
                    LOGGER.info(f'Installed cidr {cidr} via {peering_id} to {remote_vpc_id} in {account_id} {vpc_id} {route_table_id}')
                    route_table_modified = True
            if route_table_modified:
                # Tag the route table as being touched by peerd
                tags = {'peerd_support': metadata['support'],
                        'peerd_datetime': str(datetime.now())}
                tag_resource(ec2_client, route_table_id, tags, dryrun=dryrun)


def clean_route_tables(peering_id: str, vpc_id: str, account_id: str, region: str, dryrun: bool) -> None:
    """
    Deletes any routes pointing at a given peering id for a given vpc.
    Only applies to route tables with tag peerd_eligible:true

    :param peering_id: A vpc peering id e.g. pcx-011a291e5affc8d95
    :type peering_id: str
    :param vpc_id: A vpc id e.g. vpc-abc123
    :type vpc_id: str
    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    """
    # Initialise EC2 client
    ec2_client = aws_client(account_id, 'ec2', region)

    # Get the route tables for the VPC
    if not (route_tables := vpc_route_tables(vpc_id, account_id, region)):
        LOGGER.warning(f'No peerd_eligible route tables in VPC {vpc_id}')
        return

    # Find routes in each route table and delete them
    for route_table in route_tables:
        route_table_id = route_table['RouteTableId']
        route_table_modified = False
        LOGGER.info(f"Inspecting {route_table_id} {vpc_id} {account_id} {region} for route cleanup.")
        for route in route_table['Routes']:
            if route.get('VpcPeeringConnectionId', None) == peering_id:
                LOGGER.info(f"Deleting {route['DestinationCidrBlock']} -> {peering_id}")
                try:
                    ec2_client.delete_route(
                        RouteTableId=route_table['RouteTableId'],
                        DestinationCidrBlock=route['DestinationCidrBlock'],
                        DryRun=dryrun)
                except ClientError as err:
                    if err.response['Error']['Code'] != 'DryRunOperation':
                        raise
                LOGGER.info(f"Deleted {route['DestinationCidrBlock']} -> {peering_id}")
                route_table_modified = True
        if route_table_modified:
            tags = {'peerd_datetime': str(datetime.now())}
            tag_resource(ec2_client, route_table_id, tags, dryrun=dryrun)


def delete_unneeded_peerings(config: Sequence[dict], metadata: Mapping, dryrun: bool) -> None:
    """
    Compares the infrastructure with the configuration and applies
    route cleanup and peering deletion logic to remove VPC peerings.

    :param peering_id: A vpc peering id e.g. pcx-011a291e5affc8d95
    :type peering_id: str
    :param vpc_id: A vpc id e.g. vpc-abc123
    :type vpc_id: str
    :param account_id: An AWS account id number
    :type account: str
    :param region: An AWS region where the service client should be created. e.g. us-east-1
    :type region: str
    """
    LOGGER.info('Beginning deletion phase...')
    # Get a list of all VPCs configured for this environment
    config_vpc_list = list_dict_values(config, 'vpc_id')
    # Get all peerings that exist for this environment
    LOGGER.info(f'Getting all peerings active in AWS for environment {metadata["environment"]}')
    # Only filter working accounts now, as there could be times where accounts don't work
    # but we might want to keep the peerings until we remove them from the configuration.
    filtered_config = filter_working_accounts(config)
    peerings = get_all_env_peerings(filtered_config, metadata)
    # Determine which peerings no longer relate to any vpc in the environment
    LOGGER.info(f'Calculating which peerings may be deleted (do not appear in configuration)')
    deletable_peerings = get_deletable_peerings(peerings, config_vpc_list)
    # Iterate through the deletable peerings
    for peering in deletable_peerings:
        peering_id = peering['VpcPeeringConnectionId']
        LOGGER.info('Working on peering {} between {} {} {} and {} {} {}'.format(
            peering_id,
            peering['RequesterVpcInfo']['OwnerId'],
            peering['RequesterVpcInfo']['VpcId'],
            peering['RequesterVpcInfo']['Region'],
            peering['AccepterVpcInfo']['OwnerId'],
            peering['AccepterVpcInfo']['VpcId'],
            peering['AccepterVpcInfo']['Region'],
        ))

        # Clean up the route tables on both sides
        for vpc_info in [peering['RequesterVpcInfo'], peering['AccepterVpcInfo']]:
            clean_route_tables(peering_id, vpc_info['VpcId'], vpc_info['OwnerId'], vpc_info['Region'], dryrun)
        # Delete the peering
        LOGGER.info(f"Deleting peering {peering_id}...")
        ec2_client = aws_client(peering['RequesterVpcInfo']['OwnerId'], 'ec2', peering['RequesterVpcInfo']['Region'])
        try:
            ec2_client.delete_vpc_peering_connection(VpcPeeringConnectionId=peering_id, DryRun=dryrun)
        except ClientError as err:
            if err.response['Error']['Code'] != 'DryRunOperation':
                raise

        LOGGER.info(f"Deleted peering {peering_id} successfully.")
