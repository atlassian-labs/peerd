# Built in
from copy import deepcopy
from itertools import combinations
from typing import List, Mapping, Sequence, Set, Tuple

# Local
from peerd import LOGGER, nested_dict
from peerd.aws import check_iam_role_capability, get_all_peerings, list_vpc_cidrs
from peerd.decorators import memoize


def chunk_list(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def filter_working_accounts(config: list) -> list:
    """
    Filters the configuration dictionary list for accounts where IAM/EC2 API works.
    E.g. This allows us to skip accounts where the account number is invalid.

    :param config: A list containing dictionaries representing the configuration for the environment
    :type config: list
    :returns: The configuration filtered for only accounts which IAM role assumption works for
    :rtype: list
    """
    return [x for x in config if check_iam_role_capability(x['account_id'])]


def list_dict_values(dict_list: Sequence[dict], key: str) -> list:
    """
    Return a list of all unique values for a given key in a list of dictionaries.

    Example usage:
    ```
    mylist = [
        {
            'account_id': '1234567890',
            'vpc_id': 'vpc-123',
            'region': 'us-west-2'
        },
        {
            'account_id': '3456789012',
            'region': 'us-west-1'
        },
        {
            'account_id': '3456789012',
            'vpc_id': 'vpc-456',
            'region': 'us-west-1'
        }
    ]
    list_dict_values(mylist, 'vpc_id')
    > ['vpc-123', 'vpc-456']
    ```

    :param dict_list: A list of dictionaries.
    :type dict_list: list
    :returns: A list of unique values for a given key from a list of dictionaries.
    :rtype: list
    """
    return [x for x in list(set(y.get(key, None) for y in dict_list)) if x is not None]


@memoize()
def common_vpc_cidrs(peer_desc: Sequence[dict]) -> bool:
    """
    Returns true if the VPCs share any CIDRs in common
    Returns false if the VPCs share no CIDRs in common

    Example Input:
    ```
    [
        {
            'account_id': '1234567890',
            'vpc_id': 'vpc-123',
            'region': 'us-west-2'
        }
        {
            'account_id': '3456789012',
            'vpc_id': 'vpc-456',
            'region': 'us-west-1'
        }
    ]
    ```

    :param peer_desc: A list containing two dictionaries describing the account, vpc and region of two sides of a peering
    :type peer_desc: list
    :returns: True if there 1 or more common CIDRs, False otherwise.
    """
    requester_vpc_cidrs = list_vpc_cidrs(peer_desc[0]['vpc_id'], peer_desc[0]['account_id'], peer_desc[0]['region'])
    accepter_vpc_cidrs = list_vpc_cidrs(peer_desc[1]['vpc_id'], peer_desc[1]['account_id'], peer_desc[1]['region'])
    if bool(set(requester_vpc_cidrs) & set(accepter_vpc_cidrs)):
        LOGGER.info(f'VPC {peer_desc[0]["vpc_id"]} cidrs {requester_vpc_cidrs} and {peer_desc[0]["vpc_id"]} cidrs {accepter_vpc_cidrs} share a common cidr.')
    return bool(set(requester_vpc_cidrs) & set(accepter_vpc_cidrs))


def target_vpc_peerings(config: Sequence[dict]) -> List[List[dict]]:
    """
    Wrapper for a series of functions that turns the configuration
    (which is a list of accounts, vpcs and regions) into a list of of unique peerings
    which should exist in the infrastructure.

    For example: Takes
    ```
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
    ```
    Returns a list of lists representing peerings should exist (existing and to be created)
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

    :param config: A list containing dictionaries representing the configuration for the environment
    :type config: list
    :returns: A list of lists representing the requester and accepter for each peering.
    :rtype: list
    """
    # Sort by account then region, this is important to prevent stale caches later.
    # The get_vpc_peering cache is filled in the same order. If peerings are created
    # randomly. Then the cache could show no peering exists when one already does.
    # This would result in a peering which could not be accepted.
    # Note: This would never cause a black hole, as we only install routes for
    # active peerings. But it would create some cleanup work.
    sorted_config = sorted(config, key=lambda i: (i['account_id'], i['region']))
    # Create unique combinations of peerings
    # These will be the requester and accepter for our full mesh of peerings.
    target_peerings = list(combinations(sorted_config, 2))
    # Filter out vpcs with same cidrs
    # You cannot peer VPCs with common CIDRs, the peering will not be accepted.
    filtered_target_peerings = [list(peers) for peers in target_peerings if not common_vpc_cidrs(peers)]
    return filtered_target_peerings


def get_peering_map(config: Sequence[dict]) -> dict:
    """
    Takes the config and yields a dictionary of accounts, regions,
    vpcs and the vpcs they should be peered with like so:
    Returns:
    {
        "415432961280": {
            "ap-southeast-2": {
                "vpc-e08fb484": [
                    "vpc-be8fb4da",
                    "vpc-7a83b81e",
                    "vpc-00a4011afa3b4e55f"
                ],
                "vpc-be8fb4da": [
                    "vpc-e08fb484",
                    "vpc-7a83b81e",
                    "vpc-00a4011afa3b4e55f"
                ],
                "vpc-7a83b81e": [
                    "vpc-e08fb484",
                    "vpc-be8fb4da",
                    "vpc-00a4011afa3b4e55f"
                ]
            },
            "ap-southeast-1": {
                "vpc-00a4011afa3b4e55f": [
                    "vpc-e08fb484",
                    "vpc-be8fb4da",
                    "vpc-7a83b81e"
                ]
            }
        }
    }

    :param config: A list containing dictionaries representing the configuration for the environment
    :type config: list
    :param metadata: A dictionary with the environment, owner, etc
    :type metadata: list
    :returns: A dictionary of accounts, regions, vpcs and configured peer vpcs
    :rtype: dict
    """
    peering_map = nested_dict()
    for requester in config:
        peering_map[requester['account_id']][requester['region']][requester['vpc_id']] = []
        for accepter in config:
            if accepter['vpc_id'] != requester['vpc_id']:
                peering_map[requester['account_id']][requester['region']][requester['vpc_id']].append(accepter['vpc_id'])
    return peering_map


def deduplicate_list_dicts(list_dict: Sequence[dict], key: str) -> List[dict]:
    """
    Takes a list of dictionaries and deduplicates them based on a given key.
    Example use-case: When we get a list of all peerings from multiple accounts
    because peerings have two sides, we can get duplicates of the same peerings.
    We use deduplicate_list_dicts to deduplicate the list on key VpcPeeringConnectionId.

    :param list_dict: A list of dictionaries.
    :type list_dict: list
    :param key: The key to deduplicate on.
    :returns: A deduplicated list of dictionaries.
    :rtype: list
    """
    dedup_list: List[dict] = []
    for dic in list_dict:
        if dic[key] not in list_dict_values(dedup_list, key):
            dedup_list.append(dic)
    return dedup_list


def get_all_env_peerings(config: Sequence[dict], metadata: Mapping) -> List[dict]:
    """
    Given the configuration, find all the peerings which exist across all accounts
    and regions.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections
    :param config: A list containing dictionaries representing the configuration for the environment
    :type config: list
    :param key: The key to deduplicate on.
    :returns: A deduplicated list of all peerings for this environment.
    :rtype: list
    """
    # Get a dictionary of accounts, regions, vpcs and the vpcs they should be peered to
    config_peer_map = deepcopy(get_peering_map(config))
    # Initialise a filter to get vpc peerings relevant to the current environment being worked on
    filters = [{'Name': 'tag:peerd_created', 'Values': ['true']},
               {'Name': 'tag:peerd_environment', 'Values': [metadata['environment']]},
               {'Name': 'status-code', 'Values': ['active']}]
    # Get all existing peerings from accounts listed in the config file
    peerings: List[dict] = []
    for account_id in config_peer_map.keys():
        for region in config_peer_map[account_id].keys():
            peerings.extend(get_all_peerings(account_id, region, filters))
    # Now get all existing peerings from all accounts that participate in peerings
    # (There might be accounts not listed in the config file)
    for peering in peerings:
        for side in ('RequesterVpcInfo', 'AccepterVpcInfo'):
            account_id = peering[side]['OwnerId']
            region = peering[side]['Region']
            if not config_peer_map[account_id][region]:
                LOGGER.debug(f'Found peering to unconfigured account {account_id} region {region}. Inspecting...')
                peerings.extend(get_all_peerings(account_id, region, filters))
                config_peer_map[account_id][region] = True
                LOGGER.debug(f'Discovered additional peerings in {account_id} {region}')
    # Add the 2 lists, and ceduplicate peerings. These will be all existing peerings even between accounts deleted from the config file
    return deduplicate_list_dicts(peerings, 'VpcPeeringConnectionId')


def get_deletable_peerings(peerings: Sequence[dict], vpc_list: Sequence[str]) -> List[dict]:
    """
    Given a list of peerings that exist in the infrastructure, and a
    list of vpcs that are configured to be members of this environment,
    returns a list of peerings which should be deleted.

    :param config: A list containing dictionaries representing the configuration for the environment
    :type config: list
    :param key: The key to deduplicate on.
    :returns: A deduplicated list of all peerings for this environment.
    :rtype: list
    """
    peerings_to_delete = []
    for peering in peerings:
        accepter = peering['AccepterVpcInfo']
        requester = peering['RequesterVpcInfo']
        if (accepter['VpcId'] not in vpc_list) or (requester['VpcId'] not in vpc_list):
            LOGGER.debug(f"Peering between {requester['VpcId']} and {accepter['VpcId']} can be deleted.")
            peerings_to_delete.append(peering)
    return deduplicate_list_dicts(peerings_to_delete, 'VpcPeeringConnectionId')
