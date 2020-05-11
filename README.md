# peerd

peerd is an AWS VPC Peering Connection management tool. It creates full-meshes of VPCs peerings based on a simple yaml file, and manages the full lifecycle of creation, deletion and route table updates needed to make VPC peerings useful across accounts and regions. Contributions welcome.

```
 ./peerd.py --help
usage: peerd.py [-h] [--debug] --config CONFIG --environment ENVIRONMENT

AWS VPC Peering Management Tool

optional arguments:
  -h, --help            show this help message and exit
  --debug               Set log-level to DEBUG
  --config CONFIG, -c CONFIG
                        Path to configuration file
  --environment ENVIRONMENT, -e ENVIRONMENT
                        Only execute the script on this environment
  --dryrun, -d          Only check for peerings which might be created or deleted. No changes made to mesh.
```

## Capabilities

- Capable of creating and accepting cross-account VPC peerings.
- Capable of creating and accepting cross-region VPC peerings.
- Capable of creating full-meshes of VPC peerings.
- Overlapping meshes supported through the use of different environment names in configuration file.
- Injects, repairs and removes routes as needed from VPC routing tables.

### Comment on other tools

Ansible, Terraform, Transit Gateway are valid approaches to creating networks between AWS VPCs.
peerd attempts to solve the issue of managing complex overlapping meshes of VPC peerings between many accounts and regions, which can be difficult with other tools or result in large configuration modules/files.

## Requirements

### Route Tables

- peerd will only manage routes in route tables with the tag `peerd_eligible:true`
- Route tables must be tagged with Key: `peerd_eligible` Value: `true`

### Authentication

peerd will assume a target IAM role with the same principal name in each account it needs to perform work in.
The target IAM role must have EC2 route table, VPC and Peering read and write permissions.

 - peerd uses an initial role 'A' to assume-role into given a target account role 'B' with established trust relationships with role 'A'. 
 - To intialise role 'A', peerd uses the standard boto credentials locations to obtain STS client credentials and perform Assume Role operations. See: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html and https://aws.amazon.com/premiumsupport/knowledge-center/iam-assume-role-cli/
 - Example automated provider of credentials also made by Atlassian: https://bitbucket.org/atlassian/cloudtoken/src/master/
 - Assumed roles are expected to share a common principal name across every account: `arn:aws:iam::${account}:role/${COMMON_PRINCIPAL_NAME}` . E.g.  `arn:aws:iam::0123456789:role/peerd-bot` and `arn:aws:iam::0987654321:role/peerd-bot` are two accounts with VPCs being peered together.

## Setup / Installation

- peerd reequires Python 3.8 and higher
- This can be obtained via brew (Macos) or official installer at https://www.python.org/downloads/

```
# Install python 3.8 or higher if needed
brew install python@3.8

# Verify version
$ python3 --version
Python 3.8.1

# Verify python path (may be different if using brew)
$ which python3
/Library/Frameworks/Python.framework/Versions/3.8/bin/python3

# Create a virtual environment
mkvirtualenv peerd -p python3

# Activate virtual environment
workon peerd

# Install requirements
pip install -r requirements.txt
```

## Configuration file

### Metadata block
- resource_owner: String. Used for tagging. Human or Machine owner of the peerings.
- business_unit: String. Useed for tagging. Business unit owner of the peerings.
- service_name: String. Used for tagging. Usually `peerd`
- support: String. Used for tagging. Who to contact about this infrastructure e.g. email address.
- common_principal_name: String. The common principal name used to assume a role in each target account.
- role_session_name: String. Used to identify the assume-role session. Useful for Cloudtrails log filtering.

### VPC blocks
- myfirstenvironment: Used to deduplicate VPC peerings and allow overlaping meshes.
- account_id: The account id where this VPC exists.
- vpc_id: The VPC which will be part of the VPC peering mesh.
- region: The AWS region where the VPC exists.
- note: Freeform. Not used for anything.
- cidr_overrides: Override the discovered CIDRs associated with this VPC when installing on remote sides of peerings. Useful if you only want to share a slice of a VPC CIDR range(s).
- peering_tags: Any custom tags you wish peerd to apply to the VPC peering connections it creates.

### Example
In the following example, VPCs across multiple regions and accounts will be peered together into a two overlapping meshes.
Route tables in each VPC with tag peerd_eligible:true on said route tables will be updated.
Unassumable account numbers, principals and non-existent VPCs will be skipped.
```
---
metadata:
  resource_owner: myname
  business_unit: PaaS
  service_name: peerd
  support: network-team@acme.org
  common_principal_name: peerd-bot
  role_session_name: peerd
environments:
  myfirstenvironment:
    - account_id: '415433457294'
      vpc_id: vpc-bi37c2c47
      region: ap-southeast-2
      note: peerd test vpc1
      cidr_overrides:
        - 192.168.4.0/24
      peering_tags:
        my_custom_taga: '0'
    - account_id: '415433457294'
      vpc_id: vpc-vb787854
      region: ap-southeast-2
      note: peerd test vpc2
      cidr_overrides:
        - 10.53.101.32/27
        - 10.53.128.128/25
        - 192.168.2.0/24
        - 2.2.2.0/24
      peering_tags:
         my_custom_tagb: '1'
    - account_id: '415433457294'
      vpc_id: vpc-v52oby8v7
      region: ap-southeast-2
      note: peerd test vpc3
    - account_id: '415433457294'
      vpc_id: vpc-2378vby38vb348
      region: ap-southeast-1
      note: peerd test vpc4
    - account_id: '415433457294'
      vpc_id: vpc-8tv23o87yv4
      region: ap-southeast-1
      note: vpc does not exist, will be skipped
    - account_id: '123456789012'
      vpc_id: vpc-abc12345
      region: ap-southeast-2
      note: account does not exist, will be skipped
    - account_id: '4375823475902'
      vpc_id: vpc-7834bcri234bcr
      region: us-east-1
      note: peerd test vpc5
  myseecondenvironment:
    - account_id: '415433457294'
      vpc_id: vpc-2378vby38vb348
      region: ap-southeast-1
      note: peerd test vpc4
    - account_id: '4375823475902'
      vpc_id: vpc-23754cn5b38bc
      region: us-east-2
      note: peerd test vpc6
```

## Running / Executing

```
./peerd.py --config ./config/config.yaml --environment myfirstenvironment
```

## Deleting a peering

Simply remove the vpc block from the configuration file then re-run the tool.

Note: The tool does not keep state, but it is possible to remove multiple VPCs at a time. When run, the tool will go through all existing peerings that terminate in accounts in the config file, and will check if any of them peers with accounts not listed the config file. If it finds any, it will login to those accounts, and determine if there are additional peerings to delete.

For this reason, __to completely delete an entire mesh__, first remove all VPCs from the config file except one (the tool will need one to be able to determine all the peerings that have to be deleted). Once all peerings are deleted, you can safely remove the last one from the config file.

## Thanks

Shane Anderson, Nicolas Meessen, Abdul Karim, James Flemming, Michael Gehrmann, Joshua Baldock, Haishan Du, Rui Meireles, Brock Campbell

## License

Copyright (c) 2020 Atlassian and others. Apache 2.0 licensed, see LICENSE.txt file.
USA Patent Pending 15/788,229. 
