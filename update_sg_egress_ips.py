import boto3, subprocess
from botocore.exceptions import ClientError

SECURITY_GROUP_ID = input("Enter your SG id: ")
REGION = input("Enter you region: ")
PORT = input("Enter the desired port to add: ")

# Initialize a session using Amazon EC2
ec2 = boto3.client('ec2', region_name=REGION)

# Function to add an inbound rule
def add_inbound_rule(port, protocol, cidr):
    ec2.authorize_security_group_ingress(
        GroupId=SECURITY_GROUP_ID,
        IpProtocol=protocol,
        FromPort=port,
        ToPort=port,
        CidrIp=cidr
    )

# Function to print inbound rules
def print_inbound_rules(security_group_id):
    response = ec2.describe_security_groups(GroupIds=[security_group_id])
    security_group = response['SecurityGroups'][0]
    print(f"Inbound rules for Security Group {security_group_id}:")
    for rule in security_group['IpPermissions']:
        protocol = rule.get('IpProtocol', 'N/A')
        from_port = rule.get('FromPort', 'N/A')
        to_port = rule.get('ToPort', 'N/A')
        ip_ranges = [ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])]
        ipv6_ranges = [ipv6_range['CidrIpv6'] for ipv6_range in rule.get('Ipv6Ranges', [])]
        print(f"Protocol: {protocol},\nFrom Port: {from_port},\nTo Port: {to_port},\nIP Ranges: {ip_ranges},\nIPv6 Ranges: {ipv6_ranges}\n\n")

def get_ip_prefixes():
    try:
        # Execute the CLI command
        result = subprocess.run(
            ["confluent", "network", "ip-address", "list", "--region", REGION, "--services", "CONNECT", "--output", "json"],
            capture_output=True,
            text=True,
            check=True
        )

        # Pipe the output to jq to filter the ip_prefix
        jq_result = subprocess.run(
            ["jq", ".[].ip_prefix"],
            input=result.stdout,
            capture_output=True,
            text=True,
            check=True
        )

        ip_prefixes = jq_result.stdout.split()
        return ip_prefixes
    
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return None
    

ips = get_ip_prefixes()

for ip in ips:
    try:
        add_inbound_rule(PORT, 'tcp', ip)
        print (f"Adding port {PORT} rule for ip: {ip}")
    except ClientError as e:
        print(f"Error adding rule: {e}")
    except:
        print("Other error adding rule.")


print("\n\nYour SG looks like...\n")

print_inbound_rules(SECURITY_GROUP_ID)
