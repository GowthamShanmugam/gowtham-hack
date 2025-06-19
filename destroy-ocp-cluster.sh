#!/bin/bash

set -euo pipefail

CLUSTER_NAME="$1"
REGION="${2:-us-east-1}"

echo "Cleaning up AWS resources for cluster: $CLUSTER_NAME in region: $REGION"

# Delete Route53 Hosted Zones
delete_hosted_zones() {
  echo "Deleting Route53 Hosted Zones..."
  aws route53 list-hosted-zones | jq -r '.HostedZones[] | select(.Name | contains("'$CLUSTER_NAME'")) | .Id' |
  while read -r zone_id; do
    zone_id_clean=${zone_id#/hostedzone/}
    echo "  Found hosted zone: $zone_id_clean"
    
    # Delete all records in the zone (except NS/SOA)
    aws route53 list-resource-record-sets --hosted-zone-id "$zone_id_clean" |
      jq -c '.ResourceRecordSets[]' |
      grep -v '"Type":"NS"' |
      grep -v '"Type":"SOA"' |
      while read -r record; do
        echo "$record" > tmp-record.json
        aws route53 change-resource-record-sets --hosted-zone-id "$zone_id_clean" --change-batch '{"Changes":[{"Action":"DELETE","ResourceRecordSet":'"$record"'}]}'
      done

    # Delete the zone
    aws route53 delete-hosted-zone --id "$zone_id_clean"
  done
}

# Delete S3 buckets
delete_s3_buckets() {
  echo "Deleting S3 buckets..."
  aws s3api list-buckets | jq -r '.Buckets[].Name' | grep "$CLUSTER_NAME" |
  while read -r bucket; do
    echo "  Deleting bucket: $bucket"
    aws s3 rm "s3://$bucket" --recursive || true
    aws s3api delete-bucket --bucket "$bucket" || true
  done
}

# Delete IAM roles
delete_iam_roles() {
  echo "Deleting IAM Roles..."
  aws iam list-roles | jq -r '.Roles[].RoleName' | grep "$CLUSTER_NAME" |
  while read -r role; do
    echo "  Deleting role: $role"
    aws iam detach-role-policy --role-name "$role" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess || true
    aws iam delete-role --role-name "$role" || true
  done
}

# Delete security groups
delete_security_groups() {
  echo "Deleting Security Groups..."
  aws ec2 describe-security-groups --region "$REGION" |
    jq -r '.SecurityGroups[] | select(.GroupName | contains("'$CLUSTER_NAME'")) | .GroupId' |
    while read -r sg; do
      echo "  Deleting SG: $sg"
      aws ec2 delete-security-group --group-id "$sg" --region "$REGION" || true
    done
}

# Delete load balancers
delete_load_balancers() {
  echo "Deleting Load Balancers..."
  aws elb describe-load-balancers --region "$REGION" | jq -r '.LoadBalancerDescriptions[].LoadBalancerName' | grep "$CLUSTER_NAME" |
  while read -r elb; do
    echo "  Deleting Classic ELB: $elb"
    aws elb delete-load-balancer --load-balancer-name "$elb" --region "$REGION"
  done

  aws elbv2 describe-load-balancers --region "$REGION" | jq -r '.LoadBalancers[].LoadBalancerArn' |
  while read -r alb; do
    alb_name=$(aws elbv2 describe-load-balancers --load-balancer-arns "$alb" --region "$REGION" | jq -r '.LoadBalancers[0].LoadBalancerName')
    if [[ "$alb_name" == *"$CLUSTER_NAME"* ]]; then
      echo "  Deleting ALB: $alb_name"
      aws elbv2 delete-load-balancer --load-balancer-arn "$alb" --region "$REGION"
    fi
  done
}

# Delete EC2 key pairs
delete_key_pairs() {
  echo "Deleting Key Pairs..."
  aws ec2 describe-key-pairs --region "$REGION" | jq -r '.KeyPairs[].KeyName' | grep "$CLUSTER_NAME" |
  while read -r key; do
    echo "  Deleting key pair: $key"
    aws ec2 delete-key-pair --key-name "$key" --region "$REGION"
  done
}

# Delete VPCs by tag
delete_vpcs() {
  echo "Deleting VPCs..."
  vpcs=$(aws ec2 describe-vpcs --region "$REGION" --filters "Name=tag:Name,Values=*${CLUSTER_NAME}*" | jq -r '.Vpcs[].VpcId')

  for vpc_id in $vpcs; do
    echo "  Cleaning and deleting VPC: $vpc_id"

    # Delete dependencies: subnets, IGWs, etc.
    igw_ids=$(aws ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values=$vpc_id --region "$REGION" | jq -r '.InternetGateways[].InternetGatewayId')
    for igw_id in $igw_ids; do
      aws ec2 detach-internet-gateway --internet-gateway-id "$igw_id" --vpc-id "$vpc_id" --region "$REGION"
      aws ec2 delete-internet-gateway --internet-gateway-id "$igw_id" --region "$REGION"
    done

    subnet_ids=$(aws ec2 describe-subnets --filters Name=vpc-id,Values=$vpc_id --region "$REGION" | jq -r '.Subnets[].SubnetId')
    for subnet_id in $subnet_ids; do
      aws ec2 delete-subnet --subnet-id "$subnet_id" --region "$REGION"
    done

    aws ec2 delete-vpc --vpc-id "$vpc_id" --region "$REGION"
  done
}

# Main
delete_hosted_zones
delete_s3_buckets
delete_iam_roles
delete_security_groups
delete_load_balancers
delete_key_pairs
delete_vpcs

echo "✅ Cleanup for cluster '$CLUSTER_NAME' in region '$REGION' completed."

