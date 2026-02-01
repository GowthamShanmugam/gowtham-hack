#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

INFO_FILE="keycloak-instance-info.txt"

# Function to show menu
show_menu() {
    clear
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        Keycloak AWS EC2 Management Script            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}What would you like to do?${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} ${GREEN}🚀 Create Keycloak instance${NC}"
    echo -e "  ${RED}2)${NC} ${RED}🗑️  Destroy Keycloak instance${NC}"
    echo -e "  ${BLUE}3)${NC} ${BLUE}📊 Show instance status${NC}"
    echo -e "  ${YELLOW}4)${NC} ${YELLOW}👋 Exit${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    read -p "$(echo -e ${YELLOW}Enter your choice [1-4]: ${NC})" CHOICE
}

# Function to check AWS prerequisites
check_aws() {
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}❌ AWS CLI is not installed. Please install it first.${NC}"
        exit 1
    fi

    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}❌ AWS credentials not configured. Run 'aws configure' first.${NC}"
        exit 1
    fi
}

# Helper function to show spinner (for long-running operations)
show_spinner() {
    local pid=$1
    local message=$2
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf "\r   ${YELLOW}${spinstr:0:1}${NC} $message"
        spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
    done
    printf "\r   ${GREEN}✓${NC} $message\n"
}

# Helper function to add security group rule
add_sg_rule() {
    local port=$1
    local cidr=$2
    local desc=$3
    
    set +e
    RESULT=$(aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port $port \
        --cidr $cidr 2>&1)
    if [ $? -eq 0 ]; then
        echo -e "   ${GREEN}✓${NC} Added $desc (port $port)"
    elif echo "$RESULT" | grep -q "InvalidPermission.Duplicate"; then
        echo -e "   ${GREEN}✓${NC} $desc (port $port) already exists"
    else
        echo -e "   ${YELLOW}⚠️  Could not add $desc: $RESULT${NC}"
    fi
    set -e
}

# Function to collect user input
collect_user_input() {
    echo -e "${YELLOW}📋 Configuration:${NC}"
    echo ""
    
    read -p "Instance type [t3.medium]: " INSTANCE_TYPE
    INSTANCE_TYPE=${INSTANCE_TYPE:-t3.medium}
    echo -e "   ${GREEN}✓${NC} Instance type: $INSTANCE_TYPE"
    
    read -p "Key pair name [keycloak-keypair]: " KEY_NAME
    KEY_NAME=${KEY_NAME:-keycloak-keypair}
    echo -e "   ${GREEN}✓${NC} Key pair: $KEY_NAME"
    
    read -sp "Keycloak admin password [admin]: " ADMIN_PASSWORD
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin}
    echo ""
    echo -e "   ${GREEN}✓${NC} Admin password set"
    
    read -p "Instance name tag [keycloak]: " INSTANCE_NAME
    INSTANCE_NAME=${INSTANCE_NAME:-keycloak}
    echo -e "   ${GREEN}✓${NC} Instance name: $INSTANCE_NAME"
    
    USE_HTTPS="yes"
    echo -e "   ${GREEN}✓${NC} HTTPS enabled (port 443)"
    
    echo ""
    echo -e "${YELLOW}🌐 VPC Selection:${NC}"
    echo -e "  1) Create new VPC for Keycloak (recommended)"
    echo -e "  2) Select from existing VPCs"
    echo -e "  3) Specify subnet ID directly"
    echo -e "  4) Auto-detect (use default or first available)"
    read -p "Choose option [1-4] [1]: " VPC_OPTION
    VPC_OPTION=${VPC_OPTION:-1}
}

# Function to setup key pair
setup_key_pair() {
    echo -e "${YELLOW}🔑 Setting up key pair...${NC}"
    if ! aws ec2 describe-key-pairs --key-names $KEY_NAME &>/dev/null; then
        echo -e "   Creating new key pair: $KEY_NAME"
        aws ec2 create-key-pair --key-name $KEY_NAME --query 'KeyMaterial' --output text > ${KEY_NAME}.pem
        chmod 400 ${KEY_NAME}.pem
        echo -e "   ${GREEN}✓${NC} Key pair created: ${KEY_NAME}.pem"
    else
        echo -e "   ${GREEN}✓${NC} Using existing key pair: $KEY_NAME"
    fi
}

# Function to get user's IP address
get_user_ip() {
    echo -e "${YELLOW}📍 Getting your IP address...${NC}"
    MY_IP=$(curl -s https://checkip.amazonaws.com)
    echo -e "   ${GREEN}✓${NC} Your IP: $MY_IP"
}

# Function to create new VPC
create_new_vpc() {
    echo -e "   ${YELLOW}Creating new VPC for Keycloak...${NC}"
    
    AZ1=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)
    AZ2=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[1].ZoneName' --output text)
    
    VPC_CIDR="10.1.0.0/16"
    VPC_NAME="keycloak-vpc"
    
    echo -e "   Creating VPC with CIDR: $VPC_CIDR"
    VPC_ID=$(aws ec2 create-vpc \
        --cidr-block $VPC_CIDR \
        --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=$VPC_NAME}]" \
        --query 'Vpc.VpcId' --output text)
    
    if [ -z "$VPC_ID" ]; then
        echo -e "   ${RED}❌ Failed to create VPC${NC}"
        exit 1
    fi
    
    echo -e "   ${GREEN}✓${NC} Created VPC: $VPC_ID"
    
    aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames
    aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support
    
    echo -e "   Creating Internet Gateway..."
    IGW_ID=$(aws ec2 create-internet-gateway \
        --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${VPC_NAME}-igw}]" \
        --query 'InternetGateway.InternetGatewayId' --output text)
    
    aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID
    echo -e "   ${GREEN}✓${NC} Created and attached Internet Gateway: $IGW_ID"
    
    echo -e "   Creating public subnets..."
    SUBNET1_CIDR="10.1.1.0/24"
    SUBNET2_CIDR="10.1.2.0/24"
    
    AZ1_SUFFIX=$(echo $AZ1 | awk -F'-' '{print $NF}')
    AZ2_SUFFIX=$(echo $AZ2 | awk -F'-' '{print $NF}')
    
    SUBNET_ID=$(aws ec2 create-subnet \
        --vpc-id $VPC_ID \
        --cidr-block $SUBNET1_CIDR \
        --availability-zone $AZ1 \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${VPC_NAME}-public-${AZ1_SUFFIX}}]" \
        --query 'Subnet.SubnetId' --output text)
    
    SUBNET2_ID=$(aws ec2 create-subnet \
        --vpc-id $VPC_ID \
        --cidr-block $SUBNET2_CIDR \
        --availability-zone $AZ2 \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${VPC_NAME}-public-${AZ2_SUFFIX}}]" \
        --query 'Subnet.SubnetId' --output text)
    
    echo -e "   ${GREEN}✓${NC} Created subnets: $SUBNET_ID, $SUBNET2_ID"
    
    aws ec2 modify-subnet-attribute --subnet-id $SUBNET_ID --map-public-ip-on-launch
    aws ec2 modify-subnet-attribute --subnet-id $SUBNET2_ID --map-public-ip-on-launch
    
    RT_ID=$(aws ec2 create-route-table \
        --vpc-id $VPC_ID \
        --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${VPC_NAME}-public-rt}]" \
        --query 'RouteTable.RouteTableId' --output text)
    
    aws ec2 create-route --route-table-id $RT_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID
    aws ec2 associate-route-table --subnet-id $SUBNET_ID --route-table-id $RT_ID
    aws ec2 associate-route-table --subnet-id $SUBNET2_ID --route-table-id $RT_ID
    
    echo -e "   ${GREEN}✓${NC} Configured routing"
    echo -e "   ${GREEN}✓${NC} VPC setup complete!"
}

# Function to select existing VPC
select_existing_vpc() {
    echo -e "   ${YELLOW}Listing available VPCs...${NC}"
    aws ec2 describe-vpcs \
        --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0],IsDefault]' \
        --output table
    
    read -p "Enter VPC ID to use: " VPC_ID
    
    if [ -z "$VPC_ID" ]; then
        echo -e "   ${RED}❌ No VPC ID provided${NC}"
        exit 1
    fi
    
    set +e
    VPC_VERIFY=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].VpcId' --output text 2>/dev/null)
    set -e
    
    if [ -z "$VPC_VERIFY" ] || [ "$VPC_VERIFY" == "None" ] || [ "$VPC_VERIFY" != "$VPC_ID" ]; then
        echo -e "   ${RED}❌ Invalid VPC ID: $VPC_ID${NC}"
        exit 1
    fi
    
    VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].CidrBlock' --output text 2>/dev/null)
    echo -e "   ${GREEN}✓${NC} Using VPC: $VPC_ID ($VPC_CIDR)"
    
    echo -e "   ${YELLOW}Listing subnets in VPC...${NC}"
    aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query 'Subnets[*].[SubnetId,AvailabilityZone,CidrBlock,MapPublicIpOnLaunch]' \
        --output table
    
    read -p "Enter Subnet ID to use: " SUBNET_ID
    
    if [ -z "$SUBNET_ID" ]; then
        echo -e "   ${RED}❌ No Subnet ID provided${NC}"
        exit 1
    fi
    
    set +e
    SUBNET_VERIFY=$(aws ec2 describe-subnets --subnet-ids $SUBNET_ID --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[0].SubnetId' --output text 2>/dev/null)
    set -e
    
    if [ -z "$SUBNET_VERIFY" ] || [ "$SUBNET_VERIFY" == "None" ] || [ "$SUBNET_VERIFY" != "$SUBNET_ID" ]; then
        echo -e "   ${RED}❌ Subnet $SUBNET_ID not found in VPC $VPC_ID${NC}"
        exit 1
    fi
    
    SUBNET_INFO=$(aws ec2 describe-subnets --subnet-ids $SUBNET_ID --query 'Subnets[0].[AvailabilityZone,CidrBlock]' --output text)
    SUBNET_AZ=$(echo $SUBNET_INFO | awk '{print $1}')
    SUBNET_CIDR=$(echo $SUBNET_INFO | awk '{print $2}')
    echo -e "   ${GREEN}✓${NC} Using subnet: $SUBNET_ID ($SUBNET_CIDR) in $SUBNET_AZ"
}

# Function to use specified subnet
use_specified_subnet() {
    read -p "Enter Subnet ID: " USER_SUBNET_ID
    
    if [ -z "$USER_SUBNET_ID" ]; then
        echo -e "   ${RED}❌ No subnet ID provided${NC}"
        exit 1
    fi
    
    echo -e "   Using specified subnet: $USER_SUBNET_ID"
    set +e
    SUBNET_INFO=$(aws ec2 describe-subnets --subnet-ids $USER_SUBNET_ID --query 'Subnets[0].[VpcId,AvailabilityZone,CidrBlock]' --output text 2>/dev/null)
    AWS_EXIT_CODE=$?
    set -e
    
    if [ $AWS_EXIT_CODE -ne 0 ] || [ -z "$SUBNET_INFO" ] || [ "$SUBNET_INFO" == "None" ]; then
        echo -e "   ${RED}❌ Invalid subnet ID: $USER_SUBNET_ID${NC}"
        exit 1
    fi
    
    VPC_ID=$(echo $SUBNET_INFO | awk '{print $1}')
    SUBNET_AZ=$(echo $SUBNET_INFO | awk '{print $2}')
    SUBNET_CIDR=$(echo $SUBNET_INFO | awk '{print $3}')
    SUBNET_ID=$USER_SUBNET_ID
    
    VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].CidrBlock' --output text 2>/dev/null)
    echo -e "   ${GREEN}✓${NC} VPC: $VPC_ID ($VPC_CIDR)"
    echo -e "   ${GREEN}✓${NC} Subnet: $SUBNET_ID ($SUBNET_CIDR) in $SUBNET_AZ"
}

# Function to auto-detect VPC
auto_detect_vpc() {
    VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text 2>/dev/null)
    
    if [ -z "$VPC_ID" ] || [ "$VPC_ID" == "None" ]; then
        echo -e "   ${YELLOW}⚠️  No default VPC found. Looking for available VPCs...${NC}"
        VPC_ID=$(aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text 2>/dev/null)
        
        if [ -z "$VPC_ID" ] || [ "$VPC_ID" == "None" ]; then
            echo -e "   ${RED}❌ No VPCs found. Please create a VPC first.${NC}"
            exit 1
        fi
        
        VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].CidrBlock' --output text 2>/dev/null)
        echo -e "   ${GREEN}✓${NC} Using VPC: $VPC_ID ($VPC_CIDR)"
    else
        VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].CidrBlock' --output text 2>/dev/null)
        echo -e "   ${GREEN}✓${NC} Using default VPC: $VPC_ID ($VPC_CIDR)"
    fi
    
    SUBNET_ID=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$VPC_ID" "Name=map-public-ip-on-launch,Values=true" \
        --query 'Subnets[0].SubnetId' --output text 2>/dev/null)
    
    if [ -z "$SUBNET_ID" ] || [ "$SUBNET_ID" == "None" ]; then
        SUBNET_ID=$(aws ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'Subnets[0].SubnetId' --output text 2>/dev/null)
    fi
    
    if [ -z "$SUBNET_ID" ] || [ "$SUBNET_ID" == "None" ]; then
        echo -e "   ${RED}❌ No subnets found in VPC $VPC_ID${NC}"
        exit 1
    fi
    
    SUBNET_INFO=$(aws ec2 describe-subnets --subnet-ids $SUBNET_ID --query 'Subnets[0].[AvailabilityZone,CidrBlock]' --output text)
    SUBNET_AZ=$(echo $SUBNET_INFO | awk '{print $1}')
    SUBNET_CIDR=$(echo $SUBNET_INFO | awk '{print $2}')
    echo -e "   ${GREEN}✓${NC} Using subnet: $SUBNET_ID ($SUBNET_CIDR) in $SUBNET_AZ"
}

# Function to setup VPC and subnet
setup_vpc_and_subnet() {
    echo -e "${YELLOW}🔒 Setting up VPC and subnet...${NC}"
    
    case "$VPC_OPTION" in
        1)
            create_new_vpc
            ;;
        2)
            select_existing_vpc
            ;;
        3)
            use_specified_subnet
            ;;
        *)
            auto_detect_vpc
            ;;
    esac
}

# Function to setup security group
setup_security_group() {
    echo ""
    echo -e "${YELLOW}🔒 Security Group Selection:${NC}"
    read -p "Use existing security group? (yes/no) [yes]: " USE_EXISTING_SG
    USE_EXISTING_SG=${USE_EXISTING_SG:-yes}
    
    if [ "$USE_EXISTING_SG" == "yes" ]; then
        echo -e "   ${YELLOW}Listing security groups in VPC $VPC_ID...${NC}"
        SG_COUNT=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query 'length(SecurityGroups)' --output text 2>/dev/null | head -1 | tr -d '[:space:]')
        if [ -z "$SG_COUNT" ] || [ "$SG_COUNT" = "0" ]; then
            echo -e "   ${RED}❌ No security groups found in VPC $VPC_ID${NC}"
            exit 1
        fi
        for i in $(seq 0 $((SG_COUNT - 1))); do
            SG_GID=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query "SecurityGroups[$i].GroupId" --output text 2>/dev/null)
            SG_GNAME=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query "SecurityGroups[$i].GroupName" --output text 2>/dev/null)
            echo -e "   $((i + 1))) $SG_GNAME ($SG_GID)"
        done
        echo ""
        read -p "Enter security group number or ID [1]: " SG_INPUT
        SG_INPUT=${SG_INPUT:-1}
        if [[ "$SG_INPUT" =~ ^sg- ]]; then
            SG_ID="$SG_INPUT"
        else
            IDX=$(($SG_INPUT - 1))
            SG_ID=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query "SecurityGroups[$IDX].GroupId" --output text 2>/dev/null)
        fi
        if [ -z "$SG_ID" ] || [ "$SG_ID" == "None" ]; then
            echo -e "   ${RED}❌ Security group not found in VPC $VPC_ID${NC}"
            exit 1
        fi
        set +e
        SG_VERIFY=$(aws ec2 describe-security-groups --group-ids $SG_ID --filters "Name=vpc-id,Values=$VPC_ID" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)
        set -e
        if [ -z "$SG_VERIFY" ] || [ "$SG_VERIFY" == "None" ] || [ "$SG_VERIFY" != "$SG_ID" ]; then
            echo -e "   ${RED}❌ Security group $SG_ID not found in VPC $VPC_ID${NC}"
            exit 1
        fi
        echo -e "   ${GREEN}✓${NC} Using existing security group: $SG_ID"
    else
        SG_NAME="keycloak-sg"
        echo -e "   Checking for existing security group..."
        set +e
        SG_ID=$(aws ec2 describe-security-groups \
            --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
            --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)
        AWS_EXIT_CODE=$?
        set -e
        
        if [ $AWS_EXIT_CODE -ne 0 ] || [ -z "$SG_ID" ] || [ "$SG_ID" == "None" ] || [ "$SG_ID" == "null" ]; then
            echo -e "   Creating new security group..."
            set +e
            SG_OUTPUT=$(aws ec2 create-security-group \
                --group-name $SG_NAME \
                --description "Keycloak security group" \
                --vpc-id $VPC_ID \
                --query 'GroupId' --output text 2>&1)
            AWS_EXIT_CODE=$?
            set -e
            
            if [ $AWS_EXIT_CODE -ne 0 ]; then
                if echo "$SG_OUTPUT" | grep -q "SecurityGroupLimitExceeded"; then
                    echo -e "   ${RED}❌ Security Group Limit Exceeded${NC}"
                    echo -e "   ${YELLOW}You've reached the maximum number of security groups in this VPC.${NC}"
                    echo ""
                    echo -e "   ${BLUE}Options:${NC}"
                    echo -e "   1. Delete unused security groups in this VPC"
                    echo -e "   2. Use an existing security group"
                    echo ""
                    read -p "Would you like to use an existing security group? (yes/no) [no]: " USE_EXISTING
                    USE_EXISTING=${USE_EXISTING:-no}
                    
                    if [ "$USE_EXISTING" == "yes" ]; then
                        echo -e "   ${YELLOW}Listing security groups in VPC $VPC_ID...${NC}"
                        SG_COUNT=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query 'length(SecurityGroups)' --output text 2>/dev/null | head -1 | tr -d '[:space:]')
                        if [ -n "$SG_COUNT" ] && [ "$SG_COUNT" != "0" ]; then
                            for i in $(seq 0 $((SG_COUNT - 1))); do
                                SG_GID=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query "SecurityGroups[$i].GroupId" --output text 2>/dev/null)
                                SG_GNAME=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query "SecurityGroups[$i].GroupName" --output text 2>/dev/null)
                                echo -e "   $((i + 1))) $SG_GNAME ($SG_GID)"
                            done
                            echo ""
                            read -p "Enter security group number or ID [1]: " SG_INPUT
                            SG_INPUT=${SG_INPUT:-1}
                            if [[ "$SG_INPUT" =~ ^sg- ]]; then
                                SG_ID="$SG_INPUT"
                            else
                                IDX=$(($SG_INPUT - 1))
                                SG_ID=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query "SecurityGroups[$IDX].GroupId" --output text 2>/dev/null)
                            fi
                        fi
                        if [ -z "$SG_ID" ] || [ "$SG_ID" == "None" ]; then
                            echo -e "   ${RED}❌ No security group ID provided${NC}"
                            exit 1
                        fi
                        if ! aws ec2 describe-security-groups --group-ids $SG_ID --filters "Name=vpc-id,Values=$VPC_ID" &>/dev/null; then
                            echo -e "   ${RED}❌ Security group $SG_ID not found in VPC $VPC_ID${NC}"
                            exit 1
                        fi
                        echo -e "   ${GREEN}✓${NC} Using existing security group: $SG_ID"
                    else
                        echo ""
                        echo -e "   ${YELLOW}To delete unused security groups, run:${NC}"
                        echo -e "   ${CYAN}aws ec2 describe-security-groups --filters \"Name=vpc-id,Values=$VPC_ID\" --query 'SecurityGroups[*].[GroupId,GroupName]' --output table${NC}"
                        echo -e "   ${CYAN}aws ec2 delete-security-group --group-id <group-id>${NC}"
                        echo ""
                        echo -e "   ${YELLOW}Or increase your VPC security group limit (default is 5 per VPC)${NC}"
                        exit 1
                    fi
                else
                    echo -e "   ${RED}❌ Failed to create security group${NC}"
                    echo -e "   ${YELLOW}Error: $SG_OUTPUT${NC}"
                    exit 1
                fi
            else
                SG_ID="$SG_OUTPUT"
                if [ -z "$SG_ID" ] || [ "$SG_ID" == "None" ] || [ "$SG_ID" == "null" ]; then
                    echo -e "   ${RED}❌ Failed to create security group (empty response)${NC}"
                    exit 1
                fi
                echo -e "   ${GREEN}✓${NC} Created security group: $SG_ID"
            fi
        else
            echo -e "   ${GREEN}✓${NC} Using existing security group: $SG_ID"
        fi
    fi
    
    echo -e "   Adding security group rules..."
    add_sg_rule 22 "${MY_IP}/32" "SSH rule"
    add_sg_rule 8080 "0.0.0.0/0" "HTTP rule"
    add_sg_rule 443 "0.0.0.0/0" "HTTPS rule"
}

# Function to generate user data script (ADMIN_PASSWORD must be set and escaped for safe use in script)
generate_user_data_script() {
    # Escape ADMIN_PASSWORD for safe use inside single-quoted context in generated script
    ADMIN_PASSWORD_SAFE=$(printf '%s' "$ADMIN_PASSWORD" | sed "s/'/'\\\\''/g")
    cat <<EOF
#!/bin/bash
# Do not use set -e; user-data often fails on yum update or similar; we exit explicitly where needed
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "=== Starting Keycloak installation ==="
date

echo "Updating system..."
yum update -y || true

echo "Installing Docker..."
yum install docker -y || { echo "yum install docker failed"; exit 1; }

echo "Starting Docker..."
systemctl start docker
systemctl enable docker

echo "Waiting for Docker to be ready (up to 2 min)..."
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  docker info > /dev/null 2>&1 && break
  sleep 3
done
docker info > /dev/null 2>&1 || { echo "Docker did not become ready"; exit 1; }

echo "Adding ec2-user to docker group..."
usermod -a -G docker ec2-user

echo "Cleaning up disk space..."
yum clean all
rm -rf /var/cache/yum/*
docker system prune -af --volumes 2>/dev/null || true

echo "Pulling Keycloak image..."
docker pull quay.io/keycloak/keycloak:latest || {
    echo "Failed to pull image, cleaning up more space and retrying..."
    docker system prune -af 2>/dev/null || true
    journalctl --vacuum-time=1d 2>/dev/null || true
    sleep 5
    docker pull quay.io/keycloak/keycloak:latest
}

docker rm -f keycloak 2>/dev/null || true

echo "Generating self-signed certificate for HTTPS..."
mkdir -p /opt/keycloak-certs
cd /opt/keycloak-certs
# Instance must fetch its own public IP. Use IMDSv2 (token required) - default for new instances.
get_meta() { curl -s -H "X-aws-ec2-metadata-token: \${IMDS_TOKEN}" --connect-timeout 2 "http://169.254.169.254/latest/meta-data/\${1}" 2>/dev/null; }
PUBLIC_IP=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  IMDS_TOKEN=\$(curl -s -X PUT --connect-timeout 2 -H "X-aws-ec2-metadata-token-ttl-seconds: 60" "http://169.254.169.254/latest/api/token" 2>/dev/null)
  [ -n "\${IMDS_TOKEN}" ] && PUBLIC_IP=\$(get_meta public-ipv4) && [ -n "\${PUBLIC_IP}" ] && break
  sleep 3
done
[ -z "\${PUBLIC_IP}" ] && PUBLIC_IP=127.0.0.1
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key \
  -out tls.crt \
  -subj "/CN=keycloak" \
  -addext "subjectAltName=DNS:keycloak,DNS:localhost,IP:127.0.0.1,IP:\${PUBLIC_IP}"

chmod 644 tls.crt
chmod 600 tls.key
chown 1000:1000 tls.crt tls.key

echo "Starting Keycloak container with HTTPS enabled..."
# Mount certs to /etc/x509/https (Keycloak Quarkus reads KC_* env vars; avoid overwriting /opt/keycloak/conf)
docker run -d --name keycloak --restart unless-stopped \
  -p 8080:8080 \
  -p 443:8443 \
  -v /opt/keycloak-certs:/etc/x509/https:ro \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD='${ADMIN_PASSWORD_SAFE}' \
  -e KC_HTTPS_CERTIFICATE_FILE=/etc/x509/https/tls.crt \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/x509/https/tls.key \
  quay.io/keycloak/keycloak:latest \
  start \
    --http-enabled=true \
    --http-port=8080 \
    --https-port=8443 \
    --hostname-strict=false || {
    echo "Failed to start container, checking logs..."
    docker logs keycloak 2>&1 || true
    exit 1
}

sleep 5
if docker ps | grep -q keycloak; then
    echo "Keycloak container is running!"
    docker ps | grep keycloak
else
    echo "ERROR: Keycloak container failed to start!"
    docker ps -a | grep keycloak || true
    docker logs keycloak 2>&1 || true
    exit 1
fi

echo "=== Keycloak installation complete ==="
date
EOF
}

# Function to launch EC2 instance
launch_ec2_instance() {
    echo -e "${YELLOW}🔍 Finding latest Amazon Linux AMI...${NC}"
    AMI_ID=$(aws ec2 describe-images --owners amazon --filters "Name=name,Values=al2023-ami-*-x86_64" "Name=state,Values=available" \
      --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' --output text)
    echo -e "   ${GREEN}✓${NC} Found AMI: $AMI_ID"
    
    USER_DATA=$(generate_user_data_script)
    
    echo -e "${YELLOW}📦 Launching EC2 instance...${NC}"
    INSTANCE_ID=$(aws ec2 run-instances \
      --image-id $AMI_ID \
      --instance-type $INSTANCE_TYPE \
      --key-name $KEY_NAME \
      --security-group-ids $SG_ID \
      --subnet-id $SUBNET_ID \
      --associate-public-ip-address \
      --block-device-mappings "[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"VolumeSize\":20,\"DeleteOnTermination\":true,\"VolumeType\":\"gp3\"}}]" \
      --user-data "$USER_DATA" \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
      --query 'Instances[0].InstanceId' --output text)
    
    if [ -z "$INSTANCE_ID" ]; then
        echo -e "   ${RED}❌ Failed to launch instance${NC}"
        exit 1
    fi
    
    echo -e "   ${GREEN}✓${NC} Instance launched: $INSTANCE_ID"
    echo -e "${YELLOW}⏳ Waiting for instance to start...${NC}"
    aws ec2 wait instance-running --instance-ids $INSTANCE_ID
    
    PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
}

# Function to save instance info
save_instance_info() {
    cat > $INFO_FILE <<EOF
INSTANCE_ID=$INSTANCE_ID
PUBLIC_IP=$PUBLIC_IP
SECURITY_GROUP_ID=$SG_ID
KEY_NAME=$KEY_NAME
INSTANCE_NAME=$INSTANCE_NAME
VPC_ID=$VPC_ID
SUBNET_ID=$SUBNET_ID
ADMIN_PASSWORD=$ADMIN_PASSWORD
USE_HTTPS=$USE_HTTPS
EOF
}

# Function to display success message
display_success_message() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║              ${YELLOW}✨ Setup Complete! ✨${GREEN}                      ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}  ${YELLOW}📍 Instance Details${NC}                                    ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo -e "   ${CYAN}Instance ID:${NC}    ${GREEN}$INSTANCE_ID${NC}"
    echo -e "   ${CYAN}Public IP:${NC}       ${GREEN}$PUBLIC_IP${NC}"
    echo -e "   ${CYAN}Security Group:${NC}  ${GREEN}$SG_ID${NC}"
    echo ""
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}  ${YELLOW}🔑 SSH Access${NC}                                         ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo -e "   ${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "   ${CYAN}│${NC} ${GREEN}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP}${NC}              ${CYAN}│${NC}"
    echo -e "   ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}  ${YELLOW}🌐 Keycloak Access${NC}                                    ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo -e "   ${YELLOW}⏳ Installing... (wait 2-3 minutes for Keycloak to start)${NC}"
    echo ""
    echo -e "   ${GREEN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "   ${GREEN}│${NC} ${GREEN}🔒 HTTPS:${NC} ${CYAN}https://${PUBLIC_IP}:443${NC}                    ${GREEN}│${NC}"
    echo -e "   ${GREEN}│${NC} ${BLUE}🔓 HTTP:${NC}  ${CYAN}http://${PUBLIC_IP}:8080${NC}                     ${GREEN}│${NC}"
    echo -e "   ${GREEN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "   ${YELLOW}👤 Admin Username:${NC} ${GREEN}admin${NC}"
    echo -e "   ${YELLOW}🔐 Admin Password:${NC} ${GREEN}${ADMIN_PASSWORD}${NC}"
    echo ""
    echo -e "   ${YELLOW}⚠️  Note:${NC} HTTPS uses self-signed certificate (browser will show warning)"
    echo ""
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}  ${YELLOW}💾 Instance info saved to:${NC} ${GREEN}${INFO_FILE}${NC}              ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}║              ${YELLOW}🔧 Troubleshooting Guide${CYAN}                    ║${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC}  ${BLUE}📡 SSH to Instance${NC}                                      ${YELLOW}│${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
    echo -e "   ${CYAN}Command:${NC}"
    echo -e "   ${GREEN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "   ${GREEN}│${NC} ${CYAN}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP}${NC}              ${GREEN}│${NC}"
    echo -e "   ${GREEN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "   ${BLUE}If SSH connection fails:${NC}"
    echo -e "   ${CYAN}1.${NC} Check security group allows port 22 from your IP:"
    echo -e "      ${CYAN}aws ec2 describe-security-groups --group-ids $SG_ID --query 'SecurityGroups[0].IpPermissions[?FromPort==\`22\`]'${NC}"
    echo -e "   ${CYAN}2.${NC} Verify key file permissions:"
    echo -e "      ${CYAN}chmod 400 ${KEY_NAME}.pem${NC}"
    echo -e "   ${CYAN}3.${NC} Check instance status:"
    echo -e "      ${CYAN}aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].State.Name'${NC}"
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC}  ${BLUE}🔐 View Self-Signed Certificate${NC}                          ${YELLOW}│${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "   ${GREEN}Option 1:${NC} View certificate on the instance"
    echo -e "   ${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "   ${CYAN}│${NC} ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP}              ${CYAN}│${NC}"
    echo -e "   ${CYAN}│${NC} sudo openssl x509 -in /opt/keycloak-certs/tls.crt \\${NC}"
    echo -e "   ${CYAN}│${NC}   -text -noout${NC}                                    ${CYAN}│${NC}"
    echo -e "   ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "   ${GREEN}Option 2:${NC} View certificate from your local machine"
    echo -e "   ${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "   ${CYAN}│${NC} echo | openssl s_client -connect ${PUBLIC_IP}:443 \\${NC}"
    echo -e "   ${CYAN}│${NC}   -servername ${PUBLIC_IP} 2>/dev/null | \\${NC}"
    echo -e "   ${CYAN}│${NC}   openssl x509 -noout -text${NC}                ${CYAN}│${NC}"
    echo -e "   ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "   ${GREEN}Option 3:${NC} Download and view certificate"
    echo -e "   ${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "   ${CYAN}│${NC} echo | openssl s_client -connect ${PUBLIC_IP}:443 \\${NC}"
    echo -e "   ${CYAN}│${NC}   -servername ${PUBLIC_IP} 2>/dev/null | \\${NC}"
    echo -e "   ${CYAN}│${NC}   openssl x509 -out cert.pem${NC}                ${CYAN}│${NC}"
    echo -e "   ${CYAN}│${NC} openssl x509 -in cert.pem -text -noout${NC}       ${CYAN}│${NC}"
    echo -e "   ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "   ${GREEN}Quick certificate info:${NC}"
    echo -e "   ${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "   ${CYAN}│${NC} echo | openssl s_client -connect ${PUBLIC_IP}:443 \\${NC}"
    echo -e "   ${CYAN}│${NC}   -servername ${PUBLIC_IP} 2>/dev/null | \\${NC}"
    echo -e "   ${CYAN}│${NC}   openssl x509 -noout -subject -issuer -dates${NC} ${CYAN}│${NC}"
    echo -e "   ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC}  ${BLUE}🔍 Check Keycloak Status${NC}                                ${YELLOW}│${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
    echo -e "   ${CYAN}Check if container is running:${NC}"
    echo -e "   ${CYAN}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP} 'docker ps | grep keycloak'${NC}"
    echo ""
    echo -e "   ${YELLOW}If you get \"permission denied\" with docker:${NC} log out and log back in (group"
    echo -e "   takes effect on new login), or run ${CYAN}newgrp docker${NC}, or use ${CYAN}sudo docker ...${NC}"
    echo ""
    echo -e "   ${YELLOW}If no keycloak container exists:${NC} user-data may have failed. On the instance run:"
    echo -e "   ${CYAN}sudo cat /var/log/cloud-init-output.log${NC}  (look for \"Failed to run module scripts-user\")"
    echo -e "   ${CYAN}sudo cat /var/log/user-data.log${NC}  (script output; only present if script started)"
    echo ""
    echo -e "   ${CYAN}View recent logs:${NC}"
    echo -e "   ${CYAN}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP} 'docker logs keycloak --tail 50'${NC}"
    echo ""
    echo -e "   ${CYAN}View all logs:${NC}"
    echo -e "   ${CYAN}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP} 'docker logs keycloak'${NC}"
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC}  ${BLUE}🌐 Test Connectivity${NC}                                  ${YELLOW}│${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
    echo -e "   ${CYAN}Test HTTPS (with self-signed cert):${NC}"
    echo -e "   ${CYAN}curl -k -v https://${PUBLIC_IP}:443${NC}"
    echo ""
    echo -e "   ${CYAN}Test HTTP:${NC}"
    echo -e "   ${CYAN}curl -v http://${PUBLIC_IP}:8080${NC}"
    echo ""
}

# Function to create instance
create_instance() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           Creating Keycloak Instance                  ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    collect_user_input
    
    echo ""
    echo -e "${BLUE}🚀 Starting setup...${NC}"
    echo ""
    
    get_user_ip
    setup_key_pair
    setup_vpc_and_subnet
    setup_security_group
    launch_ec2_instance
    save_instance_info
    display_success_message
}

# Function to destroy instance
destroy_instance() {
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║           Destroying Keycloak Instance                 ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Check if info file exists
    if [ ! -f "$INFO_FILE" ]; then
        echo -e "${YELLOW}⚠️  No instance info file found.${NC}"
        echo -e "${YELLOW}   Looking for instances with tag Name=keycloak...${NC}"
        
        INSTANCE_ID=$(aws ec2 describe-instances \
            --filters "Name=tag:Name,Values=keycloak" "Name=instance-state-name,Values=running,stopped" \
            --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)
        
        if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" == "None" ]; then
            echo -e "${RED}❌ No Keycloak instance found.${NC}"
            return
        fi
        
        echo -e "${GREEN}✓${NC} Found instance: $INSTANCE_ID"
        read -p "Do you want to destroy this instance? (yes/no): " CONFIRM
        if [ "$CONFIRM" != "yes" ]; then
            echo "Cancelled."
            return
        fi
        
        # Try to get security group from instance
        SG_ID=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
            --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text 2>/dev/null)
        KEY_NAME="keycloak-keypair"  # Default
    else
        # Load from info file
        source $INFO_FILE
        echo -e "${BLUE}📋 Loaded instance info from: $INFO_FILE${NC}"
        echo ""
        echo -e "${YELLOW}Instance Details:${NC}"
        echo -e "   Instance ID: $INSTANCE_ID"
        echo -e "   Public IP:   $PUBLIC_IP"
        echo -e "   Security Group: $SECURITY_GROUP_ID"
        echo ""
        read -p "Are you sure you want to destroy everything? (yes/no): " CONFIRM
        if [ "$CONFIRM" != "yes" ]; then
            echo "Cancelled."
            return
        fi
        
        SG_ID=$SECURITY_GROUP_ID
    fi
    
    echo ""
    echo -e "${YELLOW}🗑️  Starting cleanup...${NC}"
    echo ""
    
    # Terminate instance
    if [ ! -z "$INSTANCE_ID" ] && [ "$INSTANCE_ID" != "None" ]; then
        echo -e "${YELLOW}📦 Terminating EC2 instance...${NC}"
        INSTANCE_STATE=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
            --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
        
        if [ "$INSTANCE_STATE" == "terminated" ]; then
            echo -e "   ${GREEN}✓${NC} Instance already terminated"
        else
            aws ec2 terminate-instances --instance-ids $INSTANCE_ID &>/dev/null
            echo -e "   ${GREEN}✓${NC} Instance termination initiated: $INSTANCE_ID"
            echo -e "   ${YELLOW}⏳ Waiting for termination...${NC}"
            aws ec2 wait instance-terminated --instance-ids $INSTANCE_ID
            echo -e "   ${GREEN}✓${NC} Instance terminated"
        fi
    else
        echo -e "   ${YELLOW}⚠️  No instance ID found${NC}"
    fi
    
    # Delete security group
    if [ ! -z "$SG_ID" ] && [ "$SG_ID" != "None" ]; then
        echo -e "${YELLOW}🔒 Deleting security group...${NC}"
        sleep 5
        aws ec2 delete-security-group --group-id $SG_ID 2>/dev/null && \
            echo -e "   ${GREEN}✓${NC} Security group deleted: $SG_ID" || \
            echo -e "   ${YELLOW}⚠️  Could not delete security group (may be in use or already deleted)${NC}"
    else
        echo -e "   ${YELLOW}⚠️  No security group ID found${NC}"
    fi
    
    # Check if VPC was created by this script and offer to delete it
    if [ ! -z "$VPC_ID" ] && [ "$VPC_ID" != "None" ]; then
        VPC_NAME=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].Tags[?Key==`Name`].Value|[0]' --output text 2>/dev/null)
        if [ "$VPC_NAME" == "keycloak-vpc" ]; then
            echo ""
            read -p "Delete VPC '$VPC_ID' (keycloak-vpc) that was created for Keycloak? (yes/no) [yes]: " DELETE_VPC
            DELETE_VPC=${DELETE_VPC:-yes}
            if [[ "$DELETE_VPC" =~ ^[yY] ]]; then
                echo -e "${YELLOW}🗑️  Deleting VPC and associated resources...${NC}"
                
                # Get Internet Gateway
                IGW_ID=$(aws ec2 describe-internet-gateways \
                    --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
                    --query 'InternetGateways[0].InternetGatewayId' --output text 2>/dev/null)
                
                # Get route tables
                RT_IDS=$(aws ec2 describe-route-tables \
                    --filters "Name=vpc-id,Values=$VPC_ID" \
                    --query 'RouteTables[*].RouteTableId' --output text 2>/dev/null)
                
                # Get subnets
                SUBNET_IDS=$(aws ec2 describe-subnets \
                    --filters "Name=vpc-id,Values=$VPC_ID" \
                    --query 'Subnets[*].SubnetId' --output text 2>/dev/null)
                
                # Detach and delete Internet Gateway
                if [ ! -z "$IGW_ID" ] && [ "$IGW_ID" != "None" ]; then
                    aws ec2 detach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID 2>/dev/null
                    aws ec2 delete-internet-gateway --internet-gateway-id $IGW_ID 2>/dev/null && \
                        echo -e "   ${GREEN}✓${NC} Internet Gateway deleted" || true
                fi
                
                # Delete subnets
                for SUBNET in $SUBNET_IDS; do
                    if [ ! -z "$SUBNET" ] && [ "$SUBNET" != "None" ]; then
                        aws ec2 delete-subnet --subnet-id $SUBNET 2>/dev/null && \
                            echo -e "   ${GREEN}✓${NC} Subnet deleted: $SUBNET" || true
                    fi
                done
                
                # Delete route tables (except main)
                for RT in $RT_IDS; do
                    if [ ! -z "$RT" ] && [ "$RT" != "None" ]; then
                        MAIN_RT=$(aws ec2 describe-route-tables --route-table-ids $RT --query 'RouteTables[0].Associations[?Main==`true`].RouteTableId' --output text 2>/dev/null)
                        if [ -z "$MAIN_RT" ] || [ "$MAIN_RT" == "None" ]; then
                            aws ec2 delete-route-table --route-table-id $RT 2>/dev/null && \
                                echo -e "   ${GREEN}✓${NC} Route table deleted: $RT" || true
                        fi
                    fi
                done
                
                # Wait a bit before deleting VPC
                sleep 5
                
                # Delete VPC
                aws ec2 delete-vpc --vpc-id $VPC_ID 2>/dev/null && \
                    echo -e "   ${GREEN}✓${NC} VPC deleted: $VPC_ID" || \
                    echo -e "   ${YELLOW}⚠️  Could not delete VPC (may have dependencies)${NC}"
            fi
        fi
    fi
    
    # Ask about key pair
    if [ ! -z "$KEY_NAME" ]; then
        echo ""
        read -p "Delete key pair '$KEY_NAME'? (yes/no) [no]: " DELETE_KEY
        DELETE_KEY=${DELETE_KEY:-no}
        if [ "$DELETE_KEY" == "yes" ]; then
            echo -e "${YELLOW}🔑 Deleting key pair...${NC}"
            aws ec2 delete-key-pair --key-name $KEY_NAME 2>/dev/null && \
                echo -e "   ${GREEN}✓${NC} Key pair deleted: $KEY_NAME" || \
                echo -e "   ${YELLOW}⚠️  Could not delete key pair (may not exist)${NC}"
            
            # Delete local key file
            if [ -f "${KEY_NAME}.pem" ]; then
                read -p "Delete local key file '${KEY_NAME}.pem'? (yes/no) [no]: " DELETE_KEY_FILE
                DELETE_KEY_FILE=${DELETE_KEY_FILE:-no}
                if [ "$DELETE_KEY_FILE" == "yes" ]; then
                    rm -f "${KEY_NAME}.pem"
                    echo -e "   ${GREEN}✓${NC} Local key file deleted"
                fi
            fi
        fi
    fi
    
    # Delete info file
    if [ -f "$INFO_FILE" ]; then
        echo ""
        read -p "Delete info file '$INFO_FILE'? (yes/no) [yes]: " DELETE_INFO
        DELETE_INFO=${DELETE_INFO:-yes}
        if [ "$DELETE_INFO" == "yes" ]; then
            rm -f "$INFO_FILE"
            echo -e "   ${GREEN}✓${NC} Info file deleted"
        fi
    fi
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              ✅ Cleanup Complete!                    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to show status
show_status() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           Instance Status                             ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ -f "$INFO_FILE" ]; then
        source $INFO_FILE
        echo -e "${BLUE}📋 Instance Details:${NC}"
        echo -e "   Instance ID: ${GREEN}$INSTANCE_ID${NC}"
        echo -e "   Public IP:   ${GREEN}$PUBLIC_IP${NC}"
        echo -e "   Instance Name: ${GREEN}$INSTANCE_NAME${NC}"
        
        # Get current state
        INSTANCE_STATE=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
            --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
        echo -e "   State:       ${GREEN}$INSTANCE_STATE${NC}"
        
        echo ""
        echo -e "${BLUE}🔑 SSH Access:${NC}"
        echo -e "   ${YELLOW}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP}${NC}"
        echo ""
        echo -e "${BLUE}🌐 Keycloak Access:${NC}"
        echo -e "   HTTPS: ${GREEN}https://${PUBLIC_IP}:443${NC}"
        echo -e "   HTTP:  ${GREEN}http://${PUBLIC_IP}:8080${NC}"
        echo -e "   Admin: ${GREEN}admin${NC}"
        echo ""
    else
        echo -e "${YELLOW}⚠️  No instance info file found.${NC}"
        echo -e "${YELLOW}   Looking for instances with tag Name=keycloak...${NC}"
        
        INSTANCE_ID=$(aws ec2 describe-instances \
            --filters "Name=tag:Name,Values=keycloak" "Name=instance-state-name,Values=running,stopped" \
            --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)
        
        if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" == "None" ]; then
            echo -e "${RED}❌ No Keycloak instance found.${NC}"
        else
            PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
                --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null)
            INSTANCE_STATE=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
                --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
            
            echo -e "${GREEN}✓${NC} Found instance: $INSTANCE_ID"
            echo -e "   Public IP: $PUBLIC_IP"
            echo -e "   State: $INSTANCE_STATE"
        fi
    fi
    echo ""
}

# Main script
check_aws

while true; do
    show_menu
    
    case $CHOICE in
        1)
            create_instance
            ;;
        2)
            destroy_instance
            ;;
        3)
            show_status
            ;;
        4)
            echo ""
            echo -e "${BLUE}Goodbye!${NC}"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please choose 1-4.${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
done
