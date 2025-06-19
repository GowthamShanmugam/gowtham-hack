#!/bin/bash

set -euo pipefail

OUTPUT_FILE="install-config.yaml"
TMP_DIR=$(mktemp -d)

echo "Generating install-config.yaml from current OpenShift cluster..."
echo "Saving to $OUTPUT_FILE"

# Get basic cluster info
CLUSTER_NAME=$(oc get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
BASE_DOMAIN=$(oc get dns cluster -o jsonpath='{.spec.baseDomain}')
CLUSTER_NETWORK=$(oc get network cluster -o jsonpath='{.spec.clusterNetwork[0].cidr}')
HOST_PREFIX=$(oc get network cluster -o jsonpath='{.spec.clusterNetwork[0].hostPrefix}')
SERVICE_NETWORK=$(oc get network cluster -o jsonpath='{.spec.serviceNetwork[0]}')
MACHINE_NETWORK=$(oc get network cluster -o jsonpath='{.spec.machineNetwork[0].cidr}')
NETWORK_TYPE=$(oc get network cluster -o jsonpath='{.spec.networkType}')

# Get pull secret
oc extract secret/pull-secret -n openshift-config --confirm --to="$TMP_DIR" > /dev/null
PULL_SECRET=$(cat "$TMP_DIR/.dockerconfigjson" | jq -c .)

# Get SSH key
SSH_KEY=$(oc get secret cluster-ssh-keys -n openshift-machine-api -o jsonpath='{.data.ssh-publickey}' 2>/dev/null | base64 -d || echo "")

# Get region, zone, instance types from Machinesets
CONTROL_PLANE_INSTANCE_TYPE=$(oc get machineset -n openshift-machine-api -l 'machine.openshift.io/cluster-api-machine-role=master' -o jsonpath='{.items[0].spec.template.spec.providerSpec.value.instanceType}' 2>/dev/null || echo "N/A")
COMPUTE_INSTANCE_TYPE=$(oc get machineset -n openshift-machine-api -l 'machine.openshift.io/cluster-api-machine-role=worker' -o jsonpath='{.items[0].spec.template.spec.providerSpec.value.instanceType}' 2>/dev/null || echo "N/A")

REGION=$(oc get machineset -n openshift-machine-api -o jsonpath='{.items[0].spec.template.spec.providerSpec.value.placement.region}' 2>/dev/null || echo "N/A")

# Get availability zones
ZONES=$(oc get machineset -n openshift-machine-api -o jsonpath='{range .items[*]}{.spec.template.spec.providerSpec.value.placement.availabilityZone}{"\n"}{end}' | sort | uniq)
ZONES_YAML=$(echo "$ZONES" | sed 's/^/    - /')

# Get replica counts
MASTER_REPLICAS=$(oc get machineset -n openshift-machine-api -l 'machine.openshift.io/cluster-api-machine-role=master' -o jsonpath='{.items[0].spec.replicas}' 2>/dev/null || echo 3)
COMPUTE_REPLICAS=$(oc get machineset -n openshift-machine-api -l 'machine.openshift.io/cluster-api-machine-role=worker' -o jsonpath='{.items[0].spec.replicas}' 2>/dev/null || echo 3)

# Generate install-config.yaml
cat <<EOF > "$OUTPUT_FILE"
apiVersion: v1
baseDomain: $BASE_DOMAIN
metadata:
  name: $CLUSTER_NAME
compute:
- name: worker
  replicas: $COMPUTE_REPLICAS
  platform:
    aws:
      type: $COMPUTE_INSTANCE_TYPE
      zones:
$ZONES_YAML
controlPlane:
  name: master
  replicas: $MASTER_REPLICAS
  platform:
    aws:
      type: $CONTROL_PLANE_INSTANCE_TYPE
      zones:
$ZONES_YAML
platform:
  aws:
    region: $REGION
pullSecret: '$PULL_SECRET'
sshKey: |
  $SSH_KEY
networking:
  networkType: $NETWORK_TYPE
  machineNetwork:
  - cidr: $MACHINE_NETWORK
  clusterNetwork:
  - cidr: $CLUSTER_NETWORK
    hostPrefix: $HOST_PREFIX
  serviceNetwork:
  - $SERVICE_NETWORK
EOF

echo "✅ Done: install-config.yaml generated."

