#!/bin/bash
set -e

KC_URL="https://keycloak-helm-dev.apps.<your-domain>/"

# Login to Keycloak (update admin pass)
kcadm.sh config credentials --server $KC_URL --realm master --user admin --password <your-admin-pass>

# Create realm
kcadm.sh create realms -s realm=myrealm -s enabled=true

# Create client
kcadm.sh create clients -r myrealm -s clientId=oauth2-proxy -s enabled=true \
  -s publicClient=false -s protocol=openid-connect \
  -s redirectUris='["https://oauth2.keycloak-demo.apps.<your-domain>/oauth2/callback"]'

# Get client-id
token=$(kcadm.sh get clients -r myrealm --fields id,clientId | jq -r '.[] | select(.clientId=="oauth2-proxy") | .id')

# Create client secret
kcadm.sh create clients/$token/client-secret -r myrealm

# Create user
echo '{"username": "demo", "enabled": true, "credentials": [{"type": "password", "value": <your-pass>}]}' | \
  kcadm.sh create users -r myrealm -f -



