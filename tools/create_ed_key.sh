#!/bin/bash

curl -k --fail-with-body -i -w '\n' -u admin:Administrator -X POST \
  https://localhost:8443/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"EdDSA_Signature"
],  "type": "Curve25519", "id": "edkey" }'
