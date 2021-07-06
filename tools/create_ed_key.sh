#!/bin/zsh

curl -k -i -w '\n' -u admin:adminadmin -X POST \
  https://nethsmdemo.nitrokey.com/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"EdDSA_Signature"
],  "type": "Curve25519", "id": "edkey" }'
