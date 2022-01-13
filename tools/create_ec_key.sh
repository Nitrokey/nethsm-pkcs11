#!/bin/bash

curl -k -i -w '\n' -u admin:adminadmin -X POST \
  https://nethsmdemo.nitrokey.com/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"ECDSA_Signature"
],  "type": "EC_P256", "id": "eckey" }'
