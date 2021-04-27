#!/bin/zsh

curl -k -i -w '\n' -u admin:adminadmin -X POST \
  https://nethsmdemo.nitrokey.com/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"ECDSA_P256_Signature"
],  "algorithm": "ECDSA_P256", "id": "eckey" }'
