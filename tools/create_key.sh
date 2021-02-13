#!/bin/zsh

curl -k -i -w '\n' -u admin:adminadmin -X POST \
  https://nethsmdemo.nitrokey.com/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d "{ \"mechanisms\": [  \"RSA_Signature_PKCS1\"  ],  \"algorithm\": \
  \"RSA\",  \"length\": 2048 }"
