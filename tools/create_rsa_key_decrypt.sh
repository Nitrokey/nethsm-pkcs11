#!/bin/bash

curl -k -i --fail-with-body -w '\n' -u admin:Administrator -X POST \
  https://localhost:8443/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"RSA_Decryption_RAW", 
"RSA_Decryption_PKCS1",
"RSA_Decryption_OAEP_MD5",
"RSA_Decryption_OAEP_SHA1",
"RSA_Decryption_OAEP_SHA224",
"RSA_Decryption_OAEP_SHA256",
"RSA_Decryption_OAEP_SHA384",
"RSA_Decryption_OAEP_SHA512"
],  "type": "RSA",  "length": 2048, "id": "rsakey1" }'
