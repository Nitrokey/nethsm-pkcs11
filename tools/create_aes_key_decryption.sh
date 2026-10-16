#!/bin/bash

curl -k --fail-with-body -i -w '\n' -u admin:Administrator -X POST \
  https://localhost:8443/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"AES_Decryption_CBC"
],  "type": "Generic", "id": "aeskey2", "length": 256 }'
