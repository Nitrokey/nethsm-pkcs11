#!/bin/bash

for type in 256 384 512
do
  curl -k --fail-with-body -i -w '\n' -u admin:Administrator -X POST \
    https://localhost:8443/api/v1/keys/generate \
    -H "content-type: application/json" \
    -d '{ "mechanisms": [ 
  "ECDSA_Signature"
  ],  "type": "BrainpoolP'${type}'", "id": "bpkey'${type}'" }'
done
