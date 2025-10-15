#!/bin/bash

if [[ $NETHSM_VERSION == v1.* ]] || [[ $NETHSM_VERSION == v2.* ]]
then
  exit
fi

curl -k --fail-with-body -i -w '\n' -u admin:Administrator -X POST \
  https://localhost:8443/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"ECDSA_Signature"
],  "type": "EC_P256K1", "id": "eckey256k1" }'
