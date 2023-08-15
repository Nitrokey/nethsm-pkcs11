#!/bin/sh -x
set -e

KEYID=tempkey

HEXID=$(echo -n ${KEYID} | xxd -ps)

# create a key
curl --fail-with-body -k -i -w '\n' -u admin:Administrator -X POST \
  https://localhost:8443/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"ECDSA_Signature"
],  "type": "EC_P256", "id": "'$KEYID'" }'


# delete the key
pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v  \
  --delete-object --type privkey --id $HEXID --login --login-type so --so-pin Administrator

## check that the key is gone
RESPONSE=$(curl -s -k -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o /dev/null -w "%{http_code}")

if [ $RESPONSE -eq 404 ]; then
  echo "Got 404 error, key was deleted"
else
  echo "No 404 error, response code was $RESPONSE"
  exit 1
fi

