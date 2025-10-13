#!/bin/sh -x
set -e

KEYID=tempkey
KEYID_NEW=tempkey2

HEXID=$(echo -n ${KEYID} | xxd -ps)
HEXID_NEW=$(echo -n ${KEYID_NEW} | xxd -ps)

# create a key
curl -k -i -w '\n' -u admin:Administrator -X POST \
  https://localhost:8443/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"ECDSA_Signature"
],  "type": "EC_P256", "id": "'$KEYID'" }'


# rename the key
pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v  \
  --set-id $HEXID_NEW --type privkey --id $HEXID --login --login-type so --so-pin Administrator

# check that the old key is gone
RESPONSE=$(curl -s -k -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o /dev/null -w "%{http_code}")

if [ $RESPONSE -eq 404 ]; then
  echo "Got 404 error, key was renamed"
else
  echo "No 404 error, response code was $RESPONSE"
  exit 1
fi

# check that the new key is still there
RESPONSE=$(curl -s -k -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID_NEW/public.pem -o /dev/null -w "%{http_code}")

if [ $RESPONSE -eq 200 ]; then
  echo "Got 200 response, key was renamed"
else
  echo "No 200 response, response code was $RESPONSE"
  exit 1
fi

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v  \
  --delete-object --type privkey --id $HEXID_NEW --login --login-type so --so-pin Administrator
