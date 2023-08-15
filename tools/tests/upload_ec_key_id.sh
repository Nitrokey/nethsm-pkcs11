#!/bin/sh -x

set -e 

KEYID=Hello

HEXID=$(echo -n ${KEYID}| xxd -ps)

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

rm -rf _test_ec_private.pem _test_ec_private.der _public.pem _ec_public.pem

openssl ecparam -name prime256v1 -genkey -noout -out _ec_private.pem

openssl pkcs8 -topk8 -nocrypt -in _ec_private.pem -outform DER -out _ec_private.der

pkcs11-tool --module target/debug/libnethsm_pkcs11.so -y privkey --write-object _ec_private.der \
    --login --login-type so --so-pin Administrator --id $HEXID

curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

## Sign with openssl

echo 'NetHSM rulez!' | openssl dgst -sha256 -binary | openssl pkeyutl -sign -inkey _ec_private.pem -out _data.sig

## Verify with openssl and the retrieved public key
echo 'NetHSM rulez!' | openssl dgst -keyform PEM -sha256 --verify _public.pem -signature _data.sig