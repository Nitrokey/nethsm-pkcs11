#!/bin/sh -x

set -e 

KEYID=edtest

HEXID=$(echo -n ${KEYID}| xxd -ps)

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

rm -rf _ed_private.pem _ed_private.der _public.pem

openssl genpkey -algorithm Ed25519 -out _ed_private.pem

# openssl pkcs8 -topk8 -nocrypt -in _ec_private.pem -outform DER -out _ec_private.der

p11tool --provider ${PWD}/target/debug/libnethsm_pkcs11.so --write  --id $HEXID --label $KEYID --load-privkey _ed_private.pem 

curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

## Sign with openssl

echo 'NetHSM rulez!' > _data

openssl pkeyutl -sign -inkey _ed_private.pem -out _data.sig -rawin -in _data

## Verify with openssl and the retrieved public key
openssl pkeyutl -verify -sigfile _data.sig -inkey _public.pem -pubin -rawin -in _data