#!/bin/sh -x

set -e 

rm -rf _rsa_private.pem _rsa_private.der _public.pem _data.sig

openssl genrsa -out _rsa_private.pem 2048

KEYID=edtest

HEXID=$(echo -n ${KEYID}| xxd -ps)

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

p11tool --provider ${PWD}/target/debug/libnethsm_pkcs11.so --write  --id $HEXID --label $KEYID --load-privkey _rsa_private.pem

curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/${KEYID}/public.pem -o _public.pem

## Sign with openssl

echo 'NetHSM rulez!' | openssl dgst -sha256 -sign _rsa_private.pem -out _data.sig

## Verify with openssl and the retrieved public key

echo 'NetHSM rulez!' | openssl dgst -keyform PEM -sha256 --verify _public.pem -signature _data.sig
