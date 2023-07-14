#!/bin/sh -x

set -e 

rm -rf _test_rsa_private.pem _test_rsa_private.der _public.pem _rsa_public.pem

# openssl ecparam -name prime256v1 -genkey -noout -out _ec_private.pem
openssl genrsa -out _rsa_private.pem 2048

# openssl pkcs8 -topk8 -nocrypt -in _ec_private.pem -outform DER -out _ec_private.der
openssl pkcs8 -topk8 -nocrypt -in _rsa_private.pem -outform DER -out _rsa_private.der


OUTPUT=$(pkcs11-tool --module target/debug/libnethsm_pkcs11.so -y privkey --write-object _rsa_private.der --login --login-type so --so-pin Administrator)

id=$(echo "$OUTPUT" | awk '/label:/{print $2}')

curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$id/public.pem -o _public.pem

## Sign with openssl

echo 'NetHSM rulez!' | openssl dgst -sha256 -binary | openssl pkeyutl -sign -inkey _rsa_private.pem -out _data.sig

## Verify with openssl and the retrieved public key

echo 'NetHSM rulez!' | openssl dgst -keyform PEM -sha256 --verify _public.pem -signature _data.sig
