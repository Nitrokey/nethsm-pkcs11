#!/bin/sh -x

# disabled, not working with current version of pkcs11-tool
exit 0

set -e 

rm -rf _rsa_private.pem _rsa_private.der _public.pem _data.sig

# openssl ecparam -name prime256v1 -genkey -noout -out _ec_private.pem
openssl genrsa -out _rsa_private.pem 2048

# openssl pkcs8 -topk8 -nocrypt -in _rsa_private.pem -outform DER -out _rsa_private.der


OUTPUT=$(pkcs11-tool --module target/debug/libnethsm_pkcs11.so -y privkey --write-object _rsa_private.pem --login --login-type so --so-pin Administrator)

id=$(echo "$OUTPUT" | awk '/label:/{print $2}')

curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$id/public.pem -o _public.pem

## Sign with openssl

echo 'NetHSM rulez!' | openssl dgst -sha256 -sign _rsa_private.pem -out _data.sig

## Verify with openssl and the retrieved public key

echo 'NetHSM rulez!' | openssl dgst -keyform PEM -sha256 --verify _public.pem -signature _data.sig
