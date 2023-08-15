#!/bin/sh -x
set -e

KEYID=eckey384

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.sig _public.pem

curl -k -s --fail-with-body -u operator:opPassphrase -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | openssl dgst -sha384 -binary | pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v  \
  --sign --mechanism ECDSA --output-file _data.sig --signature-format openssl --id $HEXID

echo 'NetHSM rulez!' | openssl dgst -keyform PEM -sha384 -verify _public.pem -signature _data.sig
