#!/bin/sh -x

set -e 
KEYID=rsakey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.sig _public.pem

curl -s --fail-with-body -k -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v \
  --sign --mechanism SHA224-RSA-PKCS --output-file _data.sig --id $HEXID --signature-format openssl

echo 'NetHSM rulez!' | openssl dgst -sha224 -binary | openssl pkeyutl -verify -inkey _public.pem -sigfile _data.sig -pubin -pkeyopt digest:sha224
