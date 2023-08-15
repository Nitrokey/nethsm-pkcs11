#!/bin/sh -x
set -e

KEYID=edkey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.sig _public.pem

curl -k -s --fail-with-body -u operator:opPassphrase -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' > _data

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v  \
  --sign --mechanism EDDSA --output-file _data.sig --id $HEXID --input-file _data

#echo 'NetHSM rulez!' | openssl dgst -sha256 -binary | openssl pkeyutl -verify -pubin -inkey _public.pem -sigfile _data.sig
openssl pkeyutl -verify -sigfile _data.sig -inkey _public.pem -keyform PEM -pubin -rawin -in _data
