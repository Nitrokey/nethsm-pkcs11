#!/bin/sh -x
set -e

KEYID=eckey256

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.sig _public.pem

curl -k -s --fail-with-body -u operator:opPassphrase -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'  | openssl dgst -sha224 -binary > _data

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v  \
  --sign --mechanism ECDSA --output-file _data.sig --signature-format openssl --id $HEXID --input-file _data

openssl pkeyutl -verify -sigfile _data.sig -inkey _public.pem -keyform PEM -pubin -in _data
