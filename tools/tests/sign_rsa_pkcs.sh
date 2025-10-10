#!/bin/sh -x

set -e 
KEYID=rsakey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.sig _public.pem

curl -s --fail-with-body -k -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

# NetHSM v3.0 only accepts digests with the correct length in PKCS1 mode.
echo -n '12345678901234567890123456789012' | pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v \
  --sign --mechanism RSA-PKCS --output-file _data.sig --id $HEXID

openssl rsautl -verify -inkey _public.pem -in _data.sig -pubin
