#!/bin/sh -x

KEYID=$1

HEXID=$(echo ${KEYID}'\c' | xxd -ps)

rm _data.sig _public.pem

curl -s -u operator:opPassphrase -X GET \
  https://nethsmdemo.nitrokey.com/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | pkcs11-tool --module p11nethsm.so -v -p opPassphrase \
  --sign --mechanism RSA-PKCS --output-file _data.sig --id $HEXID

openssl rsautl -verify -inkey _public.pem -in _data.sig -pubin
