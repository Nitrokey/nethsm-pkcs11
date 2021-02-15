#!/bin/sh -x

KEYID=$1

HEXID=$(echo ${KEYID}'\c' | xxd -ps)

rm _data.crypt _public.pem

curl -s -u operator:opPassphrase -X GET \
  https://nethsmdemo.nitrokey.com/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | openssl rsautl -encrypt -inkey _public.pem -pubin \
  -out _data.crypt

pkcs11-tool --module p11nethsm.so -v -p opPassphrase --decrypt \
  --mechanism RSA-PKCS --input-file _data.crypt --id $HEXID

