#!/bin/sh -x

KEYID=$1

HEXID=$(echo ${KEYID}'\c' | xxd -ps)

rm _data.sig _public.pem

curl -s -u operator:opPassphrase -X GET \
  https://nethsmdemo.nitrokey.com/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | openssl dgst -sha512 -binary | pkcs11-tool \
  --module p11nethsm.so -v -p opPassphrase --sign --mechanism RSA-PKCS-PSS \
  --hash-algorithm SHA512 --output-file _data.sig --id $HEXID

echo 'NetHSM rulez!' | openssl dgst -keyform PEM -verify _public.pem -sha512 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature _data.sig
