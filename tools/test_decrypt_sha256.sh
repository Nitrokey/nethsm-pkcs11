#!/bin/sh -x

KEYID=$1

HEXID=$(echo ${KEYID}'\c' | xxd -ps)

rm _data.crypt _public.pem

curl -s -u operator:opPassphrase -X GET \
  https://nethsmdemo.nitrokey.com/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | openssl pkeyutl -encrypt -pubin -inkey _public.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256 -out _data.crypt

pkcs11-tool --module p11nethsm.so -v -p opPassphrase --decrypt \
  --mechanism RSA-PKCS-OAEP --input-file _data.crypt --id $HEXID \
  --hash-algorithm SHA256
