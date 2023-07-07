#!/bin/sh -x

KEYID=$1

HEXID=$(echo -n ${KEYID}'\c' | xxd -ps)

rm -rf _data.crypt _public.pem

curl -k -s -u operator:opPassphrase -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | openssl pkeyutl -encrypt -pubin -inkey _public.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha512 \
  -pkeyopt rsa_mgf1_md:sha512 -out _data.crypt

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v -p opPassphrase --decrypt \
  --mechanism RSA-PKCS-OAEP --input-file _data.crypt --id $HEXID \
  --hash-algorithm SHA512
