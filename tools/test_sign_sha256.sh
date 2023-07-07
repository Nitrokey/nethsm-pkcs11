#!/bin/sh -x
set -e

KEYID=$1

HEXID=$(echo -n ${KEYID}| xxd -ps)

echo $HEXID
echo $KEYID

rm -rf _data.sig _public.pem

curl -s -u operator:opPassphrase -k -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | openssl dgst -sha256 -binary | P11NETHSM_CONFIG_FILE=./p11nethsm.conf pkcs11-tool \
  --module ./target/debug/libnethsm_pkcs11.so -v --sign --mechanism RSA-PKCS-PSS \
  --hash-algorithm SHA256 --output-file _data.sig --id $HEXID

echo 'NetHSM rulez!' | openssl dgst -keyform PEM -verify _public.pem -sha256 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature _data.sig
