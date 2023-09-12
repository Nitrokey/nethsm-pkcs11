#!/bin/sh -x

set -e 
KEYID=rsakey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.sig _public.pem

curl -s --fail-with-body -k -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v \
  --sign --mechanism SHA256-RSA-PKCS-PSS --output-file _data.sig --id $HEXID 

echo 'NetHSM rulez!' | openssl dgst -keyform PEM -verify _public.pem -sha256 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature _data.sig
