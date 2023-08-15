#!/bin/sh -x

KEYID=rsakey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.sig _public.pem

curl -k -s --fail-with-body -u operator:opPassphrase -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | openssl dgst -sha1 -binary | pkcs11-tool \
  --module ./target/debug/libnethsm_pkcs11.so  -v --sign --mechanism RSA-PKCS-PSS \
  --hash-algorithm SHA-1 --output-file _data.sig --id $HEXID

echo 'NetHSM rulez!' | openssl dgst -keyform PEM -verify _public.pem -sha1 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature _data.sig
