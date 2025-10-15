#!/bin/bash -x

set -e 

if [[ $NETHSM_VERSION == v3.0 ]]
then
  exit
fi

KEYID=rsakey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.sig _public.pem

curl -s --fail-with-body -k -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' | pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v \
  --sign --mechanism RSA-PKCS --output-file _data.sig --id $HEXID

openssl rsautl -verify -inkey _public.pem -in _data.sig -pubin
