#!/bin/sh -x

set -e 

KEYID=testECkey

HEXID=$(echo -n ${KEYID} | xxd -ps)

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

pkcs11-tool --module target/debug/libnethsm_pkcs11.so -k --key-type EC:prime521v1 \
    --login --login-type so --so-pin Administrator --id $HEXID

curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem 