#!/bin/sh -x

set -e 

KEYID=testAESkey

HEXID=$(echo -n ${KEYID} | xxd -ps)

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

pkcs11-tool --module target/debug/libnethsm_pkcs11.so --keygen --key-type AES:128 \
    --login --login-type so --so-pin Administrator --id $HEXID

curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID