#!/bin/sh -x

set -e 

KEYID=testEDkey

HEXID=$(echo -n ${KEYID} | xxd -ps)

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

p11tool --provider ${PWD}/target/debug/libnethsm_pkcs11.so --generate-privkey=Ed25519 --id $HEXID --label $KEYID

curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem 