#!/bin/bash -x

set -e

if [[ $NETHSM_VERSION == v1.* ]] || [[ $NETHSM_VERSION == v2.* ]] || [[ $NETHSM_VERSION == v3.* ]] || [[ $NETHSM_VERSION == v4.* ]]
then
  exit
fi

KEYID=testRSAkey
HEXID=$(echo -n ${KEYID} | xxd -ps)
LABEL=testlabel

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

pkcs11-tool --module target/debug/libnethsm_pkcs11.so -k --key-type RSA:4096 \
    --login --login-type so --so-pin Administrator --label $LABEL
pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so --label $LABEL --read-object --type pubkey --output-file /tmp/key.der
