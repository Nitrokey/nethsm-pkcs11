#!/bin/sh -x

set -e 

rm -rf _cert.key _cert.der _curl_cert.der

export P11NETHSM_CONFIG_FILE=./tools/der_cert.conf

KEYID=certtest

HEXID=$(echo -n ${KEYID}| xxd -ps)


curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

openssl req -x509 -newkey rsa:2048 -keyout _cert.key -out _cert.der -outform DER -days 365 -nodes -subj "/CN=www.example.com"
openssl x509 -in _cert.der -out _cert.pem -inform DER -outform PEM

p11tool --provider ${PWD}/target/debug/libnethsm_pkcs11.so --write  --id $HEXID --label $KEYID --load-privkey _cert.key
p11tool --provider ${PWD}/target/debug/libnethsm_pkcs11.so --write  --id $HEXID --label $KEYID --load-certificate _cert.pem

p11tool --provider ${PWD}/target/debug/libnethsm_pkcs11.so --write  --id $HEXID --label $KEYID --list-cert |grep 'Type: X.509 Certificate'


# check if the cert is there
curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/cert --header "Accept: application/octet-stream" -o _curl_cert.der

diff _cert.der _curl_cert.der

