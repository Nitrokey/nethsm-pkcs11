#!/bin/sh -x

set -e 

rm -rf _cert.key _cert.pem _curl_cert.pem

KEYID=certtest

HEXID=$(echo -n ${KEYID}| xxd -ps)


curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

openssl req -x509 -newkey rsa:2048 -keyout _cert.key -out _cert.pem -days 365 -nodes -subj "/CN=www.example.com"

p11tool --provider ${PWD}/target/debug/libnethsm_pkcs11.so --write  --id $HEXID --label $KEYID --load-privkey _cert.key
p11tool --provider ${PWD}/target/debug/libnethsm_pkcs11.so --write  --id $HEXID --label $KEYID --load-certificate _cert.pem


# check if the cert is there
curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/cert --header "Accept: application/x-pem-file" -o _curl_cert.pem

diff _cert.pem _curl_cert.pem

