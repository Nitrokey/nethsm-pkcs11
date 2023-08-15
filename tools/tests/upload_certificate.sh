#!/bin/sh -x

set -e 

rm -rf _cert.key _cert.pem

KEYID=Hello

HEXID=$(echo -n ${KEYID}| xxd -ps)


curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

# generate a certifcate
openssl req -x509 -newkey rsa:2048 -keyout _cert.key -out _cert.pem -days 365 -nodes -subj "/CN=www.example.com"

pkcs11-tool --module target/debug/libnethsm_pkcs11.so -y privkey --write-object _cert.key --id $HEXID 

pkcs11-tool --module target/debug/libnethsm_pkcs11.so -y cert --write-object _cert.pem --id $HEXID



# check if the cert is there
curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/cert --accept application/x-pem-file 

