#!/bin/sh -x
set -e

KEYID=tempkey

HEXID=$(echo -n ${KEYID} | xxd -ps)

# create a key
openssl req -x509 -newkey rsa:2048 -keyout ./_privatekey.pem -out ./_certificate.pem -days 365 -nodes -subj "/C=US/ST=California/L=San Francisco/O=Your Company/OU=Your Department/CN=yourdomain.com"


curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

curl -k -i -w '\n' -u admin:Administrator -X PUT \
  "https://localhost:8443/api/v1/keys/${KEYID}?mechanisms=RSA_Decryption_RAW,RSA_Decryption_PKCS1,RSA_Decryption_OAEP_MD5,RSA_Decryption_OAEP_SHA1,RSA_Decryption_OAEP_SHA224,RSA_Decryption_OAEP_SHA256,RSA_Decryption_OAEP_SHA384,RSA_Decryption_OAEP_SHA512,RSA_Signature_PKCS1,RSA_Signature_PSS_MD5,RSA_Signature_PSS_SHA1,RSA_Signature_PSS_SHA224,RSA_Signature_PSS_SHA256,RSA_Signature_PSS_SHA384,RSA_Signature_PSS_SHA512" \
  -H 'Content-Type: application/x-pem-file' \
  --data-binary '@_privatekey.pem'

curl -k -i -w '\n' -u admin:Administrator -X PUT \
  https://localhost:8443/api/v1/keys/${KEYID}/cert \
  -H 'Content-Type: application/x-pem-file' \
  --data-binary '@_certificate.pem'
# delete the key
pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -v  \
  --delete-object --type cert --id $HEXID --login --login-type so --so-pin Administrator

## check that the key is gone
RESPONSE=$(curl -s -k -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/cert \
  -H 'Accept: application/x-pem-file' -o /dev/null -w "%{http_code}")

if [ $RESPONSE -eq 406 ]; then
  echo "Got 406 error, cert was deleted"
else
  echo "No 404 error, response code was $RESPONSE"
  exit 1
fi

