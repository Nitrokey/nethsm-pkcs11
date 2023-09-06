#!/bin/sh

set -e

openssl req -x509 -newkey rsa:2048 -keyout ./_privatekey.pem -out ./_certificate.pem -days 365 -nodes -subj "/C=US/ST=California/L=San Francisco/O=Your Company/OU=Your Department/CN=yourdomain.com"

HOST='localhost:8443'

curl -k -u admin:Administrator -i -X DELETE \
  https://$HOST/api/v1/keys/webserver

curl -k -i -w '\n' -u admin:Administrator -X PUT \
  'https://'$HOST'/api/v1/keys/webserver?mechanisms=RSA_Decryption_RAW,RSA_Decryption_PKCS1,RSA_Decryption_OAEP_MD5,RSA_Decryption_OAEP_SHA1,RSA_Decryption_OAEP_SHA224,RSA_Decryption_OAEP_SHA256,RSA_Decryption_OAEP_SHA384,RSA_Decryption_OAEP_SHA512,RSA_Signature_PKCS1,RSA_Signature_PSS_MD5,RSA_Signature_PSS_SHA1,RSA_Signature_PSS_SHA224,RSA_Signature_PSS_SHA256,RSA_Signature_PSS_SHA384,RSA_Signature_PSS_SHA512' \
  -H 'Content-Type: application/x-pem-file' \
  --data-binary '@_privatekey.pem'

curl -k -i -w '\n' -u admin:Administrator -X PUT \
  'https://'$HOST'/api/v1/keys/webserver/cert' \
  -H 'Content-Type: application/x-pem-file' \
  --data-binary '@_certificate.pem'
