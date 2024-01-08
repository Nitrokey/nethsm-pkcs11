#!/bin/bash

set -e

HOST='localhost:8443'
ADMIN_ACCOUNT='admin'
ADMIN_ACCOUNT_PWD='Administrator'

NETHSM_PKCS11_LIBRARY_PATH="target/release/libnethsm_pkcs11.so"


CREDENTIALS="${ADMIN_ACCOUNT}:${ADMIN_ACCOUNT_PWD}"

#Use here-documents to temporarily store the OpenSSL configuration. After this command the temporary file will be available at /dev/fd/3.
exec 3<<< "
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
MODULE_PATH = ${NETHSM_PKCS11_LIBRARY_PATH}
init = 0
"

curl --include --insecure --user $CREDENTIALS --request DELETE \
  "https://${HOST}/api/v1/keys/webserver"

curl --include --insecure --user $CREDENTIALS --request POST \
  "https://${HOST}/api/v1/keys/generate" \
  --header 'Content-Type: application/json' \
  --data '
    {
      "mechanisms": ["RSA_Decryption_RAW", "RSA_Decryption_PKCS1", "RSA_Decryption_OAEP_MD5", "RSA_Decryption_OAEP_SHA1", "RSA_Decryption_OAEP_SHA224", "RSA_Decryption_OAEP_SHA256", "RSA_Decryption_OAEP_SHA384", "RSA_Decryption_OAEP_SHA512", "RSA_Signature_PKCS1", "RSA_Signature_PSS_MD5", "RSA_Signature_PSS_SHA1", "RSA_Signature_PSS_SHA224", "RSA_Signature_PSS_SHA256", "RSA_Signature_PSS_SHA384", "RSA_Signature_PSS_SHA512"],
      "type": "RSA",
      "length": 2048,
      "id": "webserver"
    }  
  '

export OPENSSL_CONF="/dev/fd/3"

P11NETHSM_CONFIG_FILE="p11nethsm.conf" openssl req -new -x509 -out ./_certificate.pem -days 365 -subj "/CN=yourdomain.com" -engine pkcs11 -keyform engine -key "pkcs11:object=webserver;type=public"

curl -k -i -w '\n' -u $CREDENTIALS -X PUT \
  "https://${HOST}/api/v1/keys/webserver/cert" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary '@_certificate.pem'

