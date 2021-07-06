#!/bin/zsh

curl -k -i -w '\n' -u admin:adminadmin -X POST \
  https://nethsmdemo.nitrokey.com/api/v1/keys/generate \
  -H "content-type: application/json" \
  -d '{ "mechanisms": [ 
"RSA_Decryption_RAW", 
"RSA_Decryption_PKCS1",
"RSA_Decryption_OAEP_MD5",
"RSA_Decryption_OAEP_SHA1",
"RSA_Decryption_OAEP_SHA224",
"RSA_Decryption_OAEP_SHA256",
"RSA_Decryption_OAEP_SHA384",
"RSA_Decryption_OAEP_SHA512",
"RSA_Signature_PKCS1",
"RSA_Signature_PSS_MD5",
"RSA_Signature_PSS_SHA1",
"RSA_Signature_PSS_SHA224",
"RSA_Signature_PSS_SHA256",
"RSA_Signature_PSS_SHA384",
"RSA_Signature_PSS_SHA512"
],  "type": "RSA",  "length": 2048 }'
