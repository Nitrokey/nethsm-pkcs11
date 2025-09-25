#!/bin/sh -x

set -e 

rm -rf _rsa_private.pem _rsa_private.der _public.pem _data.sig

openssl genrsa -out _rsa_private.pem 2048

KEYID=01

HEXID=$(echo -n ${KEYID}| xxd -ps)

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID

pkcs11-tool --module ${PWD}/target/debug/libnethsm_pkcs11.so \
  --login-type so \
  --write-object _rsa_private.pem --type privkey \
  --id $KEYID \
  --allowed-mechanisms RSA-X-509,RSA-PKCS,SHA1-RSA-PKCS,SHA224-RSA-PKCS,SHA256-RSA-PKCS,SHA384-RSA-PKCS,SHA512-RSA-PKCS,RSA-PKCS-PSS,SHA1-RSA-PKCS-PSS,SHA224-RSA-PKCS-PSS,SHA256-RSA-PKCS-PSS,SHA384-RSA-PKCS-PSS,SHA512-RSA-PKCS-PSS,RSA-PKCS-OAEP,RSA-PKCS-KEY-PAIR-GEN

if !(curl -k --fail-with-body -u operator:opPassphrase -v -X GET \
  https://localhost:8443/api/v1/keys/${KEYID} \
  | jq '.mechanisms' | grep RSA); then

  echo "missing MECHANISMS"
  exit 1
fi

