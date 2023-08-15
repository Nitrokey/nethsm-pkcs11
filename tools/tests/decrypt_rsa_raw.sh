#!/bin/sh -x

KEYID=rsakey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.crypt _public.pem _input _data.decrypt

curl -k -s --fail-with-body -u operator:opPassphrase -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaastratsaatastrastrastratsartsrasrastartsartastasrstatsarstarstar' > _input

openssl rsautl -encrypt -inkey _public.pem -pubin \
  -out _data.crypt -raw -in _input

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v --decrypt \
  --mechanism RSA-X-509 --input-file _data.crypt --id $HEXID --output-file _data.decrypt

diff _input _data.decrypt

