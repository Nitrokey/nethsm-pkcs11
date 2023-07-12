#/bin/sh

set -e

echo "Provisioning the HSM"

./tools/provision.sh
./tools/create_operator.sh
./tools/create_aes_key.sh
./tools/create_ec_key.sh
./tools/create_ed_key.sh
./tools/create_rsa_key.sh
./tools/create_web_key.sh


echo "Starting tests"

export P11NETHSM_CONFIG_FILE=./p11nethsm.conf

./tools/test_decrypt_sha1.sh
./tools/test_decrypt_sha256.sh
./tools/test_decrypt_sha512.sh
./tools/test_decrypt.sh
./tools/test_encrypt_aes.sh
./tools/test_ec_sign.sh
./tools/test_sign.sh
./tools/test_sign_sha1.sh
./tools/test_sign_sha256.sh

