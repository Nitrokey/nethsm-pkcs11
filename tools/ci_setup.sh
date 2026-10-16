#/bin/sh

set -e

echo "Provisioning the HSM"

./tools/provision.sh
./tools/create_operator.sh
./tools/create_aes_key_encryption.sh
./tools/create_aes_key_decryption.sh
./tools/create_aes_key_encryption_decryption.sh
./tools/create_brainpool_keys.sh
./tools/create_ec_p256_key.sh
./tools/create_ec_p384_key.sh
./tools/create_ec_p521_key.sh
./tools/create_ec_p256k1_key.sh
./tools/create_ed_key.sh
./tools/create_rsa_key_decrypt.sh
./tools/create_rsa_key_sign.sh
./tools/create_rsa_key_decrypt_sign.sh
./tools/create_web_key.sh


