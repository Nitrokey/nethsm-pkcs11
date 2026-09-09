ui = true
api_addr = "http://127.0.0.1:8200"
log_level = "info"
license_path = "/vault/config/license.hclic"
disable_mlock = true
storage "file" {
 path = "/vault/file"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = "true"
}
# Use NetHSM for sealing operations
seal "pkcs11" {
  lib       = "/usr/lib/nitrokey/libnethsm_pkcs11.so"
  slot      = "0"
  key_label = "vault-root-rsa"
  mechanism = "0x0009"
  rsa_encrypt_local = "true"
  pin       = "OperatorOperator"
}
# Use NetHSM for entropy augmentation
entropy "seal" {
  mode = "augmentation"
}
# Use NetHSM as KMS library for managed keys
# Note: this is mostly untested
kms_library "pkcs11" {
  name = "nethsm"
  library = "/usr/lib/nitrokey/libnethsm_pkcs11.so"
}
