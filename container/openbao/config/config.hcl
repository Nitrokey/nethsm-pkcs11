ui = true
api_addr = "http://127.0.0.1:8200"
log_level = "info"
storage "file" {
  path = "/openbao/file"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = "true"
}
seal "pkcs11" {
  lib       = "/usr/lib/nitrokey/libnethsm_pkcs11.so"
  slot      = "0"
  key_label = "bao-root-rsa"
  user      = "operator"
  pin       = "OperatorOperator"
}
