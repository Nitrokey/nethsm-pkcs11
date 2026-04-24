OpenBao Unseal Example
-------------

This example contains a compose file with several services.
- The `nethsm` service container, which behaves like the real NetHSM
- The `nethsm-provisioner` container, which provisions and auto-unlocks the NetHSM it if it has already been provisioned
- The `openbao-hsm` container, which is based `openbao-hsm-ubi` and includes `libnethsm_pkcs11`

### Startup

1. Build and start the compose stack: `docker compose up --build -d`
2. Initialise OpenBao `docker exec -it openbao_openbao-hsm_1 bao operator init -address="http://127.0.0.1:8200"`
    - Note down the recovery keys and the root token for later
3. Verify, that OpenBao was successfully unsealed `docker logs openbao_openbao-hsm_1 2>&1 | tail`
    - Watch for this line `[...]  core: vault is unsealed`
4. You can now access OpenBao at `http://127.0.0.1:8200/` and log in with the root token
    - If you manually seal the OpenBao instance you must either restart it to auto-unseal or use the recovery keys to unseal manually
5. When (re)starting OpenBao it is auto-unsealed by NetHSM `docker restart openbao_openbao-hsm_1`

### Configuration Details

- `p11nethsm.conf` contains the libnethsm_pkcs11 configuration
    - You can change the instance URL to test with real NetHSM hardware
- `config/config.hcl` contains the OpenBao configuration
    - It sets `seal "pkcs11"` to use the right pkcs11 library and parameters
- `provision.sh` is used by the nethsm-provisioner to provision the NetHSM
    - It creates an operator user to be used by OpenBao
    - It also generates the key used for unsealing ( mechanism `RSA_Decryption_OAEP_SHA256` )
        - The equivalent nitropy command is: `nitropy nethsm generate-key --type rsa --mechanism rsa_decryption_oaep_sha256 --length 2048 --key-id bao-root-rsa`

