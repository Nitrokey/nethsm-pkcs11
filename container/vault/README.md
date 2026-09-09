# Hashicorp Vault Unseal Example

This example contains a compose file with several services:
-
 The `nethsm` service container, which behaves like the real NetHSM.
- The `nethsm-provisioner` container, which provisions and auto-unlocks the NetHSM it if it has already been provisioned.
- The `vault-hsm` container, which is based on `vault-enterprise:X.X.X-ent.hsm` (the Enterprise HSM version of Vault) and includes `libnethsm_pkcs11`.

## Startup

1. Build and start the compose stack: `docker compose up --build -d`
2. Initialise Vault: `docker exec -it vault_vault-hsm_1 vault operator init -address="http://127.0.0.1:8200"`
    - Note down the recovery keys and the root token for later.
3. Verify that Vault was successfully unsealed: `docker logs vault_vault-hsm_1 2>&1 | tail`
    - Watch for this line `[...]  core: vault is unsealed`
4. You can now access Vault at `http://127.0.0.1:8200/` and log in with the root token.
    - If you manually seal the Vault instance you must either restart it to auto-unseal or use the recovery keys to unseal manually.
5. When (re)starting Vault it is auto-unsealed by NetHSM: `docker restart vault_vault-hsm_1`

## Configuration Details

- `p11nethsm.conf` contains the libnethsm_pkcs11 configuration.
    - You can change the instance URL to test with real NetHSM hardware.
- `config/config.hcl` contains the Vault configuration.
    - It sets `seal "pkcs11"` to use the right PKCS#11 library and parameters.
- `provision.sh` is used by the nethsm-provisioner to provision the NetHSM.
    - It creates an operator user to be used by Vault.
    - It also generates the key used for unsealing ( mechanism `RSA_Decryption_OAEP_SHA256` ).

# Using NetHSM as 3rd party key management in Vault

Vault has support for [3rd party key management](https://developer.hashicorp.com/vault/docs/enterprise/managed-keys) via PKCS#11,
if nethsm-pkcs11 is configured as [kms_library](https://developer.hashicorp.com/vault/docs/configuration/kms-library).
The [transit secrets engine](https://developer.hashicorp.com/vault/docs/enterprise/managed-keys/transit-secret-engine)
and the [SSH secrets engine](https://developer.hashicorp.com/vault/docs/enterprise/managed-keys/ssh-secret-engine) can then
be configured to use NetHSM as backend.

Here is an example of how to configure an RSA key for later use in the transit secrets engine:
```
docker exec -it vault_vault-hsm_1 vault write -address="http://127.0.0.1:8200" sys/managed-keys/pkcs11/transit-rsa-key library=nethsm slot=0 pin=OperatorOperator key_label="vault-rsa-key" allow_generate_key=true mechanism=0x0001  allow_store_key=true key_bits=2048 any_mount=false
```

# Tested Versions

|nethsm-pkcs11|nethsm container|vault-enterprise|
|-|-|-|
|v3.0.0|testing-v5.0|2.1.0-ent.hsm|
