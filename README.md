# PKCS#11 Module for the Nitrokey NetHSM

This module allows to use a Nitrokey NetHSM as a backend for pkcs11 operations.

Some features of pkcs11 are not supported, see the feature list here : [features.md](./features.md)

## Download

Download the binary corresponding to your system here : [latest release](https://github.com/Nitrokey/nethsm-pkcs11/releases).

## Configuration

By default the modules searches for configuration files in :

- `/etc/nitrokey/p11nethsm.conf`
- `/usr/local/etc/nitrokey/p11nethsm.conf`
- `~/.config/nitrokey/p11nethsm.conf`

If multiple files are present the slots of all the config files will be added.

You can manually set the config file location (only this one will be read) wiht the env variable `P11NETHSM_CONFIG_FILE1` (eg. `P11NETHSM_CONFIG_FILE=./p11nethsm.conf`).

### Configuration format

The configuration is yaml-formatted :

```yml
# you can set the log file location here, if no value is set, the module will only output to stderr
logfile: /tmp/p11nethsm.log

# each "slot" represents a NetHSM server
slots:
  - label: LocalHSM                        # name you NetHSM however you want
    description: Local HSM (docker)        # optional description
    url: "https://localhost:8443/api/v1"   # url to reach the server
    operator:
      username: "operator"                       # user connecting to the NetHSM server
      password: "env:LOCALHSMPASS"    
    administrator:
      username: "admin"
```

The operator and administrator users are both optional but the module won't start if no user is configured. This is so you can configure the module with only an administrator user, only an operator user or both at the same time.

When the two users are set the module will use the operator by default and only use the administrator user when the action needs it.

The regular PKCS11 user is mapped to the NetHSM operator and the PKCS11 SO is mapped to the NetHSM administrator.

The password can be provided by multiple means :

- in plain text in the configuration `password: "mypassword"`
- in an environment variable read by the module with the `env:` prefix : `env:ENV_STORING_THE_PASSWORD`
- via the login function of pkcs11, example for pcks11-tool : `pkcs11-tool --module libnethsm_pkcs11.so -p opPassphrase`
  To provide the the admin password you need to use `--so-pin` istead : `pkcs11-tool --module libnethsm_pkcs11.so --login --login-type so --so-pin Administrator`

If the password of an user is not set in the configuration file a login will be required to provide the password (3rd method).

A NetHSM that is not operational is considered as a slot wit the token not present.

## Building

```
cargo build --release
```

The dynamic library will be in `target/release/libnethsm_pkcs11.so`.

### Alpine

You need to install musl-dev, openssl-dev :

```
apk add musl-dev openssl-dev
```

To build on alpine you will need to add the C argument `target-feature=-crt-static` : 

```
RUSTFLAGS="-C target-feature=-crt-static" cargo build --release
```


## Test function (dev)

```
cargo build && RUST_LOG=trace P11NETHSM_CONFIG_FILE=./p11nethsm.conf NETHSM_PASS=TEST pkcs11-tool --module target/debug/libnethsm_pkcs11.so -I 
```
