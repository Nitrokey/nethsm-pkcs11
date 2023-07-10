# PKCS#11 Driver for the Nitrokey NetHSM

## Note

This driver is still an early Proof of Concept implementation that only
implements the functions that are necessary for operating TLS servers like for
example an HTTPS server.

See feature list here : [features.md](./features.md)

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
    user: "operator"                       # user connecting to the NetHSM server

    # The password can be provided by multiple means : 
    # - in plain text in the configuration `password: "mypassword"`
    # - in an environment variable read by the module with the `env:` prefix : `env:ENV_STORING_THE_PASSWORD`
    # - via the login function of pkcs11, example for pcks11-tool : `pkcs11-tool --module libnethsm_pkcs11.so -O -p opPassphrase`
    password: "env:LOCALHSMPASS"    
```
