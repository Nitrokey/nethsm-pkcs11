# PKCS#11 Module for the Nitrokey NetHSM

This module allows to use a Nitrokey NetHSM as a backend for pkcs11 operations.

Some features of pkcs11 are not supported, see the feature list here : [features.md](./features.md)

## Download

Download the binary corresponding to your system here : [latest release](https://github.com/Nitrokey/nethsm-pkcs11/releases).

## Documentation

The documentation is available on [Nitrokey's Website](https://docs.nitrokey.com/nethsm/pkcs11-setup.html)

## Building

Openssl and a working rust toolchain are required.

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

## Debug options

Set the `RUST_LOG` env variable to `trace`, `debug`, `info`, `warn` or `err` to change the logging level.