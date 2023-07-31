# PKCS#11 Module for the Nitrokey NetHSM

This module allows to use a [Nitrokey NetHSM](https://www.nitrokey.com/products/nethsm) as a backend for PKCS#11 operations.

See the [list of supported features](./features.md) for more details.

## Download

Download the latest binary corresponding to your system from the [release page](https://github.com/Nitrokey/nethsm-pkcs11/releases).

## Documentation

Follow the [documentation](https://docs.nitrokey.com/nethsm/pkcs11-setup.html) for usage instructions.

## Building

OpenSSL and a working Rust toolchain are required.

```
cargo build --release
```

The dynamic library will be in `target/release/libnethsm_pkcs11.so`.

### Alpine

You need to install musl-dev, openssl-dev:

```
apk add musl-dev openssl-dev
```

To build on Alpine you will need to add the C argument `target-feature=-crt-static`:

```
RUSTFLAGS="-C target-feature=-crt-static" cargo build --release
```


## Test Function (dev)

```
cargo build && RUST_LOG=trace P11NETHSM_CONFIG_FILE=./p11nethsm.conf NETHSM_PASS=TEST pkcs11-tool --module target/debug/libnethsm_pkcs11.so -I 
```

## Debug Options

Set the `RUST_LOG` env variable to `trace`, `debug`, `info`, `warn` or `err` to change the logging level.
