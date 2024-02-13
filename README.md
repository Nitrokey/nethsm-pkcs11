# PKCS#11 Module for the Nitrokey NetHSM

[![codecov.io][codecov-badge]][codecov-url]

[codecov-badge]: https://codecov.io/gh/nitrokey/nethsm-pkcs11/branch/main/graph/badge.svg
[codecov-url]: https://app.codecov.io/gh/nitrokey/nethsm-pkcs11/tree/main

This module allows to use a [Nitrokey NetHSM](https://www.nitrokey.com/products/nethsm) as a backend for PKCS#11 operations.

See the [list of supported features](./features.md) for more details.

## Download

Download the latest binary from the [release page](https://github.com/Nitrokey/nethsm-pkcs11/releases).

## Documentation

Follow the [documentation](https://docs.nitrokey.com/nethsm/pkcs11-setup.html) for usage instructions.

## Debug Options

Set the `RUST_LOG` env variable to `trace`, `debug`, `info`, `warn` or `err` to change the logging level.

## Docker Examples

For testing and development purposes there are two examples using the PKCS11 driver with Nginx and Apache.

They require each a certificate built with the `container/<server>/generate.sh`.

They can be built with:

```bash
# Building the images 
docker build -t nginx-testing -f container/nginx/Dockerfile .
docker build -t apache-testing -f container/apache/Dockerfile .
```

Assuming that a NetHSM is runnig on localhost:8443, they can then be run with :

```bash
docker run --net=host nginx-testing:latest
docker run --net=host apache-testing:latest
```

The NetHSM is expected to have be provisionned with the following configuration:

```bash
nitropy nethsm --host localhost:8443 --no-verify-tls provision -u 0123456789 -a Administrator
nitropy nethsm --host localhost:8443 --no-verify-tls add-user -n Operator -u operator -p opPassphrase -r Operator
```

## Building

Required are `gcc` and a working Rust toolchain of at least version (MSRV) 1.70.

```
cargo build --release
```

The dynamic library will be in `${CARGO_TARGET_DIR:-target}/release/libnethsm_pkcs11.so`.

### Alpine Linux

You need to install `musl-dev` and `gcc`:

```
apk add musl-dev gcc
```

To build on Alpine Linux you will need to add the C argument `target-feature=-crt-static`:

```
RUSTFLAGS="-C target-feature=-crt-static" cargo build --release
```
