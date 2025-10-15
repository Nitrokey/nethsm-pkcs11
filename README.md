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

## Compatibility

nethsm-pkcs11 is compatible with these NetHSM versions:

| NetHSM Version | Compatibility | Notes |
| :------------: | :-----------: | ----- |
| [v1.0][nethsm-v1.0] | limited | |
| [v2.0][nethsm-v2.0] | limited | |
| [v2.1][nethsm-v2.1] | limited | |
| [v2.2][nethsm-v2.2] | limited | |
| [v3.0][nethsm-v3.0] | limited | RSA signatures using PKCS1 mechanisms do not work. |
| [v3.1][nethsm-v3.1] | full | |

[nethsm-v1.0]: https://github.com/Nitrokey/nethsm/releases/tag/v1.0
[nethsm-v2.0]: https://github.com/Nitrokey/nethsm/releases/tag/v2.0
[nethsm-v2.1]: https://github.com/Nitrokey/nethsm/releases/tag/v2.1
[nethsm-v2.2]: https://github.com/Nitrokey/nethsm/releases/tag/v2.2
[nethsm-v3.0]: https://github.com/Nitrokey/nethsm/releases/tag/v3.0
[nethsm-v3.1]: https://github.com/Nitrokey/nethsm/releases/tag/v3.1

Full compatibility means that all features of the NetHSM PKCS#11 module can be used with this version.
Limited compatibility means that only some features are available for this version.
See the [changelog](./CHANGELOG.md) for more detailed information on the version requirements for new features.

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

## Testing retries

There is a set of tests that run with multiple instances and test the retry and timeout mechanisms.
They require: access to `sudo` (or being run as root) and `podman`.
You can run the command:

```bash
USE_SUDO=true cargo t -p nethsm_pkcs11 --test basic -- multi_instance_retries
# Or remove the use of sudo if running as root
cargo t -p nethsm_pkcs11 --test basic -- multi_instance_retries
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
