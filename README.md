# PKCS#11 Driver for the Nitrokey NetHSM

## Note

This driver is still an early Proof of Concept implementation that only
implements the functions that are necessary for operating TLS servers like for
example an HTTPS server.

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
