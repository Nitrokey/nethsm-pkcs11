FROM rust AS builder

WORKDIR /rust

ADD . build

RUN cd build && cargo build --release

FROM ghcr.io/openbao/openbao-hsm-ubi:2.5.2

COPY --from=builder /rust/build/target/release/libnethsm_pkcs11.so /usr/lib/nitrokey/libnethsm_pkcs11.so
