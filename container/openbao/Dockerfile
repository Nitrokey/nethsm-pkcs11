FROM rust AS builder

WORKDIR /rust

ADD . build

RUN cd build && cargo build --release

FROM almalinux AS alma

RUN dnf install -y opensc

FROM ghcr.io/openbao/openbao-hsm-ubi:2.5.2

COPY --from=builder /rust/build/target/release/libnethsm_pkcs11.so /usr/lib/nitrokey/libnethsm_pkcs11.so
COPY --from=alma /usr/lib64/pkcs11-spy.so /usr/lib64/pkcs11-spy.so
