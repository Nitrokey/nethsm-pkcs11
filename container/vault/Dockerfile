FROM rust AS builder

WORKDIR /rust

ADD . build

RUN cd build && cargo build --release

FROM docker.io/hashicorp/vault-enterprise:2.1.0-ent.hsm

COPY --from=builder /rust/build/target/release/libnethsm_pkcs11.so /usr/lib/nitrokey/libnethsm_pkcs11.so
