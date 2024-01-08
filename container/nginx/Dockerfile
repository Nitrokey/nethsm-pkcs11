FROM docker.io/rust:1.70-buster AS builder

WORKDIR /rust

ADD '.' /rust/build

RUN cd build && cargo build --release

FROM docker.io/nginx:stable

RUN apt-get update && apt-get install -y --no-install-recommends \
  libengine-pkcs11-openssl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /rust/build/target/release/libnethsm_pkcs11.so /usr/lib/x86_64-linux-gnu/pkcs11/libnethsm_pkcs11.so
COPY _certificate.pem /certs/certificate.pem

ADD container/nginx/openssl.cnf /etc/ssl/openssl.cnf
ADD container/nginx/nginx.conf /etc/nginx/nginx.conf
ADD container/nginx/p11nethsm.conf /etc/nitrokey/p11nethsm.conf
ADD container/nginx/default.conf /etc/nginx/conf.d/default.conf


