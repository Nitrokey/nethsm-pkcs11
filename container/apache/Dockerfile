FROM docker.io/rust:1.72-bookworm AS builder

WORKDIR /rust

ADD '.' /rust/build

RUN cd build && cargo build --release

FROM docker.io/httpd:2.4

RUN apt-get update && apt-get install -y --no-install-recommends \
  libengine-pkcs11-openssl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /rust/build/target/release/libnethsm_pkcs11.so /usr/lib/x86_64-linux-gnu/pkcs11/libnethsm_pkcs11.so
COPY _certificate.pem /certs/certificate.pem

ADD container/apache/openssl.cnf /etc/ssl/openssl.cnf
ADD container/apache/p11nethsm.conf /etc/nitrokey/p11nethsm.conf
ADD container/apache/httpd.conf /usr/local/apache2/conf/httpd.conf



