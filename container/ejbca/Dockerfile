FROM rust:1.70-buster AS builder

WORKDIR /rust

ADD . build

RUN cd build && cargo build --release

FROM almalinux:8 AS alma 

RUN dnf install -y opensc

FROM keyfactor/ejbca-ce

COPY --from=builder /rust/build/target/release/libnethsm_pkcs11.so /usr/lib/nitrokey/libnethsm_pkcs11.so
COPY --from=alma /usr/lib64/pkcs11-spy.so /usr/lib64/pkcs11-spy.so
COPY container/ejbca/p11nethsm.conf /etc/nitrokey/p11nethsm.conf

RUN echo 'cryptotoken.p11.lib.245.name=NetHSM' >> /etc/ejbca/conf/web.properties
RUN echo 'cryptotoken.p11.lib.245.file=/usr/lib64/pkcs11-spy.so' >> /etc/ejbca/conf/web.properties
RUN echo 'cryptotoken.p11.lib.245.canGenerateKey=true' >> /etc/ejbca/conf/web.properties