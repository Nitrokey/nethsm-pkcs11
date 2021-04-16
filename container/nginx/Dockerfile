FROM golang AS builder

ADD .git/ /tmp/repo

RUN git clone -s /tmp/repo build

RUN cd build && ./build.sh

FROM nginx:stable

RUN apt-get update && apt-get install -y --no-install-recommends \
  libengine-pkcs11-openssl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/build/p11nethsm.so /usr/lib/x86_64-linux-gnu/pkcs11/

ADD container/nginx/openssl.cnf /etc/ssl/openssl.cnf
ADD container/nginx/nginx.conf /etc/nginx/nginx.conf
ADD p11nethsm.conf /etc/nitrokey/p11nethsm.conf
ADD container/nginx/default.conf /etc/nginx/conf.d/default.conf
