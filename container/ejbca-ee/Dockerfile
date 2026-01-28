# Multi-stage build for Nitrokey NetHSM PKCS#11 Sidecar

FROM alpine:3.22 as builder
LABEL maintainer="Nitrokey GmbH <support@nitrokey.com>"

RUN apk add --no-cache wget pcsc-lite

ARG VERSION=v2.0.0
ARG ARCH=x86_64
ARG LIB=glibc

ARG PKCS11_SHA256="6c69779aa9d8b2a4fd94d796bdcfb64c7a16dd7c67650fd9c492b32ebc30c214"
ARG PKCS11_FILE=nethsm-pkcs11-${VERSION}-${ARCH}-linux-${LIB}.so

RUN wget https://github.com/Nitrokey/nethsm-pkcs11/releases/download/${VERSION}/${PKCS11_FILE} \
    -O /${PKCS11_FILE}

RUN echo "${PKCS11_SHA256} nethsm-pkcs11-${VERSION}-${ARCH}-linux-${LIB}.so" | sha256sum -c -
RUN mv nethsm-pkcs11-${VERSION}-${ARCH}-linux-${LIB}.so /libnethsm_pkcs11.so

# ----------------------------------------------------------------------
# --- RUNTIME STAGE ---
# Use softhsm as image base
# ----------------------------------------------------------------------
FROM repo.keyfactor.com/ejbca/hsm-driver-softhsm:1.1.0 AS runtime
LABEL maintainer="Nitrokey GmbH <support@nitrokey.com>"

# Create the dedicated directory for the library for better organization
RUN mkdir -p /opt/keyfactor/nitrokey/lib/ && \
    rm /opt/keyfactor/init.sh && \
    rm /opt/keyfactor/softhsm2.conf 

# Copy the verified library from the builder stage.
COPY --from=builder /libnethsm_pkcs11.so /opt/keyfactor/nitrokey/lib/libnethsm_pkcs11.so

# Required by hsm-driver-base: Tells the P11 Proxy server where to find the vendor's PKCS#11 library.
ENV HSM_PKCS11_LIBRARY=/opt/keyfactor/nitrokey/lib/libnethsm_pkcs11.so
VOLUME /opt/keyfactor/p11proxy-client

# Standard configuration
EXPOSE 7121
ENV PKCS11_DAEMON_SOCKET="tcp://0.0.0.0:7121"

# Command to start the P11 Proxy Server (usually provided by the base image)
CMD /usr/bin/start.sh
