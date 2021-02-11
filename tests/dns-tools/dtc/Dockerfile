FROM golang:1.13.4-buster

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apt update
RUN apt -y install libzmq3-dev libczmq-dev build-essential sqlite3

COPY ./dtc /dtc/

WORKDIR /dtc
ENV GO111MODULE on
RUN go mod download
RUN ./build.sh

WORKDIR /
RUN git clone https://github.com/niclabs/dns-tools

WORKDIR /dns-tools
RUN go mod tidy
RUN go build

RUN mv /dtc/dtc.so /dns-tools/dtc.so

# copy example zone and test with this shellscript.
COPY ./dtc/tests/dns-tools/dtc/test.sh test.sh 
COPY ./dtc/tests/dns-tools/dtc/example.com example.com

# Let's install docker inside docker! (we want to kill a node to test if the system works)
# Remember to link `/var/run/docker.sock:/var/run/docker.sock` as a volume

ENV DOCKERVERSION=19.03.12
RUN curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKERVERSION}.tgz \
  && tar xzvf docker-${DOCKERVERSION}.tgz --strip 1 -C /usr/local/bin docker/docker \
  && rm docker-${DOCKERVERSION}.tgz

# Sleep because we need to wait the network to be initialized
CMD sleep 5 && ./test.sh
