FROM golang:1.13.4-buster

MAINTAINER Eduardo Riveros<eduardo@niclabs.cl>

WORKDIR /
RUN apt update
RUN apt -y install libzmq3-dev libczmq-dev build-essential musl-dev

RUN git clone https://github.com/niclabs/dtcnode

WORKDIR /dtcnode
RUN go mod tidy -v
RUN go build

RUN mkdir /etc/dtcnode

# Sleep because we need to wait the network to be initialized
CMD sleep 5 && /dtcnode/dtcnode
