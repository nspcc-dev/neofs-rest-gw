FROM golang:1.22 as basebuilder

RUN set -x \
    && apt-get update \
    && apt-get install -y make jq

FROM basebuilder as builder
ENV GOGC off
ENV CGO_ENABLED 0
ARG VERSION=dev
ARG REPO=repository

WORKDIR /src
COPY . /src

RUN make

# Executable image
FROM scratch

WORKDIR /

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/bin/neofs-rest-gw /bin/neofs-rest-gw

ENTRYPOINT ["/bin/neofs-rest-gw"]
