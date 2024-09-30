ARG BUILDPLATFORM="linux/amd64"
ARG BUILDERIMAGE="golang:1.22-bookworm"
# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
ARG BASEIMAGE="gcr.io/distroless/static-debian12:nonroot"

FROM --platform=$BUILDPLATFORM $BUILDERIMAGE AS builder

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""
ARG LDFLAGS
ARG BUILDKIT_SBOM_SCAN_STAGE=true

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOARM=${TARGETVARIANT}

WORKDIR /go/src/github.com/umbrella-associates/opa-spicedb
COPY . .

#RUN go build -mod vendor -a -ldflags "${LDFLAGS}" -o manager
RUN go build -ldflags "${LDFLAGS}" -o opa-spicedb

FROM $BASEIMAGE

WORKDIR /
COPY --from=builder /go/src/github.com/umbrella-associates/opa-spicedb/opa-spicedb .
USER 65532:65532
ENTRYPOINT ["/opa-spicedb"]
