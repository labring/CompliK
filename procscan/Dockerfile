FROM --platform=$BUILDPLATFORM golang:1.24.5-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# Limit parallel package builds to reduce peak memory usage during image builds.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -p=1 -o /out/manager ./cmd/procscan

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/manager /manager
COPY config.yaml /config/config.yaml

EXPOSE 8428
USER 65532:65532

ENTRYPOINT ["/manager"]
CMD ["--config=/config/config.yaml"]
 