# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.24.5-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    target_os="${TARGETOS:-linux}" && \
    target_arch="${TARGETARCH:-$(go env GOARCH)}" && \
    CGO_ENABLED=0 GOOS="${target_os}" GOARCH="${target_arch}" \
    go build -trimpath -ldflags="-s -w" -p=1 -o /out/manager ./cmd/procscan

FROM alpine:3.22

RUN apk add --no-cache ca-certificates && \
    addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S -D -H -G nonroot nonroot

COPY --from=builder /out/manager /manager
COPY config.yaml /config/config.yaml

RUN chmod +x /manager

EXPOSE 8080
USER 65532:65532

ENTRYPOINT ["/manager"]
CMD ["--config=/config/config.yaml"]
