# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    target_os="${TARGETOS:-linux}" && \
    target_arch="${TARGETARCH:-$(go env GOARCH)}" && \
    CGO_ENABLED=0 GOOS="${target_os}" GOARCH="${target_arch}" \
    go build -trimpath -ldflags="-s -w" -p=1 -o /out/manager ./cmd/complik

FROM debian:bookworm-slim

ENV CHROME_BIN=/usr/bin/chromium \
    ROD_BROWSER_BIN=/usr/bin/chromium \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/manager /manager

RUN echo "nonroot:x:65532:" >> /etc/group && \
    echo "nonroot:x:65532:65532:nonroot:/nonexistent:/usr/sbin/nologin" >> /etc/passwd && \
    mkdir -p /tmp/.cache/rod && \
    chmod 1777 /tmp/.cache /tmp/.cache/rod && \
    chmod +x /manager

EXPOSE 8428
USER 65532:65532

ENTRYPOINT ["/manager"]
