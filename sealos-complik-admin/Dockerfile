FROM golang:1.26.1-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/sealos-complik-admin ./cmd

FROM alpine:3.22 AS runtime

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app \
    && adduser -S -G app app

COPY --from=builder /out/sealos-complik-admin /app/sealos-complik-admin
COPY configs /app/configs

RUN mkdir -p /app/logs \
    && if [ ! -f /app/configs/config.env.yaml ] && [ -f /app/configs/config.yaml ]; then ln -s /app/configs/config.yaml /app/configs/config.env.yaml; fi \
    && chown -R app:app /app

ENV TZ=Asia/Shanghai

USER app

EXPOSE 8080

ENTRYPOINT ["/app/sealos-complik-admin"]
