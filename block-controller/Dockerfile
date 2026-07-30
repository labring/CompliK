FROM golang:1.25 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/block-controller ./cmd

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/block-controller /block-controller
USER 65532:65532
ENTRYPOINT ["/block-controller"]
