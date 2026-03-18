FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
  -trimpath \
  -ldflags="-s -w \
    -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Version=${VERSION} \
    -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Commit=${COMMIT} \
    -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Date=${BUILD_DATE}" \
  -o /out/gomap .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates bash

COPY --from=builder /out/gomap /usr/local/bin/gomap

ENTRYPOINT ["/usr/local/bin/gomap"]
CMD ["-h"]
