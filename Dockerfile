# syntax=docker/dockerfile:1.7

# Builder stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git

# Copy source code
COPY . .

# Build binary
# TODO: pin to digest with crane digest
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty=.MODIFIED)" \
    -o /build/ghactor \
    ./cmd/ghactor

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /

# Copy binary from builder
COPY --from=builder /build/ghactor /usr/local/bin/ghactor

# Set to nonroot user (UID 65532)
USER nonroot

ENTRYPOINT ["/usr/local/bin/ghactor"]

# Default command
CMD ["--help"]
