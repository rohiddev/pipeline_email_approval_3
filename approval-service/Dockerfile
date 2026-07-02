# Build stage — compile the Go binary with CGO for SQLite
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o approval-service .

# Runtime stage — minimal image, just the binary + SQLite libs
FROM alpine:3.19
RUN apk add --no-cache ca-certificates sqlite-libs

WORKDIR /app
COPY --from=builder /app/approval-service .

# SQLite database lives here — mount a persistent volume to this path in prod
RUN mkdir -p /data

EXPOSE 8000
ENTRYPOINT ["/app/approval-service"]
