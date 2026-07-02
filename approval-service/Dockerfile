# Build stage — pure Go, no CGO needed (MongoDB driver is pure Go)
FROM golang:1.23.10-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o approval-service .

# Runtime stage — minimal image, just the binary
FROM alpine:3.19
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/approval-service .

EXPOSE 8000
ENTRYPOINT ["/app/approval-service"]
