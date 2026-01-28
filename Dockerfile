# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o sts ./cmd/sts

# Runtime stage
FROM gcr.io/distroless/static-debian13:nonroot

WORKDIR /home/nonroot/

# Copy the binary from builder
COPY --from=builder /app/sts .

# Create keys directory (done in builder stage since distroless has no shell)
# Keys will be mounted as a volume or created at runtime

# Expose ports
EXPOSE 8080 9090

# Run the application
CMD ["./sts", "serve"]
