# ========================
# Build Image
# ========================
FROM rust:1.86.0-alpine3.20 AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    libc-dev

# Set the working directory
WORKDIR /usr/src/app

# Copy over Cargo.toml and Cargo.lock for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy over all the source code
COPY . .

# Build the project in release mode
RUN cargo build --release

# ========================
# Runtime Image
# ========================
FROM alpine:3.20

ARG TARGETARCH=x86_64

# Install runtime dependencies (only ca-certificates)
RUN apk add --no-cache ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/pkdns /usr/local/bin
COPY --from=builder /usr/src/app/target/release/pkdns-cli /usr/local/bin

# Expose the DNS port
EXPOSE 53

# Set the default command to run the binary
CMD ["pkdns"]
