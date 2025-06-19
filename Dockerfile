# ========================
# Build Image
# ========================
FROM rust:1.86.0-alpine3.20 AS builder

# Install build dependencies, including static OpenSSL libraries
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    build-base \
    curl

# Add the MUSL target for static linking
RUN rustup target add x86_64-unknown-linux-musl

# Set the working directory
WORKDIR /usr/src/app

# Copy over Cargo.toml and Cargo.lock for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy over all the source code
COPY . .

# Build the project in release mode for the MUSL target
RUN cargo build --release --target x86_64-unknown-linux-musl

# ========================
# Runtime Image
# ========================
FROM alpine:3.20

ARG TARGETARCH=x86_64

# Install runtime dependencies (only ca-certificates)
RUN apk add --no-cache ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/pkdns /usr/local/bin
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/pkdns-cli /usr/local/bin

# Expose the DNS port
EXPOSE 53

# Set the default command to run the binary
CMD ["pkdns"]
