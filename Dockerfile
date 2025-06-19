# ========================
# Build Image
# ========================
FROM rust:1.86.0-alpine3.20 AS builder

# Build platform argument (x86_64 or aarch64) (default: x86_64)
ARG TARGETARCH=x86_64
RUN echo "TARGETARCH: $TARGETARCH"

# Install build dependencies, including static OpenSSL libraries
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    build-base \
    curl

# Set environment variables for static linking with OpenSSL
ENV OPENSSL_STATIC=yes
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include

# Add the MUSL target for static linking
RUN rustup target add $TARGETARCH-unknown-linux-musl

# Set the working directory
WORKDIR /usr/src/app

# Copy over Cargo.toml and Cargo.lock for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy over all the source code
COPY . .

# Build the project in release mode for the MUSL target
RUN cargo build --release --target $TARGETARCH-unknown-linux-musl

# Strip the binary to reduce size
RUN strip target/$TARGETARCH-unknown-linux-musl/release/pkdns
RUN strip target/$TARGETARCH-unknown-linux-musl/release/pkdns-cli

# ========================
# Runtime Image
# ========================
FROM alpine:3.20

ARG TARGETARCH=x86_64

# Install runtime dependencies (only ca-certificates)
RUN apk add --no-cache ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/$TARGETARCH-unknown-linux-musl/release/pkdns /usr/local/bin
COPY --from=builder /usr/src/app/target/$TARGETARCH-unknown-linux-musl/release/pkdns-cli /usr/local/bin

# Set the working directory
WORKDIR /usr/local/bin

# Expose the DNS port
EXPOSE 53

# Set the default command to run the binary
CMD ["pkdns"]
