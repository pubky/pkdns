FROM alpine:3.20

COPY ./target/aarch64-unknown-linux-musl/release/pkdns /usr/local/bin
COPY ./target/aarch64-unknown-linux-musl/release/pkdns-cli /usr/local/bin

# Expose regular UDP DNS and DNS-over-HTTP port
EXPOSE 53 3000

RUN ls -al ~

CMD ["pkdns"]