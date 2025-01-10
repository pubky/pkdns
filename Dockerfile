FROM alpine:3.20

COPY ./target/x86_64-unknown-linux-musl/release/pkdns /usr/local/bin
COPY ./target/x86_64-unknown-linux-musl/release/pkdns-cli /usr/local/bin

EXPOSE 53

CMD ["pkdns"]