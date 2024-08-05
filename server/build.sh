#!/bin/bash

echo pkdns $VERSION
echo Build OSX amd64
cargo build --release --package=pkdns
cp target/release/pkdns target/github-release/$OSX64_DIR_NAME
echo

echo Build Linux amd64
cargo build --release --package=pkdns --target=x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/release/pkdns target/github-release/$LINUX64_DIR_NAME
echo

echo Build Windows amd64
cargo build --release --package=pkdns --target=x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/pkdns.exe target/github-release/$WINDOWS64_DIR_NAME

