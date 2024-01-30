#!/bin/bash

echo Build OSX amd64
cargo build --release --package=pkdns
echo Build Linux amd64
cargo build --release --package=pkdns --target=x86_64-unknown-linux-gnu
echo Build Windows amd64
cargo build --release --package=pkdns --target=x86_64-pc-windows-gnu

echo
echo Build packets
rm -rf target/github-release
cd target
mkdir github-release

echo Tar osx
mkdir github-release/pknames-osx-amd64
cp release/pkdns github-release/pknames-osx-amd64
cd github-release && tar -czf pknames-osx-amd64.tar.gz pknames-osx-amd64 && cd ..
rm -rf github-release/pknames-osx-amd64

echo Tar linux
mkdir github-release/pknames-linux-amd64
cp x86_64-unknown-linux-gnu/release/pkdns github-release/pknames-linux-amd64
cd github-release && tar -czf pknames-linux-amd64.tar.gz pknames-linux-amd64 && cd ..
rm -rf github-release/pknames-linux-amd64

echo Tar Windows
mkdir github-release/pknames-windows-amd64
cp x86_64-pc-windows-gnu/release/pkdns.exe github-release/pknames-windows-amd64
cd github-release && tar -czf pknames-windows-amd64.tar.gz pknames-windows-amd64 && cd ..
rm -rf github-release/pknames-windows-amd64

echo
cd ..
tree target/github-release