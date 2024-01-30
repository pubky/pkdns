#!/bin/bash

VERSION=$(cargo get package.version)
echo pkdns $VERSION
echo Build OSX amd64
cargo build --release --package=pkdns
echo
echo Build Linux amd64
cargo build --release --package=pkdns --target=x86_64-unknown-linux-gnu
echo
echo Build Windows amd64
cargo build --release --package=pkdns --target=x86_64-pc-windows-gnu


echo
echo Build packets
rm -rf target/github-release
cd target
mkdir github-release

echo Tar osx
DIR_NAME="pkdns-osx-amd64-v$VERSION"
mkdir github-release/$DIR_NAME
cp release/pkdns github-release/$DIR_NAME
cd github-release && tar -czf $DIR_NAME.tar.gz $DIR_NAME && cd ..
rm -rf github-release/$DIR_NAME

echo Tar linux
DIR_NAME="pkdns-linux-amd64-v$VERSION"
mkdir github-release/$DIR_NAME
cp x86_64-unknown-linux-gnu/release/pkdns github-release/$DIR_NAME
cd github-release && tar -czf $DIR_NAME.tar.gz $DIR_NAME && cd ..
rm -rf github-release/$DIR_NAME

echo Tar Windows
DIR_NAME="pkdns-windows-amd64-v$VERSION"
mkdir github-release/$DIR_NAME
cp x86_64-pc-windows-gnu/release/pkdns.exe github-release/$DIR_NAME
cd github-release && tar -czf $DIR_NAME.tar.gz $DIR_NAME && cd ..
rm -rf github-release/$DIR_NAME

echo
cd ..
tree target/github-release
cd target/github-release
pwd