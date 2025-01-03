#!/bin/bash

export VERSION=$(cd server && cargo get package.version)
cross build --release --package=pkdns --target=x86_64-unknown-linux-musl
cross build --release --package=pkdns-cli --target=x86_64-unknown-linux-musl
docker build --platform linux/amd64 -t synonymsoft/pkdns:$VERSION -t synonymsoft/pkdns:latest .


echo
read -p "Do you want to publish synonymsoft/pkdns:$VERSION to Docker Hub? [yN] " response
echo
case "$response" in
    [yY]|[yY][eE][sS])  # Accepts y, Y, yes, YES

        docker push synonymsoft/pkdns:$VERSION
        ;;
    *)
        echo "Dont publish synonymsoft/pkdns:$VERSION."
        exit 1
        ;;
esac

echo
read -p "Do you want to publish synonymsoft/pkdns:latest to Docker Hub? [yN] " response
echo
case "$response" in
    [yY]|[yY][eE][sS])  # Accepts y, Y, yes, YES

        docker push synonymsoft/pkdns:latest
        ;;
    *)
        echo "Dont publish synonymsoft/pkdns:latest."
        exit 1
        ;;
esac
