#!/bin/bash

export VERSION=$(cd server && cargo get package.version)
cross build --release --package=pkdns --target=x86_64-unknown-linux-musl
cross build --release --package=pkdns-cli --target=x86_64-unknown-linux-musl
docker build --platform linux/amd64 -t sebu/pkdns:$VERSION -t sebu/pkdns:latest .


echo
echo Built sebu/pkdns:$VERSION, sebu/pkdns:latest
read -p "Do you want to publish the image to Docker Hub? [yN] " response
echo
case "$response" in
    [yY]|[yY][eE][sS])  # Accepts y, Y, yes, YES

        docker push sebu/pkdns:$VERSION
        docker push sebu/pkdns:latest
        ;;
    *)
        echo "Dont publish."
        exit 1
        ;;
esac
