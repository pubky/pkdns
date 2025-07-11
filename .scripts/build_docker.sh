#!/bin/bash

VERSION=$(cargo pkgid -p pkdns | cut -d@ -f2)
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
