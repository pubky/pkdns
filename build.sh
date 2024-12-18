export VERSION=$(cd server && cargo get package.version)
mkdir -p target
rm -rf target/github-release
mkdir target/github-release


export OSX_ARM64_DIR_NAME="pkdns-osx-arm64-v$VERSION"
mkdir -p target/github-release/$OSX_ARM64_DIR_NAME
export OSX64_DIR_NAME="pkdns-osx-amd64-v$VERSION"
mkdir -p target/github-release/$OSX64_DIR_NAME
export LINUX64_DIR_NAME="pkdns-linux-amd64-v$VERSION"
mkdir -p target/github-release/$LINUX64_DIR_NAME
export WINDOWS64_DIR_NAME="pkdns-windows-amd64-v$VERSION"
mkdir -p target/github-release/$WINDOWS64_DIR_NAME

./server/build.sh
./cli/build.sh




echo Tar files
cd target/github-release
tar -czf $OSX_ARM64_DIR_NAME.tar.gz $OSX_ARM64_DIR_NAME
rm -rf $OSX_ARM64_DIR_NAME
tar -czf $OSX64_DIR_NAME.tar.gz $OSX64_DIR_NAME
rm -rf $OSX64_DIR_NAME

tar -czf $LINUX_ARM64_DIR_NAME.tar.gz $LINUX_ARM64_DIR_NAME
rm -rf $LINUX_ARM64_DIR_NAME
tar -czf $LINUX64_DIR_NAME.tar.gz $LINUX64_DIR_NAME
rm -rf $LINUX64_DIR_NAME

tar -czf $WINDOWS64_DIR_NAME.tar.gz $WINDOWS64_DIR_NAME
rm -rf $WINDOWS64_DIR_NAME


echo
tree target/github-release
pwd