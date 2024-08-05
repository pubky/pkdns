export VERSION=$(cd server && cargo get package.version)
mkdir -p target
rm -rf target/github-release
mkdir target/github-release

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
tar -czf $OSX64_DIR_NAME.tar.gz $OSX64_DIR_NAME
tar -czf $LINUX64_DIR_NAME.tar.gz $LINUX64_DIR_NAME
tar -czf $WINDOWS64_DIR_NAME.tar.gz $WINDOWS64_DIR_NAME



echo
tree target/github-release
pwd