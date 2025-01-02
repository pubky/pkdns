export VERSION=$(cd server && cargo get package.version)
mkdir -p target
rm -rf target/github-release
mkdir target/github-release

builds=(
"aarch64-apple-darwin,osx-arm64" 
"x86_64-apple-darwin,osx-amd64"
"x86_64-unknown-linux-musl,linux-amd64"
"aarch64-unknown-linux-musl,linux-arm64"
"x86_64-pc-windows-gnu,windows-amd64"
"armv7-unknown-linux-musleabihf,linux-armv7hf"
"arm-unknown-linux-musleabihf,linux-armhf"
)

artifcats=("pkdns-cli" "pkdns")

for BUILD in "${builds[@]}"; do
    # Split tuple by comma
    IFS=',' read -r TARGET LABEL <<< "$BUILD"

    echo "Build $LABEL with $TARGET"
    FOLDER="pkdns-$LABEL-v$VERSION"
    DICT="target/github-release/$FOLDER"
    mkdir -p $DICT

    for ARTIFACT in "${artifcats[@]}"; do
        echo - $ARTIFACT
        cross build --release --package=$ARTIFACT --target=$TARGET
        if [[ $TARGET == *"windows"* ]]; then
            cp target/$TARGET/release/$ARTIFACT.exe $DICT
        else
            cp target/$TARGET/release/$ARTIFACT $DICT
        fi

    done;

    cd target/github-release
    tar -czf $FOLDER.tar.gz $FOLDER
    rm -rf $FOLDER
    cd .. && cd ..
    echo
done;


tree target/github-release
pwd