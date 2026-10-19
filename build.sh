#!/usr/bin/env bash
# Build HomehubUnlocker.apk with the Android toolchain (no Gradle needed).
# Run inside the dev shell:  nix develop -c ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

if [ -z "${ANDROID_HOME:-}" ]; then
  echo "ERROR: ANDROID_HOME is not set. Enter the dev shell first: nix develop -c ./build.sh" >&2
  exit 1
fi

SDK="$ANDROID_HOME"
BT="$SDK/build-tools/34.0.0"
PLATFORM="$SDK/platforms/android-34/android.jar"

if [ ! -f "$PLATFORM" ]; then
  echo "ERROR: android.jar not found at $PLATFORM" >&2
  exit 1
fi

rm -rf build
mkdir -p build/gen build/classes build/stubs build/dex

echo "== 1/6 aapt2: resources + R.java + base apk"
"$BT/aapt2" compile --dir res -o build/res.zip
"$BT/aapt2" link -o build/base.apk \
  -I "$PLATFORM" \
  --manifest AndroidManifest.xml \
  -A assets \
  --java build/gen \
  build/res.zip

echo "== 2/6 javac: compile-only stubs"
find stubs -name '*.java' > build/stub_sources.txt
javac --release 8 -nowarn -classpath "$PLATFORM" -d build/stubs @build/stub_sources.txt

echo "== 3/6 javac: module sources"
find src build/gen -name '*.java' > build/src_sources.txt
javac --release 8 -nowarn -classpath "$PLATFORM:build/stubs" -d build/classes @build/src_sources.txt

echo "== 4/6 d8: dex module classes"
find build/classes -name '*.class' -print0 | xargs -0 "$BT/d8" \
  --release \
  --lib "$PLATFORM" \
  --classpath build/stubs \
  --min-api 26 \
  --output build/dex

echo "== 5/6 assemble unsigned apk"
cp build/base.apk build/unsigned.apk
(cd build/dex && zip -q -X ../unsigned.apk classes.dex)

echo "== 6/6 zipalign + sign"
KEYSTORE=keystore.jks
if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair -keystore "$KEYSTORE" --alias homehubunlocker \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass homehubunlocker -keypass homehubunlocker \
    -dname "CN=HomehubUnlocker, OU=dev, O=homehub, C=JP"
fi
"$BT/zipalign" -f 4 build/unsigned.apk build/aligned.apk
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:homehubunlocker \
  --ks-key-alias homehubunlocker --out HomehubUnlocker.apk build/aligned.apk

echo
echo "OK: $PWD/HomehubUnlocker.apk"
