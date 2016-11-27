#!/bin/sh -xe

if [ "$CI_ARCH" = "amd64" ]; then
  export PATH=/mingw64/bin:$PATH
else
  export PATH=/mingw32/bin:$PATH
fi

7za | head -2
gcc -v
cppcheck --error-exitcode=1 src

export ISOLATE_VERSION=head
if [ -n "$CI_BUILD_TAG" ]; then
  export ISOLATE_VERSION=$CI_BUILD_TAG
fi
export CI_VERSION=$CI_BUILD_REF_NAME
export ISOLATE_CFLAGS="-DISOLATE_VERSION=\\\"$ISOLATE_VERSION\\\""

make
file isolate.exe

export CI_OS="windows"

# sign (win)
if [ "$CI_OS" = "windows" ]; then
  scripts/ci-sign.sh "isolate.exe"
fi

# verify
7za a isolate.7z isolate.exe

# set up a file hierarchy that ibrew can consume, ie:
#
# - dl.itch.ovh
#   - isolate
#     - windows-amd64
#       - LATEST
#       - v0.3.0
#         - isolate.7z
#         - isolate.exe
#         - SHA1SUMS

BINARIES_DIR="binaries/$CI_OS-$CI_ARCH"
mkdir -p $BINARIES_DIR/$CI_VERSION
mv isolate.7z $BINARIES_DIR/$CI_VERSION
mv isolate.exe $BINARIES_DIR/$CI_VERSION

(cd $BINARIES_DIR/$CI_VERSION && sha1sum * > SHA1SUMS && sha256sum * > SHA256SUMS)

if [ -n "$CI_BUILD_TAG" ]; then
  echo $CI_BUILD_TAG > $BINARIES_DIR/LATEST
fi
