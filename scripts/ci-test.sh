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
  export ISOLATE_VERSIOn=$CI_BUILD_TAG
fi
export ISOLATE_CFLAGS="-DISOLATE_VERSION=\\\"$ISOLATE_VERSION\\\""

make
file isolate.exe
