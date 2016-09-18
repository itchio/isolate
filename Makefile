
CFLAGS:=-std=gnu99 -Wall -Os
LDFLAGS:=-luserenv -lnetapi32
GCC:=gcc
STRIP:=strip

ISOLATE_CFLAGS?=-DISOLATE_VERSION=\"head\"

ifneq (${TRIPLET},)
GCC:=${TRIPLET}-${GCC}
STRIP:=${TRIPLET}-${STRIP}
endif

all:
	${GCC} ${CFLAGS} ${ISOLATE_CFLAGS} -static src/isolate.c -o isolate.exe ${LDFLAGS}
	${STRIP} isolate.exe
