
CFLAGS:=-std=gnu99 -Wall -Os
LDFLAGS:=-luserenv -lnetapi32
GCC:=gcc
WINDRES:=windres
STRIP:=strip

ISOLATE_CFLAGS?=-DISOLATE_VERSION=\"head\"

ifneq (${TRIPLET},)
GCC:=${TRIPLET}-${GCC}
GCC:=${TRIPLET}-${WINDRES}
STRIP:=${TRIPLET}-${STRIP}
endif

all:
	${GCC} ${CFLAGS} ${ISOLATE_CFLAGS} -c src/isolate.c
	#${WINDRES} --input isolate.rc --output isolate.res --output-format=coff
	#${GCC} -static isolate.o isolate.res -o isolate.exe ${LDFLAGS}
	${GCC} -static isolate.o -o isolate.exe ${LDFLAGS}
	${STRIP} isolate.exe
