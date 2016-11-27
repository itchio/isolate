
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

OBJECTS := strings.o relay.o errors.o isolate.o isolate.res

.PHONY: clean

all: $(OBJECTS)
	${GCC} -static $(OBJECTS) -o isolate.exe ${LDFLAGS}
	${STRIP} isolate.exe

isolate.o: src/isolate.c
	${GCC} ${CFLAGS} ${ISOLATE_CFLAGS} -c src/isolate.c

strings.o: src/strings.c
	${GCC} ${CFLAGS} ${ISOLATE_CFLAGS} -c src/strings.c

errors.o: src/errors.c
	${GCC} ${CFLAGS} ${ISOLATE_CFLAGS} -c src/errors.c

relay.o: src/relay.c
	${GCC} ${CFLAGS} ${ISOLATE_CFLAGS} -c src/relay.c

isolate.res: resources/isolate.rc
	${WINDRES} resources/isolate.rc -O coff -o isolate.res

clean:
	rm -f $(OBJECTS) isolate.exe
