INCLUDE = -I./compat
CFLAGS += -fPIC -g3 $(INCLUDE) -O0

OPENSSL = -L../station/openssl/build/lib -Wl,-Bstatic -lssl -Wl,-Bstatic -lcrypto -lpthread
LIBS = -lgmp -ldl
ALL_LIBS = $(OPENSSL) -Wl,-Bdynamic $(LIBS)

forge: forge.c
	$(CC) -o $@ $(CFLAGS) $@.c $(ALL_LIBS)

run: forge
	./forge

all: clean forge

debug: forge
	gdb ./forge --directory=$(realpath ../station/openssl/)
	rm forge
