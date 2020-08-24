INCLUDE = -I./compat -I./openssl/build/lib
CFLAGS += -fPIC -g3 $(INCLUDE) -O0

OPENSSL = -lssl -lcrypto
LIBS = -lpthread -lgmp -ldl
ALL_LIBS = -Wl,-Bstatic $(OPENSSL) -Wl,-Bdynamic $(LIBS)

run: forge
	./forge

forge: forge.c .openssl-built
	$(CC) -o $@ $(CFLAGS) $@.c $(ALL_LIBS)

debug: forge
	gdb ./forge --directory=./openssl -x gdb_init
	rm forge

clean:
	rm -f forge

build-openssl: .openssl-built

.openssl-built:
	pushd openssl && \
	sudo ./config no-asm --prefix=$(pwd)/build -g3 -O0 -fno-omit-frame-pointer -fno-inline-functions && \
	sudo make all && \
	sudo make install && \
	popd && \
	touch .openssl-built
