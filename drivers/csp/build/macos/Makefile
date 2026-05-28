# Display exported symbols:
#  nm pkcs11-mock.dylib | grep ' T '

SRC_DIR=../../src

CC= clang
ARCH_FLAGS= -target arm64-apple-macos11
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -Werror -O2 -I$(SRC_DIR)
LIBNAME=pkcs11-mock-x86.dylib

OBJS= pkcs11-mock.o ipc_client.o ipc_json.o

all: $(OBJS)
	$(CC) $(ARCH_FLAGS) -dynamiclib -o $(LIBNAME) \
	-Wl,-exported_symbols_list,pkcs11-mock.symbols \
	$(OBJS) -lcrypto
	strip -x $(LIBNAME)

pkcs11-mock.o: $(SRC_DIR)/pkcs11-mock.c $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/pkcs11-mock.c

ipc_client.o: $(SRC_DIR)/ipc_client.c $(SRC_DIR)/ipc_client.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/ipc_client.c

ipc_json.o: $(SRC_DIR)/ipc_json.c $(SRC_DIR)/ipc_json.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/ipc_json.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.dylib
