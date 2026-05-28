# Display exported symbols:
#  nm -D pkcs11-mock.so | grep ' T '

SRC_DIR=../../src

CC= gcc
ARCH_FLAGS= -m32
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -Werror -O2 -I$(SRC_DIR)
LIBNAME=pkcs11-mock-x86.so

OBJS= pkcs11-mock.o ipc_client.o ipc_json.o

all: $(OBJS)
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) \
	-Wl,-soname,$(LIBNAME) \
	-Wl,--version-script,pkcs11-mock.version \
	$(OBJS) -lcrypto
	strip --strip-all $(LIBNAME)

pkcs11-mock.o: $(SRC_DIR)/pkcs11-mock.c $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/pkcs11-mock.c

ipc_client.o: $(SRC_DIR)/ipc_client.c $(SRC_DIR)/ipc_client.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/ipc_client.c

ipc_json.o: $(SRC_DIR)/ipc_json.c $(SRC_DIR)/ipc_json.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/ipc_json.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.so
