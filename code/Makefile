CC=gcc
CFLAGS=-Wall

BIN_DIR=../bin

.PHONY: all clean

all: server client

vpnserver.o: vpnserver.c
	$(CC) $(CFLAGS) -c $< -o $@

vpnclient.o: vpnclient.c
	$(CC) $(CFLAGS) -c $< -o $@

lib.o: lib.c
	$(CC) $(CFLAGS) -c $< -o $@

server: vpnserver.o lib.o
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@ -lssl -lcrypto -lcrypt
	rm -f vpnserver.o lib.o

client: vpnclient.o
	$(CC) $(CFLAGS) $< -o $(BIN_DIR)/$@ -lssl -lcrypto
	rm -f vpnclient.o

clean:
	rm -f $(BIN_DIR)/server $(BIN_DIR)/client
