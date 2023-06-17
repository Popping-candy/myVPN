CC=gcc
CFLAGS=-Wall

BIN_DIR=../bin

.PHONY: all clean

all: server client

vpnserver.o: vpnserver.c
	$(CC) $(CFLAGS) -c $< -o $@

vpnclient.o: vpnclient.c
	$(CC) $(CFLAGS) -c $< -o $@

tlsserver.o: tlsserver.c
	$(CC) $(CFLAGS) -c $< -o $@

tlsclient.o: tlsclient.c
	$(CC) $(CFLAGS) -c $< -o $@

server: vpnserver.o tlsserver.o
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@ -lssl -lcrypto -lcrypt
	rm -f vpnserver.o tlsserver.o

client: vpnclient.o tlsclient.o
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@ -lssl -lcrypto
	rm -f vpnclient.o tlsclient.o

clean:
	rm -f $(BIN_DIR)/server $(BIN_DIR)/client
