# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -fwrapv -gdwarf-4 -DSUPERCOP -O3 -march=native -fPIC
LDFLAGS = -shared -o libladybug.so

# Source files
SRC = encrypt.c
OBJ = encrypt.o decrypt.o

# Default target
all: encrypt decrypt shared

# Compile object files
encrypt.o: $(SRC)
	$(CC) $(CFLAGS) -c -o $@ $(SRC) 

decrypt.o: $(SRC)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)

# Build standalone executables
encrypt: encrypt.o
	$(CC) -o encrypt encrypt.o -lcrypto

decrypt: decrypt.o
	$(CC) -o decrypt decrypt.o -lcrypto

# Build shared library
shared: encrypt.o
	$(CC) $(LDFLAGS) encrypt.o -lc

clean:
	rm -f encrypt.o decrypt.o encrypt decrypt libladybug.so 

.PHONY: all clean
