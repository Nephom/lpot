# Compiler
CC = gcc

# Flags and libraries
CFLAGS = -Wall -Wextra -O2

# Targets and source files
TARGETS = lpot
LPOT_SRC = lpot.c

# Default target
all: $(TARGETS)

# Build rules
lpot: $(LPOT_SRC)
	$(CC) $(CFLAGS) -o $@ $<

# Clean rule
clean:
	rm -f $(TARGETS) *.o

