# Makefile - Chaskey reference implementation
#
# Targets:
#   make          - build static library and test binary
#   make test     - build and run the test suite
#   make clean    - remove all build artefacts

CC      ?= cc
CSTD    ?= -std=c99
WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wcast-align -Wcast-qual \
           -Wpointer-arith -Wundef -Wwrite-strings -Wconversion
OPT     ?= -O2
CFLAGS  ?= $(CSTD) $(WARN) $(OPT) -fstack-protector-strong -D_FORTIFY_SOURCE=2
INCLUDE := -Iinclude

LIB_SRC := src/chaskey.c
LIB_OBJ := $(LIB_SRC:.c=.o)
LIB     := libchaskey.a

TEST_SRC := test/test_chaskey.c
TEST_BIN := test_chaskey

.PHONY: all test clean

all: $(LIB) $(TEST_BIN)

$(LIB): $(LIB_OBJ)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(TEST_BIN): $(TEST_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDE) $< -L. -lchaskey -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	$(RM) $(LIB_OBJ) $(LIB) $(TEST_BIN)
