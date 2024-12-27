RTE_SDK ?= /data/f-stack/dpdk
RTE_TARGET ?= $(RTE_SDK)/build

CC = gcc
CFLAGS = -O3 -g -Wall -Wextra -Werror -I$(BUILD_DIR)/include
LDFLAGS = -L$(BUILD_DIR)/lib -Wl,-rpath=$(BUILD_DIR)/lib
LDLIBS = -ldpdk

TARGET = IP_MAC_Parser
SRCS = IP_MAC_Parser.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
