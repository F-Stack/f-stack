APP = SRCS = IP_MAC_Parser.c
SRCS = IP_MAC_Parser.c

DPDK_PATH = /data/f-stack/dpdk
PKGCONF = pkg-config
CFLAGS += -O3 -Wall -Wextra $(shell pkg-config --cflags libdpdk)
LDFLAGS += $(shell pkg-config --libs libdpdk)

all:
	$(CC) $(CFLAGS) $(SRCS) -o build/$(APP) $(LDFLAGS)

clean:
	rm -f build/$(APP)


