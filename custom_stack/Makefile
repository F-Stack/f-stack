APP = dpdklib

SRCDIR = src
INCDIR = include
OBJDIR = build

SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

RTE_SDK = /root/task10/dpdk-22.07
RTE_TARGET = x86_64-native-linuxapp-gcc
DPDK_INC = $(RTE_SDK)/$(RTE_TARGET)/include
DPDK_LIB = $(RTE_SDK)/$(RTE_TARGET)/lib

CC = gcc
CFLAGS = -O3 -g -Wall -I$(INCDIR) -I$(DPDK_INC)
LDFLAGS = -L$(DPDK_LIB) -Wl,-rpath,$(DPDK_LIB) -ldpdk

all: $(APP)

$(APP): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(APP)

.PHONY: all clean