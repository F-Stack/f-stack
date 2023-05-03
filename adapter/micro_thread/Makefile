
# 
# Tencent is pleased to support the open source community by making MSEC available.
# 
# Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.
# 
# Licensed under the GNU General Public License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. You may 
# obtain a copy of the License at
# 
#     https://opensource.org/licenses/GPL-2.0
# 
# Unless required by applicable law or agreed to in writing, software distributed under the 
# License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
# 


########MAKEFILE##########

ifeq ($(FF_PATH),)
    FF_PATH=/usr/local
    $(warning FF_PATH environment variable not defined, default FF_PATH=/usr/local)
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found, maybe you shuld export environment variable `PKG_CONFIG_PATH`")
endif

PKGCONF ?= pkg-config

DEBUG= -g
BINARY = libmt.a
FF_LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
FF_LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
FF_LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lpthread -lnuma

# Comment the following line if you are not using the gnu c compiler
#C_ARGS = -Wall -g -fPIC -D_DEBUG
C_ARGS = -Wall -g -fPIC -O0 -DMT_REAL_TIME 
#.SUFFIXES: .o .cpp

ifeq ($(ARCH),32)
	C_ARGS +=  -march=pentium4 -m32 -DSUS_LINUX -pthread
else
	C_ARGS +=  -m64 -DSUS_LINUX -pthread
endif
# You might have to change this if your c compiler is not cc
CC = g++

# You shouldn't need to make any more changes below this line.
INCCOMM=-I./valgrind -I$(FF_PATH)/lib

#.c.o:
#	$(CC) -c $*.c

all:	$(BINARY) 

### shell color config
RED = \\e[1m\\e[31m
DARKRED = \\e[31m
GREEN = \\e[1m\\e[32m
DARKGREEN = \\e[32m
BLUE = \\e[1m\\e[34m
DARKBLUE = \\e[34m
YELLOW = \\e[1m\\e[33m
DARKYELLOW = \\e[33m
MAGENTA = \\e[1m\\e[35m
DARKMAGENTA = \\e[35m
CYAN = \\e[1m\\e[36m
DARKCYAN = \\e[36m
RESET = \\e[m
CRESET =  ;echo -ne \\e[m; test -s $@

%.o: %.cpp
	@echo -e Compiling $(GREEN)$<$(RESET) ...$(RED)
	@$(CC) $(C_ARGS) -c -o $@ $< $(INCCOMM) $(CRESET)

%.o: %.c
	@echo -e Compiling $(GREEN)$<$(RESET) ...$(RED)
	@$(CC) $(C_ARGS) -c -o $@ $< $(INCCOMM) $(CRESET)  

%.o: %.S
	@echo -e Compiling $(GREEN)$<$(RESET) ...$(RED)
	@$(CC) $(C_ARGS) -c -o $@ $< $(INCCOMM) $(CRESET) 

clean:
	@rm -f $(BINARY) *.a *.o echo  


LIB_OBJ = micro_thread.o kqueue_proxy.o arch_ctx.o mt_session.o mt_notify.o mt_action.o mt_mbuf_pool.o mt_api.o\
	 mt_connection.o mt_concurrent.o mt_sys_hook.o ff_hook.o heap_timer.o  mt_cache.o  mt_net.o

libmt.a: $(LIB_OBJ)
	@echo -e  Linking $(CYAN)$@$(RESET) ...$(RED)
	@-rm -f $@ 
	@ar crs  $@  $^ $(CRESET)
	@chmod +x $@ 

echo: echo.o libmt.a
	@echo -e Compile $(CYAN)$@$(RESET) ...$(RED)
	@$(CC) -O -gdwarf-2 -o $@ $^ -lstdc++ -ldl -lm $(FF_LIBS) $(CRESET)
