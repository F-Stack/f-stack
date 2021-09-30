# # Derived from FreeBSD src/share/mk/bsd.prog.mk
#

ifdef DEBUG_FLAGS
CFLAGS+=${DEBUG_FLAGS}
CXXFLAGS+=${DEBUG_FLAGS}
endif

ifdef NO_SHARED
ifneq (${NO_SHARED},no)
ifneq (${NO_SHARED},NO)
LDFLAGS+= -static
endif
endif
endif

ifdef PROG_CXX
PROG=   ${PROG_CXX}
endif

ifndef PROG
$(error  PROG or PROG_CXX must be defined.)
endif

ifndef TOPDIR
$(error TOPDIR must be defined.)
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found, maybe you shuld export environment variable `PKG_CONFIG_PATH`")
endif

ifndef SRCS
ifdef PROG_CXX
SRCS=   ${PROG}.cc
else
SRCS=   ${PROG}.c
endif
endif

PROGDIR= ${TOPDIR}/tools/sbin

HEADERS+= $(filter %.h,${SRCS})
OBJS+= $(patsubst %.c,%.o, $(filter %.c,${SRCS}))
OBJS+= $(patsubst %.cc,%.o, $(filter %.cc,${SRCS}))

PKGCONF ?= pkg-config

FF_PROG_CFLAGS:= -g -Wall -Werror -DFSTACK -std=gnu99 $(shell $(PKGCONF) --cflags libdpdk)
FF_PROG_CFLAGS+= -I${TOPDIR}/lib -I${TOPDIR}/tools/compat
FF_PROG_CFLAGS+= -include${TOPDIR}/tools/compat/compat.h
FF_PROG_CFLAGS+= -I${TOPDIR}/tools/compat/include -D__BSD_VISIBLE
FF_PROG_CFLAGS+= -I${TOPDIR}/tools/libxo

FF_PROG_LIBS:= -L${TOPDIR}/tools/compat -Wl,--whole-archive,-lffcompat,--no-whole-archive
FF_PROG_LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
FF_PROG_LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lpthread -lnuma

CFLAGS+= -Wno-unused-but-set-variable -Wno-unused-variable
CFLAGS+= ${FF_PROG_CFLAGS}
CXXFLAGS+= ${FF_PROG_CFLAGS}

CFLAGS+= $(foreach n,${LIBADD},-I${TOPDIR}/tools/lib${n})
LIBS+= $(foreach n,${LIBADD},-L${TOPDIR}/tools/lib${n} -l${n})

LIBS+= ${FF_PROG_LIBS}

CLEANFILES+= ${PROGDIR}/${PROG} ${OBJS}

${PROG}: ${HEADERS} ${OBJS}
ifdef PROG_CXX
	${CXX} ${CXXFLAGS} ${LDFLAGS} -o ${PROGDIR}/${PROG} ${OBJS} ${LIBS}
else
	${CC} ${CFLAGS} ${LDFLAGS} -o ${PROGDIR}/${PROG} ${OBJS} ${LIBS}
endif

clean:
	@rm -f ${CLEANFILES}

all: ${PROG}
