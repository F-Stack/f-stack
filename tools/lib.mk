#
# Derived from FreeBSD src/share/mk/bsd.lib.mk
#

ifdef DEBUG_FLAGS
CFLAGS+=${DEBUG_FLAGS}
CXXFLAGS+=${DEBUG_FLAGS}
endif

ifndef LIB
$(error  LIB must be defined.)
endif

ifndef SRCS
SRCS=	${LIB}.c
endif

ifndef TOPDIR
$(error TOPDIR must be defined.)
endif

FF_LIB_CFLAGS:= -g -Wall -Werror -DFSTACK -std=gnu99
FF_LIB_CFLAGS+= -I${TOPDIR}/lib -I${TOPDIR}/tools/compat
FF_LIB_CFLAGS+= -include${TOPDIR}/tools/compat/compat.h
FF_LIB_CFLAGS+= -I${TOPDIR}/tools/compat/include -D__BSD_VISIBLE

CFLAGS+= ${FF_LIB_CFLAGS}

OBJS+= $(patsubst %.cc,%.o,$(patsubst %.c,%.o,${SRCS}))

LIBBASENAME=lib${LIB}

CLEANFILES+= ${LIBBASENAME}.a ${OBJS}

${LIBBASENAME}.a: ${OBJS}
	rm -f $@
	ar -cqs $@ ${OBJS}

${OBJS}: %.o: %.c
	${CC} -c ${CFLAGS} $<

clean:
	@rm -f ${CLEANFILES}

all: ${LIBBASENAME}.a

