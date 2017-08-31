# $FreeBSD$

PACKAGE=lib${LIB}
SHLIBDIR?=      /lib

TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/tools/opts.mk

LIBXOSRC=	./libxo
VPATH+= ${LIBXOSRC}

LIB=	xo
SHLIB_MAJOR=0

#SRCS=	${LIBXOSRC}/libxo.c ${LIBXOSRC}/xo_encoder.c ${LIBXOSRC}/xo_syslog.c
SRCS=	libxo.c xo_encoder.c xo_syslog.c

CFLAGS+= -I${LIBXOSRC} -I${CURDIR}
#CFLAGS+= -DXO_ENCODERDIR=\"/usr/lib/libxo/encoder\"
CFLAGS+= -DXO_ENCODERDIR=\"\"

CFLAGS+= -I${TOPDIR}/tools/libutil

include ${TOPDIR}/tools/lib.mk

