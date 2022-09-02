#
# Derived from FreeBSD src/sys/conf/kern.pre.mk
#

include ${TOPDIR}/mk/compiler.mk

MACHINE_CPUARCH:= $(shell uname -m)

# Convert Mac OS X name to FreeBSD one.
ifeq (${MACHINE_CPUARCH},x86_64)
MACHINE_CPUARCH=	amd64
endif

AWK?=		awk

ifdef DEBUG
_MINUS_O=	-O0
CTFFLAGS+=	-g3
else
ifeq (${MACHINE_CPUARCH},powerpc)
_MINUS_O=	-O	# gcc miscompiles some code at -O2
else
_MINUS_O=	-O2
endif
ifeq (${MACHINE_CPUARCH},amd64)
ifneq (${COMPILER_TYPE},clang)
COPTFLAGS?=-O2 -fno-strict-aliasing -frename-registers -pipe -Wno-maybe-uninitialized #-finline-functions
else
COPTFLAGS?=-O2 -pipe
endif
else
COPTFLAGS?=${_MINUS_O} -pipe
endif

ifneq ($(filter -O2 -O3 -Os,${COPTFLAGS}),) 
ifeq ($(filter -fno-strict-aliasing,${COPTFLAGS}),)
COPTFLAGS+= -fno-strict-aliasing
endif
endif
endif

ifndef NO_CPU_COPTFLAGS
COPTFLAGS+= ${_CPUCFLAGS}
endif
C_DIALECT= -std=c99
NOSTDINC= -nostdinc

INCLUDES= -undef -imacros ${IMACROS_FILE} ${NOSTDINC} ${INCLMAGIC} -I. -I$S -I. -I$C

CFLAGS=	${COPTFLAGS} ${C_DIALECT} ${DEBUG} ${CWARNFLAGS}
KERNEL_CFLAGS= -D__FreeBSD__ -D_KERNEL -DHAVE_KERNEL_OPTION_HEADERS -include opt_global.h -fno-builtin
ifneq (${COMPILER_TYPE},clang)
CFLAGS+= -fno-common -finline-limit=${INLINE_LIMIT}
ifneq (${MACHINE_CPUARCH},mips)
CFLAGS+= --param inline-unit-growth=100
CFLAGS+= --param large-function-growth=1000
else
# XXX Actually a gross hack just for Octeon because of the Simple Executive.
CFLAGS+= --param inline-unit-growth=10000
CFLAGS+= --param large-function-growth=100000
CFLAGS+= --param max-inline-insns-single=10000
endif
endif
WERROR?= -Werror -Wno-unused-variable

# XXX LOCORE means "don't declare C stuff" not "for locore.s".
ASM_CFLAGS= -x assembler-with-cpp -DLOCORE ${CFLAGS} ${KERNEL_CFLAGS}

ifeq (${COMPILER_TYPE},clang)
CLANG_NO_IAS= -no-integrated-as
endif

DEFINED_PROF=	${PROF}

# Put configuration-specific C flags last (except for ${PROF}) so that they
# can override the others.
CFLAGS+=	${CONF_CFLAGS}

# Optional linting. This can be overridden in /etc/make.conf.
LINTFLAGS=	${LINTOBJKERNFLAGS}

NORMAL_C= ${CC} -c ${CFLAGS} ${KERNEL_CFLAGS} ${INCLUDES} ${WERROR} ${PROF} $< -o $@
NORMAL_S= ${CC} -c ${ASM_CFLAGS} ${INCLUDES} ${WERROR} $<
PROFILE_C= ${CC} -c ${CFLAGS} ${KERNEL_CFLAGS} ${INCLUDES} ${WERROR} $<
NORMAL_C_NOWERROR= ${CC} -c ${CFLAGS} ${KERNEL_CFLAGS} ${INCLUDES} ${PROF} $<

NORMAL_M= ${AWK} -f $S/tools/makeobjops.awk $< -c ; \
	  ${CC} -c ${CFLAGS} ${KERNEL_CFLAGS} ${WERROR} ${PROF} $*.c

GEN_CFILES= $S/$M/$M/genassym.c ${MFILES:T:S/.m$/.c/}
SYSTEM_CFILES= config.c env.c hints.c vnode_if.c
SYSTEM_DEP= Makefile ${SYSTEM_OBJS}
SYSTEM_OBJS= locore.o ${MDOBJS} ${OBJS}
SYSTEM_OBJS+= ${SYSTEM_CFILES:.c=.o}
SYSTEM_OBJS+= hack.So
SYSTEM_LD= @${LD} -Bdynamic -T ${LDSCRIPT} ${LDFLAGS} --no-warn-mismatch \
	-warn-common -export-dynamic -dynamic-linker /red/herring \
	-o ${.TARGET} -X ${SYSTEM_OBJS} vers.o
SYSTEM_LD_TAIL= @${OBJCOPY} --strip-symbol gcc2_compiled. ${.TARGET} ; \
	${SIZE} ${.TARGET} ; chmod 755 ${.TARGET}
SYSTEM_DEP+= ${LDSCRIPT}


IMACROS_FILE=filtered_predefined_macros.h

IMACROS_FILTER+= __STDC__ __STDC_HOSTED__ __STDC_VERSION__
IMACROS_FILTER+= __APPLE__ __MACH__
IMACROS_FILTER+= __CYGWIN__ __CYGWIN32__
IMACROS_FILTER+= __FreeBSD__
IMACROS_FILTER+= __linux __linux__ __gnu__linux__ linux
IMACROS_FILTER+= _WIN32 _WIN64

SPACE= $(eval) $(eval)
IMACROS_FILTER_EXPR:= $(subst ${SPACE},|,$(strip ${IMACROS_FILTER}))

