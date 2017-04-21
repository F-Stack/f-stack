#
# Derived from FreeBSD src/sys/conf/kern.mk
#
#
# Warning flags for compiling the kernel and components of the kernel:
#

CWARNFLAGS?=	-Wall -Wnested-externs -Wstrict-prototypes \
		-Wmissing-prototypes -Wpointer-arith -Wno-inline -Wcast-qual \
		-Wno-pointer-sign -Wmissing-include-dirs -fdiagnostics-show-option \
		${CWARNEXTRA}
#
# The following flags are next up for working on:
#	-Wextra

# Disable a few warnings for clang, since there are several places in the
# kernel where fixing them is more trouble than it is worth, or where there is
# a false positive.
ifeq (${COMPILER_TYPE},clang)
NO_WCONSTANT_CONVERSION=	-Wno-constant-conversion
NO_WARRAY_BOUNDS=		-Wno-array-bounds
NO_WSHIFT_COUNT_NEGATIVE=	-Wno-shift-count-negative
NO_WSHIFT_COUNT_OVERFLOW=	-Wno-shift-count-overflow
NO_WUNUSED_VALUE=		-Wno-unused-value
NO_WSELF_ASSIGN=		-Wno-self-assign
NO_WFORMAT_SECURITY=		-Wno-format-security
NO_WUNNEEDED_INTERNAL_DECL=	-Wno-unneeded-internal-declaration
NO_WSOMETIMES_UNINITIALIZED=	-Wno-error-sometimes-uninitialized
# Several other warnings which might be useful in some cases, but not severe
# enough to error out the whole kernel build.  Display them anyway, so there is
# some incentive to fix them eventually.
CWARNEXTRA?=	-Wno-error-tautological-compare -Wno-error-empty-body \
		-Wno-error-parentheses-equality -Wno-incompatible-library-redeclaration \
		-Wno-builtin-requires-header -Wno-error-shift-negative-value -Wno-unknown-warning-option
endif

ifeq (${COMPILER_TYPE},gcc)
CWARNEXTRA?=	-Wno-unused-but-set-variable
endif

#
# On i386, do not align the stack to 16-byte boundaries.  Otherwise GCC 2.95
# and above adds code to the entry and exit point of every function to align the
# stack to 16-byte boundaries -- thus wasting approximately 12 bytes of stack
# per function call.  While the 16-byte alignment may benefit micro benchmarks,
# it is probably an overall loss as it makes the code bigger (less efficient
# use of code cache tag lines) and uses more stack (less efficient use of data
# cache tag lines).
#
ifeq (${MACHINE_CPUARCH},i386)
ifneq (${COMPILER_TYPE},clang)
CFLAGS+=	-mno-align-long-strings -mpreferred-stack-boundary=2
else
CFLAGS+=	
endif
CFLAGS+=	
INLINE_LIMIT?=	8000
endif

ifeq (${MACHINE_CPUARCH},arm)
INLINE_LIMIT?=	8000
endif

#
# For IA-64, we use r13 for the kernel globals pointer and we only use
# a very small subset of float registers for integer divides.
#
ifeq (${MACHINE_CPUARCH},ia64)
CFLAGS+=	-ffixed-r13 -mfixed-range=f32-f127 -fpic #-mno-sdata
INLINE_LIMIT?=	15000
endif

#
# For sparc64 we want the medany code model so modules may be located
# anywhere in the 64-bit address space.
#
ifeq (${MACHINE_CPUARCH},sparc64)
CFLAGS+=	-mcmodel=medany
INLINE_LIMIT?=	15000
endif

ifeq (${MACHINE_CPUARCH},amd64)
ifeq (${COMPILER_TYPE},clang)
CFLAGS+=	
endif
CFLAGS+=	
INLINE_LIMIT?=	8000
endif

ifeq (${MACHINE_CPUARCH},powerpc)
CFLAGS+=	
INLINE_LIMIT?=	15000
endif

ifeq (${MACHINE_ARCH},powerpc64)
CFLAGS+=	
endif

ifeq (${MACHINE_CPUARCH},mips)
CFLAGS+=	
INLINE_LIMIT?=	8000
endif

#
# GCC SSP support
#
ifneq (${MK_SSP},no)
ifneq (${MACHINE_CPUARCH},ia64)
ifneq (${MACHINE_CPUARCH},arm)
ifneq (${MACHINE_CPUARCH},mips)
CFLAGS+=	-fstack-protector
endif
endif
endif
endif


${IMACROS_FILE}: ${TOPDIR}/mk/kern.pre.mk
	echo | ${CC} -E -dM - | grep -v -E '${IMACROS_FILTER_EXPR}' > ${IMACROS_FILE}
