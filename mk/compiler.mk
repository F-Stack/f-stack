#
# Derived from FreeBSD src/share/mk/bsd.compiler.mk
#

ifndef COMPILER_TYPE
  ifeq ($(patsubst gcc%,gcc,$(notdir ${CC})),gcc)
COMPILER_TYPE:=	gcc  
  else ifeq ($(notdir ${CC}), clang)
COMPILER_TYPE:=	clang
  else
_COMPILER_VERSION:= $(shell ${CC} --version)
   ifneq ($(filter gcc (GCC),${_COMPILER_VERSION}),)
COMPILER_TYPE:=	gcc
   else ifneq ($(filter Free Software Foundation,${_COMPILER_VERSION}),)
COMPILER_TYPE:=	gcc
   else ifneq ($(findstring clang,${_COMPILER_VERSION}),)
COMPILER_TYPE:=	clang
   else
$(error  Unable to determine compiler type for ${CC}.  Consider setting COMPILER_TYPE.)
   endif
# XXX
#undefine _COMPILER_VERSION
  endif
endif

ifeq (${COMPILER_TYPE}, clang)
COMPILER_FEATURES=	c++11
else
COMPILER_FEATURES=
endif


