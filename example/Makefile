LIBS = $(shell pkg-config --define-variable=TOPDIR=${CURDIR}/.. --libs f-stack.pc)
TARGET="helloworld"
all:
	cc -O -gdwarf-2  -I../lib -o ${TARGET} main.c ${LIBS}

.PHONY: clean
clean:
	rm -f *.o ${TARGET}