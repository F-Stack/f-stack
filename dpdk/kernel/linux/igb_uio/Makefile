KSRC ?= /lib/modules/`uname -r`/build

all:
	make -C $(KSRC)/ M=$(PWD)

clean:
	make -C $(KSRC)/ M=$(PWD) clean
