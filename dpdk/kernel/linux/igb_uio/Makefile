KSRC ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KSRC)/ M=$(CURDIR)

%:
	make -C $(KSRC)/ M=$(CURDIR) $@
