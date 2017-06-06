SUBDIRS=compat sysctl ifconfig

all:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) all ) ; done

clean:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) clean ) ; done
