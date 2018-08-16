SUBDIRS=compat libutil libmemstat libxo libnetgraph sysctl ifconfig route top netstat ngctl ipfw arp traffic

all:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) all ) ; done

clean:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) clean ) ; done
