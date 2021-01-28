SUBDIRS=compat libutil libmemstat libxo libnetgraph sysctl ifconfig route top netstat ngctl ipfw arp traffic knictl ndp
PREFIX_BIN=/usr/local/bin

all:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) all ) ; done

clean:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) clean ) ; done

install:
	rm -rf ${PREFIX_BIN}/f-stack

	cp -rf sbin/ ${PREFIX_BIN}/f-stack
	ln -sf ${PREFIX_BIN}/f-stack/arp ${PREFIX_BIN}/ff_arp
	ln -sf ${PREFIX_BIN}/f-stack/ndp ${PREFIX_BIN}/ff_ndp
	ln -sf ${PREFIX_BIN}/f-stack/ifconfig ${PREFIX_BIN}/ff_ifconfig
	ln -sf ${PREFIX_BIN}/f-stack/ipfw ${PREFIX_BIN}/ff_ipfw
	ln -sf ${PREFIX_BIN}/f-stack/netstat ${PREFIX_BIN}/ff_netstat
	ln -sf ${PREFIX_BIN}/f-stack/ngctl ${PREFIX_BIN}/ff_ngctl
	ln -sf ${PREFIX_BIN}/f-stack/route ${PREFIX_BIN}/ff_route
	ln -sf ${PREFIX_BIN}/f-stack/sysctl ${PREFIX_BIN}/ff_sysctl
	ln -sf ${PREFIX_BIN}/f-stack/top ${PREFIX_BIN}/ff_top
	ln -sf ${PREFIX_BIN}/f-stack/traffic ${PREFIX_BIN}/ff_traffic
	ln -sf ${PREFIX_BIN}/f-stack/knictl ${PREFIX_BIN}/ff_knictl

uninstall:
	rm -rf ${PREFIX_BIN}/f-stack
	rm -rf ${PREFIX_BIN}/ff_*
