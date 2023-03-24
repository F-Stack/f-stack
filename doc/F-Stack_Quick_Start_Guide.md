# F-Stack Quick Start Guide

  F-Stack is an open source high performance network framework based on DPDK.


## System Requirements

See Intel DPDK [linux_gsg](http://dpdk.org/doc/guides/linux_gsg/index.html)

## clone F-Stack

	mkdir /data/f-stack
	git clone https://github.com/F-Stack/f-stack.git /data/f-stack

## Install python and modules for running DPDK python scripts
    pip3 install pyelftools --upgrade # RedHat/Centos
    sudo apt install python # On ubuntu
    #sudo pkg install python # On FreeBSD

## Compile DPDK

Read DPDK Quick Started Guide or run the command below

	cd /data/f-stack/dpdk
	meson -Denable_kmods=true build
	ninja -C build
	ninja -C build install

## Set hugepage

For a single-node system, the command to use is as follows (assuming that 1024 pages are required):

	echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

On a NUMA machine, pages should be allocated explicitly on separate nodes:

	echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

Once the hugepage memory is reserved, to make the memory available for DPDK use, perform the following steps:

	mkdir /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge

The mount point can be made permanent across reboots, by adding the following line to the `/etc/fstab` file:

	nodev /mnt/huge hugetlbfs defaults 0 0

## offload NIC

    modprobe uio
    insmod /data/f-stack/dpdk/build/kernel/linux/igb_uio/igb_uio.ko
    insmod /data/f-stack/dpdk/build/kernel/linux/kni/rte_kni.ko carrier=on
    python dpdk-devbind.py --status
    ifconfig eth0 down
    python dpdk-devbind.py --bind=igb_uio eth0 # assuming that use 10GE NIC and eth0

## Compile  lib

    # Upgrade pkg-config while version < 0.28
    cd /data/
    wget https://pkg-config.freedesktop.org/releases/pkg-config-0.29.2.tar.gz
    tar xzvf pkg-config-0.29.2.tar.gz
    cd pkg-config-0.29.2
    ./configure --with-internal-glib
    make
    make install
    mv /usr/bin/pkg-config /usr/bin/pkg-config.bak
    ln -s /usr/local/bin/pkg-config /usr/bin/pkg-config

    export FF_PATH=/data/f-stack
    export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
    cd /data/f-stack
    cd lib
    make

### Compile Nginx

	cd ../
	cd app/nginx-1.16.1
	./configure --prefix=/usr/local/nginx_fstack --with-ff_module
	make
	make install
	cd ../../
	/usr/local/nginx_fstack/sbin/nginx

### Compile Redis

	cd app/redis-6.2.6/deps/jemalloc
	./autogen.sh
	cd ../..
	make
	# run with start.sh
	./start.sh -b ./redis-server -o /path/to/redis.conf
	# or run like this:
	#./redis-server --conf config.ini --proc-type=primary --proc-id=0 /path/to/redis.conf

