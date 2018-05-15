# F-Stack Quick Start Guide

  F-Stack is an open source high performance network framework based on DPDK.


## System Requirements

See Intel DPDK [linux_gsg](http://dpdk.org/doc/guides/linux_gsg/index.html)

## Clone F-Stack

	mkdir /data/f-stack
	git clone https://github.com/F-Stack/f-stack.git /data/f-stack

## Install libnuma-dev

	# on Centos
	yum install numactl-devel
	# on Ubuntu
	sudo apt-get install libnuma-dev

## Compile DPDK

Read DPDK Quick Started Guide or run the command below

	cd /data/f-stack/dpdk/tools
	./dpdk-setup.sh 

Compile with x86_64-native-linuxapp-gcc

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
	insmod /data/f-stack/dpdk/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
	insmod /data/f-stack/dpdk/x86_64-native-linuxapp-gcc/kmod/rte_kni.ko
	python dpdk-devbind.py --status
	ifconfig eth0 down
	python dpdk-devbind.py --bind=igb_uio eth0 # assuming that use 10GE NIC and eth0

## Compile  lib

	export FF_PATH=/data/f-stack
	export FF_DPDK=/data/f-stack/dpdk/x86_64-native-linuxapp-gcc
	cd ../../
	cd lib
	make

### Compile Nginx

	cd ../
	cd app/nginx-1.11.10
	./configure --prefix=/usr/local/nginx_fstack --with-ff_module
	make
	make install
	cd ../../
	/usr/local/nginx_fstack/sbin/nginx

### Compile Redis

	cd app/redis-3.2.8/
	make
	make install

