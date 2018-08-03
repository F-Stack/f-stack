# F-Stack Build GUide

The procedures to compile f-stack in different linux releases is almost the same, but there are still some points you need to pay attention to. This document aims to help you solve some of the problems you may meet when compiling f-stack in different linux releases.

```sh
$ sudo -i
# in centos and redhat
$ yum install -y git gcc openssl-devel kernel-devel-$(uname -r) bc numactl-devel python
# in ubuntu
$ apt-get install git gcc openssl libssl-dev linux-headers-$(uname -r) bc libnuma1 libnuma-dev libpcre3 libpcre3-dev zlib1g-dev python

$ mkdir /data/f-stack
$ git clone https://github.com/F-Stack/f-stack.git /data/f-stack

# compile dpdk
$ cd /data/f-stack/dpdk
$ make config T=x86_64-native-linuxapp-gcc
$ make

# Compile f-stack lib
$ export FF_PATH=/data/f-stack
$ export FF_DPDK=/data/f-stack/dpdk/build
$ cd /data/f-stack/lib
$ make

# Compile Nginx
$ cd ../app/nginx-1.11.10
$ ./configure --prefix=/usr/local/nginx_fstack --with-ff_module
$ make
$ make install

# Compile Redis
$ cd ../redis-3.2.8
$ make

# Compile f-stack tools
$ cd ../../tools
$ make

# Compile helloworld examples
$ cd ../examples
$ make
```

## Compile Nginx in Ubuntu

- before make Nginx, remove -Werror from CFLAGS at app/nginx-1.11.10/objs/Makefile line 3. (you should run ./configure command first to generate Makefile) (fixed in 2018/07/23)

```
-   CFLAGS = -pipe -Os -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g 
+   CFLAGS = -pipe -Os -W -Wall -Wpointer-arith -Wno-unused-parameter -g 
```

- remove '\\' in statement printf at f-stack/tools/netstat/Makefile line 70, now it should be: 

```
-   printf("\#define\tN%s\t%s\n", toupper($$2), i++);
+   printf("#define\tN%s\t%s\n", toupper($$2), i++);
```

## Compile Redis in Ubuntu 18.04 (fixed in 2018/07/10)

- add an extra Macros to STD in f-stack/app/redis-3.2.8/src/Makefile line 28, and now it should be:

```
-   STD=-std=c99 -pedantic -DREDIS_STATIC=''
+   STD=-std=c99 -pedantic -DREDIS_STATIC='' -D_POSIX_C_SOURCE=199506L
```

## Compile Nginx in Ubuntu 18.04

- there will be a lot of warnings when compiling Nginx in Ubuntu 18.04, and sometimes it may fail, you'd better configure with the following command:

```
    ./configure --prefix=/usr/local/nginx_fstack --with-ff_module --with-cc-opt="-Wno-implicit-fallthrough -Wno-unused-result"
```

## Compile DPDK in CentOS 7.5 and RHEL 7.5

- struct member 'ndo_change_mtu' in struct net_device_ops has been renamed to 'ndo_change_mtu_rh74', f-stack/dpdk/lib/librte_eal/linuxapp/kni/kni_net.c line 704 should also be updated:

```
-   .ndo_change_mtu = kni_net_change_mtu,
+   .ndo_change_mtu_rh74 = kni_net_change_mtu,
```

## Compile dpdk in virtual machine

- f-stack/dpdk/lib/librte_eal/linuxapp/igb_uio/igb_uio.c line 279:
```

-   if (pci_intx_mask_supported(udev->pdev)) {
+   if (true || pci_intx_mask_supported(udev->pdev)) {
```