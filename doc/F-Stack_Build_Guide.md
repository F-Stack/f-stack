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
$ cd ../app/nginx-1.16.1
$ ./configure --prefix=/usr/local/nginx_fstack --with-ff_module
$ make
$ make install

# Compile Redis
$ cd ../redis-5.0.5
$ make

# Compile f-stack tools
$ cd ../../tools
$ make

# Compile helloworld examples
$ cd ../examples
$ make
```

## Compile tools in Ubuntu

- remove '\\' in statement printf at f-stack/tools/netstat/Makefile line 70, now it should be: 

```
-   printf("\#define\tN%s\t%s\n", toupper($$2), i++);
+   printf("#define\tN%s\t%s\n", toupper($$2), i++);
```

## Compile dpdk in virtual machine

- f-stack/dpdk/lib/librte_eal/linuxapp/igb_uio/igb_uio.c line 279:
```

-   if (pci_intx_mask_supported(udev->pdev)) {
+   if (true || pci_intx_mask_supported(udev->pdev)) {
```