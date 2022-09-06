# F-Stack Build GUide

The procedures to compile f-stack in different linux releases is almost the same, but there are still some points you need to pay attention to. This document aims to help you solve some of the problems you may meet when compiling f-stack in different linux releases.

```sh
$ sudo -i
# in centos and redhat
$ yum install -y git gcc openssl-devel kernel-devel-$(uname -r) bc numactl-devel python
$ pip3 install pyelftools --upgrade

# in ubuntu
$ apt-get install git gcc openssl libssl-dev linux-headers-$(uname -r) bc libnuma1 libnuma-dev libpcre3 libpcre3-dev zlib1g-dev python

$ mkdir /data/f-stack
$ git clone https://github.com/F-Stack/f-stack.git /data/f-stack

# compile dpdk
$ cd /data/f-stack/dpdk
$ meson -Denable_kmods=true build
$ ninja -C build
$ ninja -C build install

# Upgrade pkg-config while version < 0.28
$ cd /data
$ wget https://pkg-config.freedesktop.org/releases/pkg-config-0.29.2.tar.gz
$ tar xzvf pkg-config-0.29.2.tar.gz
$ cd pkg-config-0.29.2
$ ./configure --with-internal-glib
$ make
$ make install
$ mv /usr/bin/pkg-config /usr/bin/pkg-config.bak
$ ln -s /usr/local/bin/pkg-config /usr/bin/pkg-config

# Compile f-stack lib
$ export FF_PATH=/data/f-stack
$ export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
$ cd /data/f-stack/lib
$ make

# Compile Nginx
$ cd ../app/nginx-1.16.1
$ ./configure --prefix=/usr/local/nginx_fstack --with-ff_module
$ make
$ make install

# Compile Redis
$ cd app/redis-6.2.6/deps/jemalloc
$ ./autogen.sh
$ cd ../redis-6.2.6
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

- f-stack/dpdk/kernel/linux/igb_uio/igb_uio.c line 274:
```

-   if (pci_intx_mask_supported(udev->pdev)) {
+   if (true || pci_intx_mask_supported(udev->pdev)) {
```
