# F-Stack Binary Release Quick Start

## How to use

Before you start to use f-stack-binary-release package, please make sure you: 
- have access to the internet
- have at least one NIC up
- have root permission
- meet all other requirements of dpdk

```sh
$ sudo -i
$ wget https://github.com/F-Stack/f-stack/releases/download/v1.12/f-stack-binary-release.tar.gz
$ tar zxf f-stack-binary-release.tar.gz
$ cd f-stack-binary-release/scripts
# set_env.sh will offload the NIC, if you only have one NIC, the following three commands must run in a script
$ ./set_env.sh dev_name
$ ./run_app.sh [app_name]
$ ./config_veth0.sh
```

- dev_name is the name of your NIC, you can see it with *ifconfig* or *ip addr* command
- app_name is the name of application you want to run, now we support 'nginx' and 'redis'. If you do not add any argument, it will run a helloworld example, you can use it to test whether the envrionment is setup correctly.
- All the scripts should run with root permission

## Directory structure

```
+-- f-stack-binary-release
|   +-- doc
|   |   +-- F-Stack_Build_Guide.md
|   |   +-- F-Stack_Binary_Release_Quick_Start.md
|   +-- f-stack-release
|   |   +-- CentOS
|   |   |   +-- app (nignx-1.11.10 redis-3.2.8)
|   |   |   +-- config.ini
|   |   |   +-- doc
|   |   |   +-- dpdk
|   |   |   +-- example
|   |   |   +-- start.sh (a script helps to run applications)
|   |   |   +-- tools
|   |   +-- RHEL
|   |   +-- Ubuntu
|   |   +-- kmod (kernel modules)
|   |   |   +-- CentOS
|   |   |   |   +-- supported_kernel_version
|   |   |   |   |   +-- igb_uio.ko
|   |   |   |   |   +-- rte_kni.ko
|   |   |   +-- RHEL
|   |   |   +-- Ubuntu
|   +-- scripts
|   |   +-- config_veth0.sh (configure the virtual NIC)
|   |   +-- run_app.sh  (run a specific application)
|   |   +-- set_env.sh  (setup environment that f-stack needs)
```

## Supported Linux releases

 The f-stack-binary-release package has supported several frequent used linux releases, you can use f-stack applications directly on these releases. What should be paid attention to is that f-stack uses linux kernel modules, so if you have different kernel versions in your machine, you could not use this f-stack-quick-start package and need to compile f-stack by yourself. Here is the list of linux releases this package support now:

| Linux Release  | Kernel |
| -------------- | ------ |
| CentOS 7.0     | 3.10.0-123.el7.x86_64 |
| CentOS 7.2     | 3.10.0-327.el7.x86_64 |
| CentOS 7.3     | 3.10.0-514.el7.x86_64 |
| CentOS 7.4     | 3.10.0-693.el7.x86_64 |
| CentOS 7.5     | 3.10.0-862.el7.x86_64 |
| RHEL 7.2       | 3.10.0-327.el7.x86_64 |
| RHEL 7.3       | 3.10.0-514.el7.x86_64 |
| RHEL 7.4       | 3.10.0-693.el7.x86_64 |
| RHEL 7.5       | 3.10.0-862.el7.x86_64 |
| Ubuntu 14.04.5 | 4.4.0-31-generic      |
| Ubuntu 16.04.4 | 4.13.0-36-generic     |
| Ubuntu 18.04   | 4.15.0-20-generic     |

Also, we support tencent cloud, if you are using cloud virtual machine in cloud.tencent.com, you can also use this f-stack-quick-start package.

| Linux Release  | Kernel |
| -------------- | ------ |
| CentOS 7.2     | 3.10.0-514.26.2.el7.x86_64 |
| CentOS 7.3     | 3.10.0-514.21.1.el7.x86_64 |
| CentOS 7.4     | 3.10.0-693.el7.x86_64      |
| Ubuntu 14.04.1 | 3.13.0-128-generic         |
| Ubuntu 16.04.1 | 4.4.0-91-generic           |

## Uninstall f-stack-binary-release package

```
$ sudo rm -rf /usr/local/nginx_fstack
$ rm -rf /path/to/f-stack-binary-release
```

## Compile f-stack by yourself

If your OS version is not in the above list or you want to compile f-stack by yourself, you can refer to another document [Build_Guide](https://github.com/F-Stack/f-stack/blob/master/doc/F-Stack_Build_Guide.md).
