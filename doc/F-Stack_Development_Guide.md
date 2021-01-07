# F-Stack Development Guide

With the rapid development of Network Interface Cards the poor performance of data packet processing with the Linux kernel has become the bottleneck in modern network systems. Yet, the increasing demands of the Internet's growth demand a higher performant network processing solution. Kernel bypass has emerged to catch more and more attention. There are various similar technologies such as: DPDK, NETMAP and PF_RING. The main idea of kernel bypass is that Linux is only used to deal with control flow; all data streams are processed in user space. Therefore, kernel bypass can avoid performance bottlenecks caused by kernel packet copying, thread scheduling, system calls, and interrupts. Furthermore, kernel bypass can achieve higher performance with multi-optimizing methods. Within various techniques, DPDK has been widely used because of it's more thorough isolation from kernel scheduling and active community support.

F-Stack is an open source high performant network framework based on DPDK with the following characteristics:

1. Ultra high network performance which the network card can achieve under full load: 10 million concurrent connections, 5 million RPS, 1 million CPS.
2. Transplant FreeBSD 11.01 user space stack, which provides a complete stack function, and cut a great amount of irrelevant features. This greatly enhances network performance.
3. Support Nginx, Redis, and other mature applications. Services can easily use F-Stack.
4. Easy to extend with multi-process architecture.
5. Provides micro thread interface. Various applications with stateful applications can easily use F-Stack to get high performance without processing complex asynchronous logic.
6. Provide an Epoll/Kqueue interface that allow many kinds of applications to easily use F-Stack.

## Structure of F-Stack code

    ├── app  -- Nginx(1.16.1)/Redis(3.2.8)/Microthread framework
    ├── config.ini
    ├── doc
    ├── dpdk -- Intel DPDK(16.07) directory
    ├── example -- DEMO
    ├── freebsd -- FreeBSD(11.0) Network Stack directory
    ├── lib -- F-Stack lib directory
    ├── mk
    └── start.sh


## DPDK initialization

### PORT & SOCKET

F-Stack simplify the initialization of the standard DPDK. By setting the NIC port and CPU core mask, you can set binding relationship of the port and CPU and lcore on different socket node. If there is no binding relationship set, port0 and socket node 0 will be set by default.

### KNI related

If the server does not have dedicated port, or all port used for service process, you need to open the KNI in the configuration file, and set the related protocol and port number to decide which packets need to be processed by the F-Stack, remaining packets will be forwarded to kernel by KNI, to support SSH management functions.

## Revise of FreeBSD Network Stack and DPDK based

Since DPDK is open source, there are various open source network stacks based on DPDK to support the higher level application in the market. Some are will be packaging Linux network stack into a library, some are porting FreeBSD network stack.

At the beginning of this work, F-Stack used a simple TCP/IP stack that developed by ourselves. However, with the growth of various services, this stack couldn't meet the needs of these services while continue to develop and maintain a complete network stack will cost high. So the FreeBSD network stack was ported into F-Stack. The FreeBSD network stack provides complete features and can follow up the improvement from the community. Thanks to [libplebnet](https://gitorious.org/freebsd/kmm-sandbox/commit/fa8a11970bc0ed092692736f175925766bebf6af?p=freebsd:kmm-sandbox.git;a=tree;f=lib/libplebnet;h=ae446dba0b4f8593b69b339ea667e12d5b709cfb;hb=refs/heads/work/svn_trunk_libplebnet) and [libuinet](https://github.com/pkelsey/libuinet), this work becomes a lot easier.

In order to minimize the impact of resource sharing and kernel system (such as scheduling, locks, etc.) on the performance, F-Stack uses a multi-process architecture. Following are the changes to the FreeBSD network stack.

### Scheduling

Cut kernel thread, interrupt thread, timer thread, sched, wakeup, sleep, etc of FreeBSD Network Stack

### Lock

Cut lock operations of FreeBSD Network Stack, including mtx、rw、rm、sx、cond, etc.

### Memory related

Using phymem, uma\_page\_slab\_hash, uma initialization, kmem_malloc malloc

### Global variables

pcpu curthread proc0 thread0, initialization

### Environment variable

setenv getenv

### SYS_INIT

mi_startup

### Clock

timecounter, ticks, hz, timer

### Other

Linux and freebsd errno conversion, glue code, Remove unnecessary modules

## Applications use F-Stack

F-Stack provides ff API (See  *F-Stack\_API\_Reference*) to support applications. F-Stack also integrates third-party application such as Nginx, Redis, etc and. Micro thread interface is also provided to help original application easily use F-Stack.

### Web application

HTTP web application can use F-Stack with Nginx.

### key-value application

key-value db application can use F-Stack with redis, and can start multi Redis instance.

### Stateful(High latency) applications

Applications with stateful(high latency) use F-Stack , state need to be stored for a long time, can directly use the F-Stack micro threading framework. Applications only need to focus on with the service logic. And with synchronous programming, high performance asynchronous service server can be achieved.

## F-Stack configure file reference

  DPDK related parameters, including coremask adn NIC ports num.
  FreeBSD related parameters, similar with original FreeBSD's /boot.config and /etc/sysctl.conf.

## Start a F-Stack application

Since F-Stack is multi-process architecture, every F-Stack application process should call `ff_init(argc, argv)` to initialize the environments.
For example, if `lcore_mask=f` in config.ini, you can start your app like this:

    ${bin} --conf config.ini --proc-type=primary --proc-id=0
    ${bin} --conf config.ini --proc-type=secondary --proc-id=1
    ${bin} --conf config.ini --proc-type=secondary --proc-id=2
    ${bin} --conf config.ini --proc-type=secondary --proc-id=3

Or you can just use `start.sh` under F-Stack root directory.
