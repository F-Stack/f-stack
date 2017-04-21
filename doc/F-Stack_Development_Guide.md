# F-Stack Development Guide

With the rapid development of NIC, the poor performance of data packets processing with Linux kernel has become the bottleneck. However the rapid development of the Internet needs high performance of network processing, kernel bypass has caught more and more attention. There are various similar technologies appear, such as DPDK, NETMAP and PF_RING. The main idea of kernel bypass is that Linux is only used to deal with control flow, all data streams are processed in user space. Therefore kernel bypass can avoid performance bottlenecks caused by kernel packet copy, thread scheduling, system calls and interrupt. Further more, kernel bypass can achieve higher performance with multi optimizing methods.  Within various techniques, DPDK has been widely used because of its more thorough isolation from kernel scheduling and active community support.

F-Stack is an open source network framework with high performance based on DPDK. With follow characteristics

1. Ultra high network performance which can achieve network card under full load, 10 million concurrent, five million RPS, 1 million CPS.
2. Transplant FreeBSD 11.01 user space stack, provides a complete stack function, cut a great amount of irrelevant features. Therefore greatly enhance the performance.
3. Support Nginx, Redis and other mature applications, service can easily use F-Stack
4. With Multi-process architecture, easy to extend
5. Provide micro thread interface. Various applications with long time consuming can easily use F-Stack to get high performance without processing complex asynchronous logic.
6. Provide Epoll/kqueue interface that allow many kinds of applications easily use F-Stack

## Structure of F-Stack code

    ├── app  -- Nginx(1.11.10)/Redis(3.2.8)/Microthread framework
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

  DPDK related parameters, including coremask adn NIC ports num

	[dpdk]
    lcore_mask=3
    ## Port mask, enable and disable ports.
    ## Default: all ports are enabled.
    #port_mask=1
    channel=4
    nb_ports=1
    promiscuous=1
    numa_on=1
    
    [port0]
    addr=192.168.1.2
    netmask=255.255.255.0
    broadcast=192.168.1.255
    gateway=192.168.1.1

    ## Packet capture path, this will hurt performance
    #pcap=./a.pcap
    
    ## Kni config: if enabled and method=reject,
    ## all packets that do not belong to the following tcp_port and udp_port
    ## will transmit to kernel; if method=accept, all packets that belong to
    ## the following tcp_port and udp_port will transmit to kernel.
    #[kni]
    #enable=1
    #method=reject
    #tcp_port=80
    #udp_port=53
    
    # log is invalid
    [log]
    level=1
    dir=/var/log
    
    ## FreeBSD network performance tuning configurations.
    ## Most native FreeBSD configurations are supported.
    [freebsd.boot]
    hz=100
    
    kern.ipc.maxsockets=262144
    
    net.inet.tcp.syncache.hashsize=4096
    net.inet.tcp.syncache.bucketlimit=100
    
    net.inet.tcp.tcbhashsize=65536
    
    [freebsd.sysctl]
    kern.ipc.somaxconn=32768
    kern.ipc.maxsockbuf=16777216
    
    net.inet.tcp.fast_finwait2_recycle=1
    net.inet.tcp.sendspace=16384
    net.inet.tcp.recvspace=8192
    net.inet.tcp.nolocaltimewait=1
    net.inet.tcp.cc.algorithm=htcp
    net.inet.tcp.sendbuf_max=16777216
    net.inet.tcp.recvbuf_max=16777216
    net.inet.tcp.sendbuf_auto=1
    net.inet.tcp.recvbuf_auto=1
    net.inet.tcp.sendbuf_inc=16384
    net.inet.tcp.recvbuf_inc=524288
    net.inet.tcp.inflight.enable=0
    net.inet.tcp.sack=1
    net.inet.tcp.blackhole=1
    net.inet.tcp.msl=2000
    net.inet.tcp.delayed_ack=0
    
    net.inet.udp.blackhole=1
    net.inet.ip.redirect=0

## F-Stack Application Start

F-Stack use a multi process architecture to remove resource sharing. There are some attentions for start of application dock with F-Stack. We take the example of start.sh under F-Stack root directory.

    #!/bin/bash

    function usage() {
        echo "F-Stack app start tool"
        echo "Options:"
        echo " -c [conf]                Path of config file"
        echo " -b [N]                   Path of binary"
        echo " -h                       show this help"
        exit
    }

    conf=config.ini
    bin=./helloword
    
    while getopts "c:b:h" args
    do
        case $args in
             c)
                conf=$OPTARG
                ;;
             b)
                bin=$OPTARG
                ;;
             h)
                usage
                exit 0
                ;;
        esac
    done

    allcmask0x=`cat ${conf}|grep lcore_mask|awk -F '=' '{print $2}'`
    ((allcmask=16#$allcmask0x))
    
    # match coremask actual number of CPU core, and calculate the specified startup parameters of all processes, including
    #	-c coremask，The coremask parameters and the actual number of CPU core match, and calculate the specific startup parameters of all processes, including
    #	--proc-type=primary/secondary
    #	--num-procs = number of process
    #	--proc-id = current process ID, increase from 0
    num_procs=0
    PROCESSOR=$(grep 'processor' /proc/cpuinfo |sort |uniq |wc -l)
    for((i=0;i<${PROCESSOR};++i))
    do
        mask=`echo "2^$i"|bc`
        ((result=${allcmask} & ${mask}))
        if [ ${result} != 0 ]
        then 
            ((num_procs++));
            cpuinfo[$i]=1
        else
            cpuinfo[$i]=0
        fi 
    done
    proc_id=0
    for((i=0;i<${PROCESSOR};++i))
    do
        if ((cpuinfo[$i] == 1))
        then
            cmask=`echo "2^$i"|bc`
            cmask=`echo "obase=16;${cmask}"|bc`
            if ((proc_id == 0))
            then
                #echo "${bin} config.ini -c $cmask  --proc-type=primary --num-procs=${num_procs} --proc-id=${proc_id}"
                ${bin} config.ini -c ${cmask}  --proc-type=primary --num-procs=${num_procs} --proc-id=${proc_id} &
                sleep 5
            else
                #echo "${bin} config.ini -c $cmask --proc-type=secondary --num-procs=${num_procs} --proc-id=${proc_id}"
                ${bin} config.ini -c $cmask --proc-type=secondary --num-procs=${num_procs} --proc-id=${proc_id} &
            fi
            ((proc_id++))
        fi 
    done
