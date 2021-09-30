# Introduction

Compile ff tools

    # Upgrade pkg-config while version < 0.28
    #wget https://pkg-config.freedesktop.org/releases/pkg-config-0.29.2.tar.gz
    #tar xzvf pkg-config-0.29.2.tar.gz
    #cd pkg-config-0.29.2
    #./configure --with-internal-glib
    #make
    #make install
    #mv /usr/bin/pkg-config /usr/bin/pkg-config.bak
    #ln -s /usr/local/bin/pkg-config /usr/bin/pkg-config

    export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig

    make

Install ff tools, all ff tools will be installed to `/usr/local/bin/f-stack/`, and some soft link will be created in `/usr/local/bin`, such as `ff_top`,`ff_traffic`, etc.

    make install

Directory `compat` implements an ipc library using dpdk `rte_ring` and ports some source files compatible with FreeBSD and Linux.

Directory `sbin` contains all the tools binary that compiled.

All other directories are useful tools ported from FreeBSD.
Since F-Stack is multi-process architecture and every process has an independent stack, so we must communicate with every F-Stack process.
Each tool add an option `-p`(Which F-Stack process to communicate with, default 0), except that, it is same with the original FreeBSD.

Note that these tools must be executed serially.

# sysctl
Usage:
```
sysctl -p <f-stack proc_id> [-bdehiNnoqTtWx] [ -B <bufsize> ] [-f filename] name[=value] ...
sysctl -p <f-stack proc_id> [-bdehNnoqTtWx] [ -B <bufsize> ] -a
```
For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?sysctl).

# ifconfig
Usage:
```
ifconfig -p <f-stack proc_id> [-f type:format] %sinterface address_family
        [address [dest_address]] [parameters]
    ifconfig -p <f-stack proc_id> interface create
    ifconfig -p <f-stack proc_id> -a %s[-d] [-m] [-u] [-v] [address_family]
    ifconfig -p <f-stack proc_id> -l [-d] [-u] [address_family]
    ifconfig -p <f-stack proc_id> %s[-d] [-m] [-u] [-v]
```
We has supportted inet6, you can config ipv6 address like this:

    ifconfig -p <f-stack proc_id> interface inet6 <ipv6 address> autoconf

Unsupported interfaces or parameters:
```
MAC(Mandatory Access Control)
media
SFP/SFP+
IEEE80211 Wireless
pfsync
LAGG LACP
jail
```
For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?ifconfig).

# route
Usage:
```
route -p <f-stack proc_id> [-46dnqtv] command [[modifiers] args]
```
Examples:
```
     Add a default route:

       ./sbin/route -p 0 add -net 0.0.0.0/0 192.168.1.1

     A shorter version of adding a default route can also be written as:

       ./sbin/route -p 0 add default 192.168.1.1

     Add a static route to the 172.16.10.0/24 network via the 172.16.1.1 gate-
     way:

       ./sbin/route -p 0 add -net 172.16.10.0/24 172.16.1.1

     Change the gateway of an already established static route in the routing
     table:

       ./sbin/route -p 0 change -net 172.16.10.0/24 172.16.1.2

     Display the route for a destination network:

       ./sbin/route -p 0 show 172.16.10.0
       ./sbin/route -p 0 -6 show ::/0

     Delete a static route from the routing table:

       ./sbin/route -p 0 delete -net 172.16.10.0/24 172.16.1.2

     Remove all routes from the routing table:

       ./sbin/route -p 0 flush

    FreeBSD uses `netstat -rn ` to list the route table which we havn't ported,
    you can execute the following command instead, `-d` means debug mode, `-v`
    means verbose.
       ./sbin/route -p 0 -d -v flush
```
Note that, if you want to modify the route table, you must use `-p` to execute the same command for each f-stack process.

For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?route).

# top
Usage:
```
top [-p <f-stack proc_id>] [-P <max proc_id>] [-d <secs>] [-n <num>]
```
Examples:
```
./sbin/top -p 0 -P 3
|---------|---------|---------|---------|---------------|
|  proc_id|     idle|      sys|      usr|           loop|
|---------|---------|---------|---------|---------------|
|        0|   92.44%|    4.00%|    3.56%|          13427|
|        1|   92.18%|    4.21%|    3.61%|          14035|
|        2|   92.19%|    4.19%|    3.62%|          13929|
|        3|   92.33%|    4.14%|    3.53%|          13938|
|    total|  369.14%|   16.54%|   14.32%|          55329|
|         |         |         |         |               |
|        0|   92.27%|    4.10%|    3.63%|          13438|
|        1|   92.03%|    4.27%|    3.70%|          13906|
|        2|   92.08%|    4.24%|    3.68%|          13817|
|        3|   92.28%|    4.15%|    3.57%|          13759|
|    total|  368.65%|   16.77%|   14.58%|          54920|
|         |         |         |         |               |
|        0|   91.88%|    4.30%|    3.81%|          13802|
|        1|   91.94%|    4.32%|    3.74%|          13928|
|        2|   92.10%|    4.24%|    3.66%|          13856|
|        3|   92.30%|    4.14%|    3.56%|          13708|
|    total|  368.22%|   17.00%|   14.77%|          55294|
|         |         |         |         |               |
```

# netstat
Usage:
```
   netstat -t <f-stack proc_id> [-46AaLnRSTWx] [-f protocol_family | -p protocol]
   netstat -t <f-stack proc_id> -i | -I interface [-46abdhnW] [-f address_family]
   netstat -t <f-stack proc_id> -w wait [-I interface] [-46d] [-q howmany]
   netstat -t <f-stack proc_id> -s [-46sz] [-f protocol_family | -p protocol]
   netstat -t <f-stack proc_id> -i | -I interface -s [-46s]
           [-f protocol_family | -p protocol]
   netstat -t <f-stack proc_id> -B [-z] [-I interface]
   netstat -t <f-stack proc_id> -r [-46AnW] [-F fibnum] [-f address_family]
   netstat -t <f-stack proc_id> -rs [-s]
   netstat -t <f-stack proc_id> -g [-46W] [-f address_family]
   netstat -t <f-stack proc_id> -gs [-46s] [-f address_family]
   netstat -t <f-stack proc_id> -Q
```

Unsupported commands or features:
```
-M
-N
-m
netgraph
ipsec
```

For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?netstat).

# ngctl
Usage:
```
ngctl -p <f-stack proc_id>  [-d] [-f file] [-n name] [command ...]
```

About interactive mode:
- if you have `libedit` in your system, you can turn on `MK_HAVE_LIBEDIT` in `opts.mk`,
  the interactive mode will support generic line editing, history functions.


For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?ngctl).

# ipfw
Usage:
```
ipfw -P <f-stack proc_id> [-abcdefhnNqStTv] <command>

where <command> is one of the following:

add [num] [set N] [prob x] RULE-BODY
{pipe|queue} N config PIPE-BODY
[pipe|queue] {zero|delete|show} [N{,N}]
nat N config {ip IPADDR|if IFNAME|log|deny_in|same_ports|unreg_only|reset|
                reverse|proxy_only|redirect_addr linkspec|
                redirect_port linkspec|redirect_proto linkspec}
set [disable N... enable N...] | move [rule] X to Y | swap X Y | show
set N {show|list|zero|resetlog|delete} [N{,N}] | flush
table N {add ip[/bits] [value] | delete ip[/bits] | flush | list}
table all {flush | list}

RULE-BODY:      check-state [PARAMS] | ACTION [PARAMS] ADDR [OPTION_LIST]
ACTION: check-state | allow | count | deny | unreach{,6} CODE |
               skipto N | {divert|tee} PORT | forward ADDR |
               pipe N | queue N | nat N | setfib FIB | reass
PARAMS:         [log [logamount LOGLIMIT]] [altq QUEUE_NAME]
ADDR:           [ MAC dst src ether_type ] 
                [ ip from IPADDR [ PORT ] to IPADDR [ PORTLIST ] ]
                [ ipv6|ip6 from IP6ADDR [ PORT ] to IP6ADDR [ PORTLIST ] ]
IPADDR: [not] { any | me | ip/bits{x,y,z} | table(t[,v]) | IPLIST }
IP6ADDR:        [not] { any | me | me6 | ip6/bits | IP6LIST }
IP6LIST:        { ip6 | ip6/bits }[,IP6LIST]
IPLIST: { ip | ip/bits | ip:mask }[,IPLIST]
OPTION_LIST:    OPTION [OPTION_LIST]
OPTION: bridged | diverted | diverted-loopback | diverted-output |
        {dst-ip|src-ip} IPADDR | {dst-ip6|src-ip6|dst-ipv6|src-ipv6} IP6ADDR |
        {dst-port|src-port} LIST |
        estab | frag | {gid|uid} N | icmptypes LIST | in | out | ipid LIST |
        iplen LIST | ipoptions SPEC | ipprecedence | ipsec | iptos SPEC |
        ipttl LIST | ipversion VER | keep-state | layer2 | limit ... |
        icmp6types LIST | ext6hdr LIST | flow-id N[,N] | fib FIB |
        mac ... | mac-type LIST | proto LIST | {recv|xmit|via} {IF|IPADDR} |
        setup | {tcpack|tcpseq|tcpwin} NN | tcpflags SPEC | tcpoptions SPEC |
        tcpdatalen LIST | verrevpath | versrcreach | antispoof
```
Note [dummynet](https://www.freebsd.org/cgi/man.cgi?query=dummynet) is not supported yet.

For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?ipfw) or [handbook](https://www.freebsd.org/doc/handbook/firewalls-ipfw.html).

# arp
Usage
```
usage: arp -p <f-stack proc_id> [-n] [-i interface] hostname
       arp -p <f-stack proc_id> [-n] [-i interface] -a
       arp -p <f-stack proc_id> -d hostname [pub]
       arp -p <f-stack proc_id> -d [-i interface] -a
       arp -p <f-stack proc_id> -s hostname ether_addr [temp] [reject | blackhole] [pub [only]]
       arp -p <f-stack proc_id> -S hostname ether_addr [temp] [reject | blackhole] [pub [only]]
       arp -p <f-stack proc_id> -f filename
```

For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?arp).

# traffic
Usage:
```
traffic [-p <f-stack proc_id>] [-P <max proc_id>] [-d <secs>] [-n <num>]
```
Examples:
```
./sbin/traffic -p 0 -P 3

|---------|--------------------|--------------------|--------------------|--------------------|
|  proc_id|          rx packets|            rx bytes|          tx packets|            tx bytes|
|---------|--------------------|--------------------|--------------------|--------------------|
|        0|               39594|             3721836|               79218|            30945013|
|        1|               43427|             4082138|               86860|            33918830|
|        2|               37708|             3544552|               75448|            29462444|
|        3|               41306|             3882764|               82598|            32254519|
|    total|              162035|            15231290|              324124|           126580806|
|         |                    |                    |                    |                    |
|        0|               40849|             3839831|               81686|            31898383|
|        1|               44526|             4185444|               89056|            34776368|
|        2|               38491|             3618154|               76974|            30058347|
|        3|               41631|             3913314|               83244|            32506782|
|    total|              165497|            15556743|              330960|           129239880|
|         |                    |                    |                    |                    |
|        0|               41136|             3866750|               82268|            32125654|
|        1|               42184|             3965296|               84372|            32947266|
|        2|               39182|             3683108|               78358|            30598799|
|        3|               41458|             3897052|               82926|            32382603|
|    total|              163960|            15412206|              327924|           128054322|
|         |                    |                    |                    |                    |
```

# ndp
Usage:
```
ndp -C <f-stack proc_id> [-nt] hostname
ndp -C <f-stack proc_id> [-nt] -a | -c | -p | -r | -H | -P | -R
ndp -C <f-stack proc_id> [-nt] -A wait
ndp -C <f-stack proc_id> [-nt] -d hostname
ndp -C <f-stack proc_id> [-nt] -f filename
ndp -C <f-stack proc_id> [-nt] -i interface [flags...]
ndp -C <f-stack proc_id> [-nt] -I [interface|delete]
ndp -C <f-stack proc_id> [-nt] -s nodename etheraddr [temp] [proxy]
```
For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?ndp).

# how to implement a custom tool for communicating with F-Stack process

Add a new FF_MSG_TYPE in ff_msg.h:
```
enum FF_MSG_TYPE {
    FF_UNKNOWN = 0,
    FF_SYSCTL,
    FF_HELLOWORLD,
};
```

Define a structure used to communicate:
```
struct ff_helloworld_args {
    void *request;
    size_t req_len;
    void *reply;
    size_t rep_len;
};
```
Note that, when using struct ff_helloworld_args, pointers in this structure must point to the addresses range from ff_msg.buf_addr and ff_msg.buf_addr+ff_msg.buf_len, ff_msg.buf_len is (10240 - sizeof(struct ff_msg)).

And add it to ff_msg:
```
struct ff_msg {
    ...
    union {
        struct ff_sysctl_args sysctl;
        struct ff_helloworld_args helloworld;
    };
};
```

Modify ff_dpdk_if.c, add a handle function:
```
static inline void
handle_helloworld_msg(struct ff_msg *msg, uint16_t proc_id)
{
    printf("helloworld msg recved.\n");
    msg->result = 0;
    rte_ring_enqueue(msg_ring[proc_id].ring[1], msg);
}

static inline void
handle_msg(struct ff_msg *msg, uint16_t proc_id)
{
    switch (msg->msg_type) {
        case FF_SYSCTL:
            handle_sysctl_msg(msg, proc_id);
            break;
        case FF_HELLOWORLD:
            handle_helloworld_msg(msg, proc_id);
        default:
            handle_default_msg(msg, proc_id);
            break;
    }
}
```

Create helloworld.c:

```
int main()
{
    struct ff_msg *msg = ff_ipc_msg_alloc();

    char *buf = msg->buf_addr;

    msg->helloworld.request = buf;
    memcpy(msg->helloworld.request, "hello", 5);
    msg->helloworld.req_len = 5;
    buf += 5;

    msg->helloworld.reply = buf;
    msg->helloworld.rep_len = 10;

    ff_ipc_send(msg, 0);

    struct ff_msg *retmsg;
    ff_ipc_recv(retmsg, 0);
    assert(remsg==msg);

    ff_ipc_msg_free(msg);
}

```

The Makefile may like this:
```
TOPDIR?=${CURDIR}/../..

PROG=helloworld

include ${TOPDIR}/tools/prog.mk
```
