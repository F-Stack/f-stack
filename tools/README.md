# Introduction

Directory `compat` implements an ipc library using dpdk `rte_ring` and ports some source files compatible with FreeBSD and Linux.

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
Unsupported interfaces or parameters:
```
inet6
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

       ./route -p 0 add -net 0.0.0.0/0 192.168.1.1

     A shorter version of adding a default route can also be written as:

       ./route -p 0 add default 192.168.1.1

     Add a static route to the 172.16.10.0/24 network via the 172.16.1.1 gate-
     way:

       ./route -p 0 add -net 172.16.10.0/24 172.16.1.1

     Change the gateway of an already established static route in the routing
     table:

       ./route -p 0 change -net 172.16.10.0/24 172.16.1.2

     Display the route for a destination network:

       ./route -p 0 show 172.16.10.0

     Delete a static route from the routing table:

       ./route -p 0 delete -net 172.16.10.0/24 172.16.1.2

     Remove all routes from the routing table:

       ./route -p 0 flush

    FreeBSD uses `netstat -rn ` to list the route table which we havn't ported,
    you can execute the following command instead, `-d` means debug mode, `-v`
    means verbose.
        ./route -p 0 -d -v flush
```
Note that, if you want to modify the route table, you must use `-p` to execute the same command for each f-stack process.

For more details, see [Manual page](https://www.freebsd.org/cgi/man.cgi?route).

# top
Usage:
```
top [-p <f-stack proc_id>] [-d <secs>] [-n num]
```
Examples:
```
./tools/top/top 

|---------|---------|---------|---------------|
|     idle|      sys|      usr|           loop|
|---------|---------|---------|---------------|
|   99.69%|    0.00%|    0.31%|        8214640|
|   99.77%|    0.00%|    0.23%|        8205713|
|    5.02%|   45.19%|   49.79%|         769435|
|    0.00%|   19.88%|   80.12%|            393|
|    0.00%|   20.28%|   79.72%|            395|
|    0.00%|   15.50%|   84.50%|            403|
|    0.00%|   31.31%|   68.69%|            427|
|   32.07%|    8.78%|   59.15%|        2342862|
|   99.79%|    0.00%|    0.21%|        9974439|
|   99.81%|    0.00%|    0.19%|        7336153|
|   99.79%|    0.00%|    0.21%|        8147676|
```

# netstat
Usage:
```
   netstat -P <f-stack proc_id> [-46AaLnRSTWx] [-f protocol_family | -p protocol]
   netstat -P <f-stack proc_id> -i | -I interface [-46abdhnW] [-f address_family]
   netstat -P <f-stack proc_id> -w wait [-I interface] [-46d] [-q howmany]
   netstat -P <f-stack proc_id> -s [-46sz] [-f protocol_family | -p protocol]
   netstat -P <f-stack proc_id> -i | -I interface -s [-46s]
           [-f protocol_family | -p protocol]
   netstat -P <f-stack proc_id> -B [-z] [-I interface]
   netstat -P <f-stack proc_id> -r [-46AnW] [-F fibnum] [-f address_family]
   netstat -P <f-stack proc_id> -rs [-s]
   netstat -P <f-stack proc_id> -g [-46W] [-f address_family]
   netstat -P <f-stack proc_id> -gs [-46s] [-f address_family]
   netstat -P <f-stack proc_id> -Q
```

Unsupported commands or features:
```
-M
-N
-m
ipv6
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
