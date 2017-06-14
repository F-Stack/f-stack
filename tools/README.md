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
