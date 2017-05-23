# Introduction

Directory `ipc` implements an ipc library using dpdk `rte_ring`, can be used to communicate with F-Stack processes.

All other directories are useful tools ported from FreeBSD.

# ipc

This is a simple implemention using dpdk `rte_ring`.
```
ff_ipc_msg_alloc: get msg structure from rte_mempool.
ff_ipc_msg_free: put msg to rte_mempool.
ff_ipc_send: enqueue msg to rte_ring.
ff_ipc_recv: dequeue msg from rte_ring.
```

Since F-Stack is multi-process architecture and every process has an independent stack, so we must communicate with every F-Stack process.

# sysctl
Usage:
```
sysctl -p <f-stack proc_id> [-bdehiNnoqTtWx] [ -B <bufsize> ] [-f filename] name[=value] ...
sysctl -p <f-stack proc_id> [-bdehNnoqTtWx] [ -B <bufsize> ] -a
```

```
-p   Which F-Stack process to communicate with, default 0. 
```

Except this option, it is same with the original FreeBSD sysctl, see [Manual page](https://www.freebsd.org/cgi/man.cgi?sysctl).

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
