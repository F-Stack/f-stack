# F-Stack Nginx APP Guide

F-Stack is an open source network framework based on DPDK. F-Stack supports standard Nginx as HTTP framework which means all web application based on HTTP can easily use F-Stack.

## How does Nginx use F-Stack?

  Nginx APP is in `app/nginx-1.16.1` directory.

```

                                                        +--------+
                         +------------------------+     |
                            channel: socketpair         |
                         +------------------------+     |  signal(reload, quit..)
                                                        |
                                                        |
                                              +---------v--------+
                                              |                  |
                             +----------------+  master process  +---------------+
                             |                |                  |               |
                             |  channel       +----------+-------+               |
                             |                           |              channel  |
                             |                  channel  |                       |
                             |                           |                       |
                   +---------+----------+     +----------+--------+    +---------+--------+
first one to start |                    |     |                   |    |                  |
 last one to exit<-+   primary worker   |     |  secondary worker |    | secondary worker |
                   |                    |     |                   |    |                  |
                   +--------------------+     +-------------------+    +------------------+
                   +--------------------+     +-------------------+  
                   |                    |     |                   |
                   |   fstack,kernel    |     |   fstack,kernel   |
                   |     and channel    |     |     and channel   |
                   |     loop thread    |     |     loop thread   |
                   |                    |     |			  |
                   +--------------------+     +-------------------+
                    woker process cycle        woker process cycle

```

- spawn primary worker firstly, and then wait for primary startup, continue to spawn secondary workers.

- a major addition to the worker process is fstack-handling：ff_init();ff_run(worker_process_cycle); worker_process_cycle(handle channel/host/fstack event).

## What's Different?
### New directives:
All the directives below are available only when ```NGX_HAVE_FSTACK``` is defined.
```
    Syntax: kernel_network_stack on | off;
    Default: kernel_network_stack off;
    Context: http, server

    Determines whether server should run on kernel network stack or fstack.
```

```
    Syntax: proxy_kernel_network_stack on | off;
    Default: kernel_network_stack off;
    Context: http, stream, mail, server

    Determines whether proxy should go through kernel network stack or fstack.
```

```
    Syntax: schedule_timeout time;
    Default: schedule_timeout 30ms;
    Context: main

    Sets a time interval for polling kernel_network_stack. The default value is 30 msec.
```

### Command-line `reload`
the `reload` is not graceful, service will still be unavailable during the process of reloading.

### Necessary modifies in nginx.conf:
```
    user  root; # root account is necessary.
    fstack_conf f-stack.conf;  # path of f-stack configuration file, default: $NGX_PREFIX/conf/f-stack.conf.
    worker_processes  1; # should be equal to the lcore count of `dpdk.lcore_mask` in f-stack.conf.

    events {
        worker_connections  102400; # increase
        use kqueue; # use kqueue
    }

    sendfile off; # sendfile off
```

## Nginx compiling
	./configure --prefix=/usr/local/nginx_fstack --with-ff_module
	make
	make install

