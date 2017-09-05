# F-Stack Nginx APP Guide

F-Stack is an open source network framework based on DPDK. F-Stack supports standard Nginx as HTTP framework which means all web application based on HTTP can easily use F-Stack.

## How does Nginx use F-Stack?

  Nginx APP is in `app/nginx-1.11.10` directory.

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
                   +--------+  +-------+      +--------+  +-------+
                   |        |  |       |      |        |  |       |
                   | fstack |  |channel|      | fstack |  |channel|
                   |  main  |  | event |      |  main  |  | event |
                   |  loop  |  |thread |      |  loop  |  |thread |
                   | thread |  |       |      | thread |  |       |
                   |        |  |       |      |        |  |       |
                   +--------+  +-------+      +--------+  +-------+
                    woker       loop:          worker      loop:
                   process      handle        process      handle
                    cycle      channel         cycle      channel
                                event                      event

```

- spawn primary worker firstly, and then wait for primary startup, continue to spawn secondary workers.

- worker process has 2 threads. main thread: ff_init();ff_run(worker_process_cycle), channel thread: loop(handle channel event).

Note that:

- the `reload` is not graceful, service will still be unavailable during the process of reloading.

- necessary modifies in nginx.conf:

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

