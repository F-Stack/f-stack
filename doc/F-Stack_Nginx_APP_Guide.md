# F-Stack Nginx APP Guide

F-Stack is an open source network framework based on DPDK. F-Stack supports standard Nginx as HTTP framework which means all web application based on HTTP can easily use F-Stack.

## How does Nginx use F-Stack?

  Nginx APP is in `app/nginx-1.11.10` directory.

```

                                                    +--------+
                                                    |
+------------------------+                          |
   channel: socketpair                              |  signal(reload, quit..)
+------------------------+                          |
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
               |                    |     |                   |    |                  |
               | ff primary process |     |  worker process   |    |  worker process  |
               |                    |     |                   |    |                  |
               +--------------------+     +-------------------+    +------------------+
                ff_init                   +--------+  +-------+
                loop:                     |        |  |       |
                 handle channel event     | fstack |  |channel|
                                          |  main  |  | event |
                                          |  loop  |  |thread |
                                          | thread |  |       |
                                          |        |  |       |
                                          +--------+  +-------+
                                           woker       loop:
                                          process      handle
                                           cycle      channel
                                                       event

```

- spawn a new process: ff primary, ff_init(--proc-type=primary);loop(wait channel event).
- worker process, main thread: ff_init(--proc-type=secondary);ff_run(worker_process_cycle), channel thread: wait channel event.

Note that:
- supported nginx signals: reload(HUP)/reopen(USR1)/stop(TERM).

- unsupported nginx signals: NGX_CHANGEBIN_SIGNAL(USR2).

- when use `nginx -s reload`, you should make sure that `woker_processes` in nginx.conf and f-stack.conf couldn't be modified.

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

