# F-Stack Nginx APP Guide

F-Stack is an open source network framework based on DPDK. F-Stack supports standard Nginx as HTTP framework which means all web application based on HTTP can easily use F-Stack.

## How does Nginx use F-Stack?

  Nginx APP is in `app/nginx-1.25.2` directory.

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
    Default: proxy_kernel_network_stack off;
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

### Graceful reload preparation (`graceful_reload`, experimental)

The nginx APP supports `graceful_reload` in the `[dpdk]` section of the F-Stack config file (`fstack_conf`). It is `0` (off) by default: the behavior is identical to previous releases (worker 0 is the DPDK primary, reload is the legacy two-phase serial reload).

With `graceful_reload=1` (requires `primary_slim=1`, `nb_procs>=2`, incompatible with `thread_mode=1`):

- The nginx master spawns a **resident slim primary** (a DPDK primary with no rx/tx queue, `--proc-type=primary --proc-id=0` + `primary_slim=1`) at startup, double-forked and detached from the master lifecycle: `reload`/`upgrade` never signal it, and it survives master exit. It is detected via `/var/run/ff_slim_primary.pid` (diagnostics go to `/var/run/ff_slim_primary.log`); run the master as root or make `/var/run` writable.
- All nginx workers attach as DPDK **secondaries**: worker `i` runs F-Stack `proc_id = i + 1` because the slim primary owns `proc_id 0`. Accordingly set `dpdk.lcore_mask` to `worker_processes + 1` bits and exclude the primary lcore from every `[portN] lcore_list`.
- The master validates the topology before spawning workers: the `dpdk.lcore_mask` bit count must equal `worker_processes + 1` exactly (too many lcores leave queues with no consumer — a silent RSS black hole; too few make worker attach fail with proc_id out of range).
- The master waits up to 60s for the slim primary to become ready (the primary_slim baseline reports measured ~25s for EAL + port init) and up to 60s for worker 0 to confirm its secondary attach; the legacy 15s primary-worker gate stays unchanged when `graceful_reload=0`.
- Reload still follows the legacy two-phase serial order at this stage (old workers exit before new workers start); the actual lossless coexistence arrives with the later milestones.

Failure modes: if the slim primary dies, it is not respawned automatically (primary_slim E10); restart nginx fully (the master re-spawns a fresh slim primary when the stale pidfile no longer points to a live process).

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

