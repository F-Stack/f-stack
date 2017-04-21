# F-Stack Redis APP Guide
F-Stack is an open source network framework based on DPDK. F-Stack supports standard Redis which means all applications with key-value pair model can easily use F-Stack.
## How does Redis use F-Stack?
    Nginx APP is in `app/redis-3.2.8` directory.
### New redis module ``anet_ff.c``, `anet_ff.h`

Hook operation of Network IO interface , the transformation of the ff socket, in order to distinguish from regular file descriptor.
First, define network interface functions.
    static int (*real_close)(int);
    static int (*real_socket)(int, int, int);
    static int (*real_bind)(int, const struct sockaddr*, socklen_t);
    static int (*real_connect)(int, const struct sockaddr*, socklen_t);
    static int (*real_listen)(int, int);
    static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
    
    static int (*real_accept)(int, struct sockaddr *, socklen_t *);
    static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
    static ssize_t (*real_recv)(int, void *, size_t, int);
    static ssize_t (*real_send)(int, const void *, size_t, int);
    
    static ssize_t (*real_writev)(int, const struct iovec *, int);
    static ssize_t (*real_write)(int, const void *, size_t );
    static ssize_t (*real_read)(int, void *, size_t );
    static ssize_t (*real_readv)(int, const struct iovec *, int);
    
    static int (*real_ioctl)(int, int, void *);
    
    static int (*real_select) (int, fd_set *, fd_set *, fd_set *, struct timeval *);
Initialize the F-Stack module, hook network interface functions, using our interface to replace the System Interface. Initialize F-Stack.
    void fst_mod_init(int argc, char * const *argv) {        int rc;            #define INIT_FUNCTION(func) \            real_##func = dlsym(RTLD_NEXT, #func); \            assert(real_##func)            INIT_FUNCTION(socket);        INIT_FUNCTION(bind);        INIT_FUNCTION(connect);        INIT_FUNCTION(close);        INIT_FUNCTION(listen);            INIT_FUNCTION(setsockopt);        INIT_FUNCTION(accept);        INIT_FUNCTION(accept4);        INIT_FUNCTION(recv);        INIT_FUNCTION(send);        INIT_FUNCTION(writev);        INIT_FUNCTION(write);        INIT_FUNCTION(read);        INIT_FUNCTION(readv);            INIT_FUNCTION(ioctl);        INIT_FUNCTION(select);        #undef INIT_FUNCTION            assert(argc >= 2);            rc = ff_init(argv[1], argc, argv);        assert(0 == rc);            inited = 1;    }

Re-implement the network interface with FF API to replace the System network interface. Take socket () as an example, use ff_socket instead of real_socket, and return the F-Stack file descriptor. Other APIs refers to module code.
    int socket(int domain, int type, int protocol)    {        int rc;               if ((inited == 0) ||  (AF_INET != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type))        {            rc = real_socket(domain, type, protocol);            return rc;        }            rc = ff_socket(domain, type, protocol);        if(rc >= 0)            rc |= 1 << FST_FD_BITS;            return rc;    }
### New redis module `ae_ff_kqueue.c`
Mainly identical to  `ae_kqueue.c` , just use ff API instead.
### Other modifications
`config.h`
disable setproctitle
    #ifndef HAVE_FF_KQUEUE
    #if ((defined __linux && defined(__GLIBC__)) || defined __APPLE__)
    #define USE_SETPROCTITLE
    #define INIT_SETPROCTITLE_REPLACEMENT
    void spt_init(int argc, char *argv[]);
    void setproctitle(const char *fmt, ...);
    #endif
    #endif

`ae.c`
  1. Prior use ff_kqueue
  2. File descriptor converted between F-Stack and Linux systems
  3. Main loop function of Redis is an argument of ff_run which means the loop function will be executed by ff_run.
`anet.c`
Modify the method of setting block/nonblock for ff socket in ``anetSetBlock`` .
`server.c`
1.  Add ff related head files
2.  FF initial operation in ``main`` function
3.  Call ff_run
`Makefile`
Add F-Stack related libraries and compilation options.
    FINAL_CFLAGS+= -DHAVE_FF_KQUEUE
    FINAL_CFLAGS+= -I$(FF_PATH)/lib

    FINAL_LIBS+= -L$(FF_PATH)/lib -L$(FF_DPDK) -Wl,--whole-archive,-lfstack,--no-whole-archive
    FINAL_LIBS+= -g -Wl,--no-as-needed -fvisibility=default -pthread -lm -lrt
    FINAL_LIBS+= -Wl,--whole-archive -lrte_pmd_vmxnet3_uio -lrte_pmd_i40e -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring
    FINAL_LIBS+= -Wl,--whole-archive -lrte_hash -lrte_kvargs -Wl,-lrte_mbuf -lethdev -lrte_eal -Wl,-lrte_mempool
    FINAL_LIBS+= -lrte_ring -lrte_cmdline -lrte_cfgfile -lrte_kni -lrte_timer -Wl,-lrte_pmd_virtio
    FINAL_LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lm -lcrypto
    ....
    REDIS_SERVER_OBJ=adlist.o quicklist.o ae.o anet.o  ...
    REDIS_CLI_OBJ=anet.o adlist.o redis-cli.o zmalloc.o release.o anet.o anet_ff.o ae.o crc64.o
    REDIS_BENCHMARK_OBJ=ae.o anet.o anet_ff.o redis-benchmark.o adlist.o zmalloc.o redis-benchmark.o
`Makefile.dep`
    ...
    ae.o: ae.c ae.h zmalloc.h config.h ae_kqueue.c ae_epoll.c ae_select.c ae_evport.c ae_ff_kqueue.c
    ae_ff_kqueue.o: ae_ff_kqueue.c
    anet_ff.o: anet_ff.c anet_ff.h
    ...
    server.o: server.c server.h fmacros.h config.h solarisfixes.h \
     ../deps/lua/src/lua.h ../deps/lua/src/luaconf.h ae.h sds.h dict.h \
     adlist.h zmalloc.h anet.h ziplist.h intset.h version.h util.h latency.h \
     sparkline.h quicklist.h zipmap.h sha1.h endianconv.h crc64.h rdb.h rio.h \
     cluster.h slowlog.h bio.h asciilogo.h anet_ff.h
## Start Redis Compiling
	make
	make install
Start Redis with start.sh or with the method below. Description of arguments is as bellow,

	#	-c coremask, The primary and secondary processes need to specify the coremask of the individual lcore they want to use, for example, primary process -c 1, secondary -c 2, -c 4, -c 8, -c 10, etc.
	# --proc-type = primary/secondary
	#	--num-procs = number of process
	#	--proc-id = current process ID, increase from 0
	<nginx_dir>/redis-server config.ini -c <cmask>  --proc-type=primary --num-procs=<num_procs> --proc-id=<proc_id> # primary instance of single/multi instance
	<nginx_dir>/redis-server config.ini -c <cmask>  --proc-type=secondary --num-procs=<num_procs> --proc-id=<proc_id> # secondary instance or multi instance
Other is identical to the standard Redis.
