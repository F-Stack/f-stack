# F-Stack Nginx APP Guide

F-Stack is an open source network framework based on DPDK. F-Stack supports standard Nginx as HTTP framework which means all web application based on HTTP can easily use F-Stack.

## How does Nginx use F-Stack?

  Nginx APP is in `app/nginx-1.11.10` directory.

### New nginx module `ngx_ff_module.c`

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

      void ff_mod_init(int argc, char * const *argv) {
        int rc;
    
        #define INIT_FUNCTION(func) \
            real_##func = dlsym(RTLD_NEXT, #func); \
            assert(real_##func)
    
        INIT_FUNCTION(socket);
        INIT_FUNCTION(bind);
        INIT_FUNCTION(connect);
        INIT_FUNCTION(close);
        INIT_FUNCTION(listen);    
        INIT_FUNCTION(setsockopt);
        INIT_FUNCTION(accept);
        INIT_FUNCTION(accept4);
        INIT_FUNCTION(recv);
        INIT_FUNCTION(send);
        INIT_FUNCTION(writev);
        INIT_FUNCTION(write);
        INIT_FUNCTION(read);
        INIT_FUNCTION(readv);
    
        INIT_FUNCTION(ioctl);
        INIT_FUNCTION(select);
    
    #undef INIT_FUNCTION
    
        assert(argc >= 2);
    
        rc = ff_init(argv[1], argc, argv);
        assert(0 == rc);
    
        inited = 1;
    }

Re-implement the network interface with FF API to replace the System network interface. Take socket () as an example, use ff\_socket instead of real\_socket, and return the F-Stack file descriptor. Other APIs refers to module code.

    int socket(int domain, int type, int protocol)
    {
        int rc;
       
        if ((inited == 0) ||  (AF_INET != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type))
        {
            rc = real_socket(domain, type, protocol);
            return rc;
        }
    
        rc = ff_socket(domain, type, protocol);
        if(rc >= 0)
            rc |= 1 << FST_FD_BITS;
    
        return rc;
    }

### Other modifications

 `auto/sources`

Add compiling file

 `auto/make`

Add link lib

 `auto/options`

Add module

`ngx_kqueue_module.c`

kqueue module adapted to F-Stack ff API

## Start Nginx compiling

Configuration needs to include F-Stack `ff_module`

	./configure --prefix=/usr/local/nginx_fstack --with-ff_module
	make
	make install

Notes for Nginx based F-Stack configuration file.

	worker_processes  1; # always be 1

	events {
		worker_connections  102400; # to 102400
		use kqueue; # use kqueue
	}
	
	sendfile off; # sendfile off

Start Nginx with `start.sh`

    ./start.sh -b /usr/local/nginx_fstack/sbin/nginx -c config.ini

 or with the method below. Description of arguments is as bellow,

	#	-c coremask, The primary and secondary processes need to specify the coremask of the individual lcore they want to use, for example, primary process -c 1, secondary -c 2, -c 4, -c 8, -c 10, etc.
	#	--proc-type = primary/secondary primary/secondary
	#	--num-procs = number of process
	#	--proc-id = current process ID, increase from 0
	
	<nginx_dir>/nginx config.ini -c <cmask>  --proc-type=primary --num-procs=<num_procs> --proc-id=<proc_id> # primary process
	<nginx_dir>/nginx config.ini -c <cmask>  --proc-type=secondary --num-procs=<num_procs> --proc-id=<proc_id> # seconary process, if needed

 Other is identical to the standard Nginx.
