# F-Stack Microthread APP Guide

F-Stack is an open source network framework based on DPDK. F-Stack has integrated the microthread framework in [SPP_RPC](https://github.com/Tencent/MSEC/tree/master/spp_rpc/src/sync_frame/micro_thread) of MSEC. Applications only need to focus on the service logic. APPs can obtain high-performance asynchronous service server with synchronous programming.

## How does F-Stack support microthread?

  Microthread framework is in `app/micro_thread` directory.

### New module `ff_hook.cpp` `ff_hook.h`

Hook operation of Network IO interface , the transformation of the ff socket, in order to distinguish from regular file descriptor.

First, define network interface functions.

    void ff_hook_new_fd(int fd);
    bool ff_hook_find_fd(int fd);
    
    void ff_hook_free_fd(int fd);
    int ff_hook_socket(int domain, int type, int protocol);
    int ff_hook_close(int fd);
    
    int ff_hook_connect(int fd, const struct sockaddr *address, socklen_t addrlen_len);
    
    ssize_t ff_hook_read(int fd, void *buf, size_t nbyte);
    
    ssize_t ff_hook_write(int fd, const void *buf, size_t nbyte);
    ssize_t ff_hook_sendto(int fd, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
    ssize_t ff_hook_recvfrom(int fd, void *buffer, size_t length, int flags, struct sockaddr *address, socklen_t *address_len);
    ssize_t ff_hook_recv(int fd, void *buffer, size_t length, int flags);
    ssize_t ff_hook_send(int fd, const void *buf, size_t nbyte, int flags);
    int ff_hook_setsockopt(int fd, int level, int option_name, const void *option_value, socklen_t option_len);
    int ff_hook_ioctl(int fd, int cmd, void *arg);
    
    int ff_hook_fcntl(int fd, int cmd, void *arg);
    
    int ff_hook_listen(int fd, int backlog);
    
    int ff_hook_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);
    int ff_hook_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);

Re-implement the network interface with FF API to replace the System network interface. Take socket () as an example, use ff_socket instead of real_socket, and return the F-Stack file descriptor. Other APIs refers to module code.

    int ff_hook_socket(int domain, int type, int protocol)
    {
        if (!ff_hook_active() ||  (AF_INET != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type)) {
            return mt_real_func(socket)(domain, type, protocol);
    	}
    	int fd = ff_socket(domain, type, protocol);
    	if (fd >= 0) {
    		fd |= 1 << FF_FD_BITS;
    	}
    	return fd;
    }

### Replace module `epoll_proxy.cpp` with `kqueue_proxy.cpp`

  Replace read/write event of epoll  with ff_kqueue, ff_event interface.

### Other modifications

`Makefile`

  1. Add F-Stack development library, libfstack.a
  2. Microthread framework library libmt.a has already included libfstack.a

## Guide of microthread framework usage

 `echo.cpp` is the demo of microthread framework. Simply refer to source code, interfaces are easy to use.

First initialize F-Stack microthread framework, next enter the interface of your own service logic and call microthread API provided by F-Stack for network operation. This will allow synchronous programming with asynchronous execution.  Main code is showed below.

    void echo(void *arg)
    {
    	int ret;
    	int *p = (int *)arg;
    	int clt_fd = *p;
    	delete p;
    	char buf[64 * 1024];
    	while (true) {
    		ret = mt_recv(clt_fd, (void *)buf, 64 * 1024, 0, -1);
    		if (ret < 0) {
    			printf("recv from client error\n");
    			break;
    		}
    		ret = mt_send(clt_fd, (void *)buf, ret, 0, 1000);
    		if (ret < 0) {
    			//printf("send data to client error\n");
    			break;
    		}
    	}
    	close(clt_fd);
    }
    
    int echo_server()
    {
    	struct sockaddr_in addr;
    	addr.sin_family = AF_INET;
    	addr.sin_addr.s_addr = INADDR_ANY;
    	addr.sin_port = htons(80);
    
    	int fd = create_tcp_sock();
    	if (fd < 0) {
    		fprintf(stderr, "create listen socket failed\n");
    		return -1;
    	}
    
    	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    		close(fd);
    		fprintf(stderr, "bind failed [%m]\n");
    		return -1;
    	}
    
    	if (listen(fd, 1024) < 0) {
    		close(fd);
    		fprintf(stderr, "listen failed [%m]\n");
    		return -1;
    	}
        int clt_fd = 0;
    	int *p;
    	while (true) {
    		struct sockaddr_in client_addr;
    		int addr_len = sizeof(client_addr);
    
            clt_fd = mt_accept(fd, (struct sockaddr*)&client_addr, (socklen_t*)&addr_len, -1);
    		if (clt_fd < 0) {
    			mt_sleep(1);
    			continue;
    		}
    		if (set_fd_nonblock(clt_fd) == -1) {
    			fprintf(stderr, "set clt_fd nonblock failed [%m]\n");
    			break;
    		}
    
    		p = new int(clt_fd);
    		mt_start_thread((void *)echo, (void *)p);
    	}
    	return 0;
    }
    
    int main(int argc, char *argv[])
    {
    	mt_init_frame("./config.ini", argc, argv);
    	echo_server();
    }
