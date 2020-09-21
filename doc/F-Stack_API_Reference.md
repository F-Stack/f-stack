# F-Stack API Reference

F-Stack (FF) is a high-performance network framework based on DPDK.

FF API provides the standard Kqueue/Epoll interface, and a micro threading framework (SPP).

In order to facilitate a variety of services to use F-Stack simpler and faster, F-Stack has been integrated with Nginx and Redis。

## FF API

The header file ff_api.h defines the following API, which should be used to replace the system calls when using F-Stack.

### Initialize

#### ff_init

	int ff_init(const char *conf, int argc, char * const argv[]);
	conf:Profile path
	argv：-c <coremask>,the coremask parameters can cover the coremask in configuration file

Initialize F-Stack，including DPDK/FreeBSD network stack, etc.

#### ff_run

	void ff_run(loop_func_t loop, void *arg);
loop is a callback function，the service logic is implemented by the user, and called by each poll of F-Stack .

### Control API

#### ff_fcntl

	int ff_fcntl(int fd, int cmd, ...);

 fcntl() performs one of the operations described below on the open file descriptor fd.  The operation is determined by cmd.
more info see man fcntl.

#### ff_sysctl

	int ff_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
	const void *newp, size_t newlen);

 ff_sysctl is used to modify kernel parameters at runtime.
However, it is  supported only before F-Stack is started.

#### ff_ioctl

	int ff_ioctl(int fd, unsigned long request, ...);

  The ioctl() function manipulates the underlying device parameters of special files.
  more info see man ioctl.

### Network API

#### ff_socket

	int ff_socket(int domain, int type, int protocol);

  ff_socket creates an endpoint for communication and returns a file descriptor that refers to that endpoint.
  more info see man socket.

#### ff_setsockopt & ff_getsockopt

	int ff_getsockopt(int s, int level, int optname, void *optval,
	socklen_t *optlen);
	int ff_setsockopt(int s, int level, int optname, const void *optval,
	socklen_t optlen);

  getsockopt() and setsockopt() manipulate options for the socket denoted by the file descriptor sockfd.
  more info see man getsockopt and man setsockopt.

#### ff_socketpair

	int ff_socketpair(int domain, int type, int protocol, int *sv);

  The socketpair() call creates an unnamed pair of connected sockets in the given domain in the specified type, and uses the optionally given protocol.
  more info see man socketpair.

#### Socket operation function

	int ff_listen(int s, int backlog);
	int ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen);
	int ff_accept(int s, struct linux_sockaddr *addr, socklen_t *addrlen);
	int ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen);
	int ff_close(int fd);
	int ff_shutdown(int s, int how);

  Socket operation function, more info see Linux Programmer's Manual.

#### ff_getpeername

	int ff_getpeername(int s, struct linux_sockaddr *name, socklen_t *namelen);

  ff_getpeername() returns the address of the peer connected to the socket sockfd, in the buffer pointed to by addr.
  more info see man getpeername.

#### ff_getsockname

	int ff_getsockname(int s, struct linux_sockaddr *name,
	socklen_t *namelen);

  ff_getsockname() returns the current address to which the socket sockfd is bound, in the buffer pointed to by addr.
  more info see man getsockname.

#### ff\_read & ff\_readv

	ssize_t ff_read(int d, void *buf, size_t nbytes);
	ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt);

  read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
  more info see man read and man readv.

#### ff\_write & ff\_writev

	ssize_t ff_write(int fd, const void *buf, size_t nbytes);
	ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt);

  write() writes up to count bytes from the buffer pointed buf to the file referred to by the file descriptor fd.
  more info see man write and man readv.

#### ff\_send & ff\_sendto & ff\_sendmsg

	ssize_t ff_send(int s, const void *buf, size_t len, int flags);
	ssize_t ff_sendto(int s, const void *buf, size_t len, int flags, const struct linux_sockaddr *to, socklen_t tolen);
	ssize_t ff_sendmsg(int s, const struct msghdr *msg, int flags);

 Functions to send a message on a socket.
  more info see man send.

#### ff\_recv & ff\_recvfrom & ff\_recvmsg

	ssize_t ff_recv(int s, void *buf, size_t len, int flags);
	ssize_t ff_recvfrom(int s, void *buf, size_t len, int flags, struct linux_sockaddr *from, socklen_t *fromlen);
	ssize_t ff_recvmsg(int s, struct msghdr *msg, int flags);

  Functions to receive a message from a socket.
  more info see man recv.

#### ff_select

	int ff_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);

  select() allow a program to monitor multiple file descriptors, waiting until one or more of the file descriptors become "ready" for some class of I/O operation (e.g., input possible).
  more info see man select.

#### ff_poll

	int ff_poll(struct pollfd fds[], nfds_t nfds, int timeout);

  ff_poll waits for events on a file descriptor.
  more info see man poll.

### Kqueue API

#### ff_kqueue

	int ff_kqueue(void);
	int ff_kevent(int kq, const struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, const struct timespec *timeout);

  The kqueue() system call provides a generic method of notifying the user when an event occurs or a condition holds, based on the results of small pieces of kernel code termed filters.
  more info see man kqueue on FreeBSD System Calls Manual.

### Epoll API

#### ff\_epoll\_create

	int ff_epoll_create(int size);

  epoll_create() returns a file descriptor referring to the new epoll instance.
  more info see man epoll_create.

#### ff\_epoll\_ctl

	int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

  This system call performs control operations on the epoll(7) instance referred by the file descriptor epfd.
  more info see man epoll_ctl.

### Micro Thread API `micro_thread/mt_api.h`

  In order to develop asynchronous program convenient without complex asynchronous logic processing (reference [SPP's micro thread framework](https://github.com/Tencent/MSEC/tree/master/spp_rpc)), F-Stack provides a micro thread framework so that synchronous programming can be achieved using asynchronous calls.

#### UDP send/recv interface

    int mt_udpsendrcv(struct sockaddr_in* dst, void* pkg, int len, void* rcv_buf, int& buf_size, int timeout);

  Use Random socket port to send and recv udp packet.
  

#### tcp send/recv interface
​    
    int mt_tcpsendrcv(struct sockaddr_in* dst, void* pkg, int len, void* rcv_buf, int& buf_size, int timeout, MtFuncTcpMsgLen chek_func);

  Use connection pool to send and recv tcp packet, keep-alive default are 10 mintues. The parameter of buf can't use `static`.
​    

    enum MT_TCP_CONN_TYPE
    {
        MT_TCP_SHORT         = 1,
        MT_TCP_LONG          = 2,
        MT_TCP_SHORT_SNDONLY = 3,
        MT_TCP_LONG_SNDONLY  = 4,
        MT_TCP_BUTT
    };
    
    int mt_tcpsendrcv_ex(struct sockaddr_in* dst, void* pkg, int len, void* rcv_buf, int* buf_size, int timeout, MtFuncTcpMsgLen func, MT_TCP_CONN_TYPE type = MT_TCP_LONG);
    
  TCP send and recv interface, you can choose if the connection is keep-alive or close.The parameter of buf can't use `static`.


    int mt_tcpsendrcv_ex(struct sockaddr_in* dst, void* pkg, int len, void*& rcv_buf, int& recv_pkg_size, int timeout, MtFuncTcpMsgChecker check_func, void* msg_ctx=NULL, MT_TCP_CONN_TYPE type = MT_TCP_LONG, bool keep_rcv_buf=false);

  Tcp send and recv interface, you can choose if the connection is keep-alive or close.The parameter of buf can't use `static`.
​    

    int mt_tcpsendrcv(struct sockaddr_in* dst, void* pkg, int len, void*& rcv_buf, int& recv_pkg_size, int timeout, MtFuncTcpMsgChecker check_func, void* msg_ctx=NULL, bool keep_rcv_buf=false);


  Use connection pool to send and recv tcp packet, keep-alive default are 10 mintues. The parameter of buf can't use `static`.

#### Socket API for micro threads

  see `micro_thread/mt_api.h`.

### Dispatch API

 Packet dispatch callback function, implemented by user.

	typedef int (*dispatch_func_t)(void *data, uint16_t *len, uint16_t queue_id, uint16_t nb_queues);

	void ff_regist_packet_dispatcher(dispatch_func_t func);

  Regist a packet dispath function.

#### param

 - data
   The data pointer of this packet.
 - len
   The length of this packet.
 - queue_id
   Current queue of this packet.
 - nb_queues
   Number of queues to be dispatched.

#### return

 - 0 to (nb_queues - 1)
   The queue id that the packet will be dispatched to.
 - FF_DISPATCH_ERROR (-1)
   Error occurs or packet is handled by user, packet will be freed.
 - FF_DISPATCH_RESPONSE (-2)
   Packet is handled by user, packet will be responsed.
