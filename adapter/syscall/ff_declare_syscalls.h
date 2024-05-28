FF_SYSCALL_DECL(int, socket, (int, int, int));
FF_SYSCALL_DECL(int, bind, (int, const struct sockaddr *, socklen_t));
FF_SYSCALL_DECL(int, listen, (int, int));
FF_SYSCALL_DECL(int, shutdown, (int, int));
FF_SYSCALL_DECL(int, getsockname, (int, struct sockaddr *, socklen_t *));
FF_SYSCALL_DECL(int, getpeername, (int, struct sockaddr *, socklen_t *));
FF_SYSCALL_DECL(int, getsockopt, (int, int, int, void *, socklen_t *));
FF_SYSCALL_DECL(int, setsockopt, (int, int, int, const void *, socklen_t));
FF_SYSCALL_DECL(int, accept, (int, struct sockaddr *, socklen_t *));
FF_SYSCALL_DECL(int, accept4,(int, struct sockaddr *, socklen_t *, int flags));
FF_SYSCALL_DECL(int, connect, (int, const struct sockaddr *, socklen_t));
FF_SYSCALL_DECL(ssize_t, recv, (int, void *, size_t, int));
FF_SYSCALL_DECL(ssize_t, send, (int, const void *, size_t, int));
FF_SYSCALL_DECL(ssize_t, read, (int, void *, size_t));
FF_SYSCALL_DECL(ssize_t, write, (int, const void *, size_t));
FF_SYSCALL_DECL(ssize_t, writev, (int, const struct iovec *, int));
FF_SYSCALL_DECL(ssize_t, readv, (int, const struct iovec *, int));
FF_SYSCALL_DECL(ssize_t, sendto, (int, const void *, size_t, int,
    const struct sockaddr *, socklen_t));
FF_SYSCALL_DECL(ssize_t, recvfrom, (int, void *, size_t, int,
    struct sockaddr *, socklen_t *));
FF_SYSCALL_DECL(ssize_t, sendmsg, (int, const struct msghdr *, int flags));
FF_SYSCALL_DECL(ssize_t, recvmsg, (int, struct msghdr *, int flags));
FF_SYSCALL_DECL(int, close, (int));
FF_SYSCALL_DECL(int, ioctl, (int, unsigned long, unsigned long));
FF_SYSCALL_DECL(int, fcntl, (int, int, unsigned long));
FF_SYSCALL_DECL(int, epoll_create, (int));
FF_SYSCALL_DECL(int, epoll_ctl, (int, int, int, struct epoll_event *));
FF_SYSCALL_DECL(int, epoll_wait, (int, struct epoll_event *, int, int));
FF_SYSCALL_DECL(pid_t, fork, (void));
#undef FF_SYSCALL_DECL
