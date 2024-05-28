#ifndef _FF_LINUX_SYSCALL_H_
#define _FF_LINUX_SYSCALL_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>

#undef FF_SYSCALL_DECL
#define FF_SYSCALL_DECL(ret, fn, args) ret ff_linux_##fn args
#include "ff_declare_syscalls.h"

#endif
