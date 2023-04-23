#ifndef _FF_HOOK_SYSCALL_H
#define _FF_HOOK_SYSCALL_H

#undef FF_SYSCALL_DECL
#define FF_SYSCALL_DECL(ret, fn, args) extern ret ff_hook_##fn args
#include <ff_declare_syscalls.h>

extern int kqueue(void);
extern int kevent(int kq, const struct kevent *changelist, int nchanges,
		    struct kevent *eventlist, int nevents, const struct timespec *timeout);

#endif
