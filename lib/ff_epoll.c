#include <sys/param.h>
#include <sys/limits.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/event.h>
#include <sys/kernel.h>
#include <sys/refcount.h>
#include <sys/sysctl.h>
#include <sys/pcpu.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/event.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ttycom.h>
#include <sys/filio.h>
#include <sys/sysproto.h>
#include <sys/fcntl.h>
#include <machine/stdarg.h>

#include "ff_api.h"
#include "ff_epoll.h"
#include "ff_errno.h"
#include "ff_host_interface.h"



int
ff_epoll_create(int size __attribute__((__unused__)))
{
	return ff_kqueue();
}


int 
ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	if (!event && op != EPOLL_CTL_DEL) {
        ff_os_errno(ff_EINVAL);
		return -1;
	}

	struct kevent kev[3];
	if (op == EPOLL_CTL_ADD){
		EV_SET(&kev[0], fd, EVFILT_READ,
			EV_ADD | (event->events & EPOLLIN ? 0 : EV_DISABLE), 0, 0, NULL);
		EV_SET(&kev[1], fd, EVFILT_WRITE,
			EV_ADD | (event->events & EPOLLOUT ? 0 : EV_DISABLE), 0, 0, NULL);
		EV_SET(&kev[2], fd, EVFILT_USER, EV_ADD,
			    event->events & EPOLLRDHUP ? 1 : 0, 0, NULL);		
	} else if (op == EPOLL_CTL_DEL) {
		EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
		EV_SET(&kev[2], fd, EVFILT_USER, EV_DELETE, 0, 0, NULL);
	} else if (op == EPOLL_CTL_MOD) {
		EV_SET(&kev[0], fd, EVFILT_READ,
		    event->events & EPOLLIN ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
		EV_SET(&kev[1], fd, EVFILT_WRITE,
		    event->events & EPOLLOUT ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
		EV_SET(&kev[2], fd, EVFILT_USER, 0,
		    NOTE_FFCOPY | (event->events & EPOLLRDHUP ? 1 : 0), 0, NULL);		
	} else {
		ff_os_errno(ff_EINVAL);
		return -1;
	}

	return ff_kevent(epfd, kev, 3, NULL, 0, NULL);
}

int 
ff_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	if (!events || maxevents < 1) {
		ff_os_errno(ff_EINVAL);
		return -1;
	}
	
	struct kevent *evlist = malloc(sizeof(struct kevent)*maxevents, M_DEVBUF, M_ZERO|M_NOWAIT);
	if(NULL == evlist){
		ff_os_errno(ff_EINVAL);
		return -1;		
	}
	memset(evlist, 0, sizeof(struct kevent)*maxevents);
	
	int ret = ff_kevent(epfd, NULL, 0, evlist, maxevents, NULL);
	if (ret == -1) {
		free(evlist, M_DEVBUF);
		return ret;
	}

	unsigned int event_one = 0;
	for (int i = 0; i < ret; ++i) {
		event_one = 0;
		if (evlist[i].filter & EVFILT_READ) {
			event_one |= EPOLLIN;
		} 
		if (evlist[i].filter & EVFILT_WRITE) {
			event_one |= EPOLLOUT;
		}

		if (evlist[i].flags & EV_ERROR) {
			event_one |= EPOLLERR;
		}

		if (evlist[i].flags & EV_EOF) {
			event_one |= EPOLLIN;		
		}
		events[i].events   = event_one;
		events[i].data.fd  = evlist[i].ident;
	}
	
	free(evlist, M_DEVBUF);
	return ret;
}

int 
ff_epoll_close(int epfd)
{
	return ff_close(epfd);
}

