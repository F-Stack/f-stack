#ifndef _FF_ADAPTER_H
#define _FF_ADAPTER_H

/* socket.h */
//#define	SOCK_CLOEXEC	0x10000000
//#define	SOCK_NONBLOCK	0x20000000
#define SOCK_FSTACK 0x01000000
#define SOCK_KERNEL 0x02000000

int ff_adapter_init();
//int __attribute__((constructor)) ff_adapter_init(int argc, char * const argv[]);

void alarm_event_sem();

/*-
 * Verify whether the socket is supported by fstack or not.
 */
int fstack_territory(int domain, int type, int protocol);

/* Tell whether a 'sockfd' belongs to fstack. */
int is_fstack_fd(int fd);

#endif
