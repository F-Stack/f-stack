#include <sys/cdefs.h>
#ifndef FSTACK
__FBSDID("$FreeBSD$");

#include "namespace.h"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#ifndef FSTACK
#include "un-namespace.h"
#endif

char *
if_indextoname(unsigned int ifindex, char *ifname)
{
	struct ifaddrs *ifaddrs, *ifa;
	int error = 0;

	if (ifindex == 0) {
		errno = ENXIO;
		return(NULL);
	}

	if (getifaddrs(&ifaddrs) < 0)
		return(NULL);	/* getifaddrs properly set errno */

	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr &&
		    ifa->ifa_addr->sa_family == AF_LINK &&
		    ifindex == LLINDEX((struct sockaddr_dl*)ifa->ifa_addr))
			break;
	}

	if (ifa == NULL) {
		error = ENXIO;
		ifname = NULL;
	}
	else
		strncpy(ifname, ifa->ifa_name, IFNAMSIZ);

	freeifaddrs(ifaddrs);

	errno = error;
	return(ifname);
}

