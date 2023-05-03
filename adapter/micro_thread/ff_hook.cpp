
/**
 * Tencent is pleased to support the open source community by making MSEC available.
 *
 * Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.
 *
 * Licensed under the GNU General Public License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. You may 
 * obtain a copy of the License at
 *
 *     https://opensource.org/licenses/GPL-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the 
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdarg.h>
#include "ff_api.h"
#include "mt_sys_hook.h"
#include "ff_hook.h"

int ff_hook_socket(int domain, int type, int protocol)
{
    if ((AF_INET != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type)) {
        return mt_real_func(socket)(domain, type, protocol);
	}
	return ff_socket(domain, type, protocol);
}

int ff_hook_close(int fd)
{
	if (ff_fdisused(fd)) {
		return ff_close(fd);
	} else {
        return mt_real_func(close)(fd);
	}
}

int ff_hook_connect(int fd, const struct sockaddr *address, socklen_t addrlen_len)
{
	if (ff_fdisused(fd)) {
		return ff_connect(fd, (struct linux_sockaddr *)address, addrlen_len);
	} else {
        return mt_real_func(connect)(fd, address, addrlen_len);
	}
}

ssize_t ff_hook_read(int fd, void *buf, size_t nbyte)
{
	if (ff_fdisused(fd)) {
		return ff_read(fd, buf, nbyte);
	} else {
        return mt_real_func(read)(fd, buf, nbyte);
	}
}

ssize_t ff_hook_write(int fd, const void *buf, size_t nbyte)
{
	if (ff_fdisused(fd)) {
		return ff_write(fd, buf, nbyte);
	} else {
        return mt_real_func(write)(fd, buf, nbyte);
	}
}
ssize_t ff_hook_sendto(int fd, const void *message, size_t length, int flags, 
               const struct sockaddr *dest_addr, socklen_t dest_len)
{
	if (ff_fdisused(fd)) {
        return ff_sendto(fd, message, length, flags, (struct linux_sockaddr *)dest_addr, dest_len);
	} else {
        return mt_real_func(sendto)(fd, message, length, flags, dest_addr, dest_len);
	}
}
ssize_t ff_hook_recvfrom(int fd, void *buffer, size_t length, int flags, 
                  struct sockaddr *address, socklen_t *address_len)
{
	if (ff_fdisused(fd)) {
        return ff_recvfrom(fd, buffer, length, flags, (struct linux_sockaddr *)address, address_len);
	} else {
        return mt_real_func(recvfrom)(fd, buffer, length, flags, address, address_len);
	}
}
ssize_t ff_hook_recv(int fd, void *buffer, size_t length, int flags)
{
	if (ff_fdisused(fd)) {
		return ff_recv(fd, buffer, length, flags);
	} else {
        return mt_real_func(recv)(fd, buffer, length, flags);
	}
}
ssize_t ff_hook_send(int fd, const void *buf, size_t nbyte, int flags)
{
	if (ff_fdisused(fd)) {
		return ff_send(fd, buf, nbyte, flags);
	} else {
        return mt_real_func(send)(fd, buf, nbyte, flags);
	}

}
int ff_hook_setsockopt(int fd, int level, int option_name, const void *option_value, socklen_t option_len)
{
	if (ff_fdisused(fd)) {
        return ff_setsockopt(fd, level, option_name, option_value, option_len);
	} else {
        return mt_real_func(setsockopt)(fd, level, option_name, option_value, option_len);
	}
}

int ff_hook_ioctl(int fd, int cmd, void *arg)
{
	if (ff_fdisused(fd)) {
		return ff_ioctl(fd, cmd, arg);
	} else {
        return mt_real_func(ioctl)(fd, cmd, arg);
	}
}

int ff_hook_fcntl(int fd, int cmd, void *arg)
{
	if (ff_fdisused(fd)) {
		return ff_fcntl(fd, cmd, arg);
	} else {
        return mt_real_func(fcntl)(fd, cmd, arg);
	}
}

int ff_hook_listen(int fd, int backlog)
{
	if (ff_fdisused(fd)) {
		return ff_listen(fd, backlog);
	} else {
		return mt_real_func(listen)(fd, backlog);
	}
}

int ff_hook_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (ff_fdisused(fd)) {
		return ff_bind(fd, (struct linux_sockaddr *)addr, addrlen);
	} else {
		return mt_real_func(bind)(fd, addr, addrlen);
	}
}

int ff_hook_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (ff_fdisused(fd)) {
		return ff_accept(fd, (struct linux_sockaddr *)addr, addrlen);
	} else {
		return mt_real_func(accept)(fd, addr, addrlen);
	}
}
