
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


#ifndef __FF_HOOK_H__
#define __FF_HOOK_H__

#include <stdint.h>

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

#endif

