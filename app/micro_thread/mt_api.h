
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


/**
 *  @filename mt_api.h
 */
 
#ifndef __MT_API_H__
#define __MT_API_H__
 
#include <netinet/in.h>
#include <vector>

using std::vector;

namespace NS_MICRO_THREAD {

int mt_udpsendrcv(struct sockaddr_in* dst, void* pkg, int len, void* rcv_buf, int& buf_size, int timeout);

typedef int (*MtFuncTcpMsgLen)(void* buf, int len);

int mt_tcpsendrcv(struct sockaddr_in* dst, void* pkg, int len, void* rcv_buf, int& buf_size, 
                  int timeout, MtFuncTcpMsgLen chek_func);


enum MT_TCP_CONN_TYPE
{
    MT_TCP_SHORT         = 1,
    MT_TCP_LONG          = 2,
    MT_TCP_SHORT_SNDONLY = 3,
    MT_TCP_LONG_SNDONLY  = 4,
    MT_TCP_BUTT
};

int mt_tcpsendrcv_ex(struct sockaddr_in* dst, void* pkg, int len, void* rcv_buf, int* buf_size,
                     int timeout, MtFuncTcpMsgLen func, MT_TCP_CONN_TYPE type = MT_TCP_LONG);

typedef int (*MtFuncTcpMsgChecker)(void* buf, int len, bool closed, void* msg_ctx, bool &msg_len_detected);


int mt_tcpsendrcv_ex(struct sockaddr_in* dst, void* pkg, int len, void*& rcv_buf, int& recv_pkg_size, 
                     int timeout, MtFuncTcpMsgChecker check_func, void* msg_ctx=NULL, 
                     MT_TCP_CONN_TYPE type = MT_TCP_LONG, bool keep_rcv_buf=false);


int mt_tcpsendrcv(struct sockaddr_in* dst, void* pkg, int len, void*& rcv_buf, int& recv_pkg_size, 
                     int timeout, MtFuncTcpMsgChecker check_func, void* msg_ctx=NULL, bool keep_rcv_buf=false);


class IMtTask
{
public:

    virtual int Process() { return -1; };

    void SetResult(int rc)
    {
        _result = rc;
    }

    int GetResult(void)
    {
        return _result;
    }

    void SetTaskType(int type)
    {
        _type = type;
    }

    int GetTaskType(void)
    {
        return _type;
    }
 
    IMtTask() {};
    virtual ~IMtTask() {};

protected:

    int _type;
    int _result;
};

typedef vector<IMtTask*>  IMtTaskList;

int mt_exec_all_task(IMtTaskList& req_list);

void mt_sleep(int ms);

unsigned long long mt_time_ms(void);

void mt_set_msg_private(void *data);

void* mt_get_msg_private();

bool mt_init_frame(int argc=0, char * const argv[]=NULL);

void mt_set_stack_size(unsigned int bytes);

int mt_recvfrom(int fd, void *buf, int len, int flags, struct sockaddr *from, socklen_t *fromlen, int timeout);

int mt_sendto(int fd, const void *msg, int len, int flags, const struct sockaddr *to, int tolen, int timeout);

int mt_connect(int fd, const struct sockaddr *addr, int addrlen, int timeout);

int mt_accept(int fd, struct sockaddr *addr, socklen_t *addrlen, int timeout);

ssize_t mt_read(int fd, void *buf, size_t nbyte, int timeout);

ssize_t mt_write(int fd, const void *buf, size_t nbyte, int timeout);

ssize_t mt_recv(int fd, void *buf, int len, int flags, int timeout);

ssize_t mt_send(int fd, const void *buf, size_t nbyte, int flags, int timeout);

int mt_wait_events(int fd, int events, int timeout);

void* mt_start_thread(void* entry, void* args);

void* mt_active_thread();

void mt_thread_wait(int ms);

void mt_thread_wakeup_wait(void * thread_p);

void mt_swap_thread();

}

#endif

 
