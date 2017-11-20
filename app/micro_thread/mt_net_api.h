
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
 *  @file mt_net_api.h
 **/

#ifndef __MT_NET_API_H__
#define __MT_NET_API_H__

#include <netinet/in.h>

namespace NS_MICRO_THREAD {

enum MT_PROTO_TYPE 
{
    NET_PROTO_UNDEF      = 0,
    NET_PROTO_UDP        = 0x1,
    NET_PROTO_TCP        = 0x2
};

enum MT_RC_TYPE 
{
    RC_SUCCESS          = 0,
    RC_ERR_SOCKET       = -1,
    RC_SEND_FAIL        = -2,
    RC_RECV_FAIL        = -3,
    RC_CONNECT_FAIL     = -4,
    RC_CHECK_PKG_FAIL   = -5,
    RC_NO_MORE_BUFF     = -6,
    RC_REMOTE_CLOSED    = -7,

    RC_INVALID_PARAM    = -10,
    RC_INVALID_HANDLER  = -11,
    RC_MEM_ERROR        = -12,
    RC_CONFLICT_SID     = -13,
    RC_KQUEUE_ERROR     = -14,
};

typedef int32_t (*CHECK_SESSION_CALLBACK)(const void* data, uint32_t len,
                                        uint64_t* session_id, uint32_t* need_len);

class CNetHelper
{
public:

    static char* GetErrMsg(int32_t result);

    int32_t SendRecv(void* data, uint32_t len, uint32_t timeout);

    void* GetRspBuff();

    uint32_t GetRspLen();    

    void SetProtoType(MT_PROTO_TYPE type);

    void SetDestAddress(struct sockaddr_in* dst);

    void SetSessionId(uint64_t sid);

    void SetSessionCallback(CHECK_SESSION_CALLBACK function);

    CNetHelper();
    ~CNetHelper();

private:

    void*    handler;
};


}

#endif


