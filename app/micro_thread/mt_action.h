
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

#ifndef __MT_ACTION_H__
#define __MT_ACTION_H__

#include <netinet/in.h>
#include <queue>
#include "mt_msg.h"
#include "mt_session.h"
#include "mt_notify.h"

namespace NS_MICRO_THREAD {


enum MULTI_STATE 
{
    MULTI_FLAG_UNDEF   = 0x0,
    MULTI_FLAG_INIT    = 0x1,
    MULTI_FLAG_OPEN    = 0x2,
    MULTI_FLAG_SEND    = 0x4,
    MULTI_FLAG_FIN     = 0x8,
};

enum MULTI_CONNECT 
{
    CONN_UNKNOWN        = 0,
    CONN_TYPE_SHORT     = 0x1,
    CONN_TYPE_LONG      = 0x2,
    CONN_TYPE_SESSION   = 0x4,
};

enum MULTI_ERROR 
{
    ERR_NONE            =  0,          
    ERR_SOCKET_FAIL     = -1,
    ERR_CONNECT_FAIL    = -2,
    ERR_SEND_FAIL       = -3,
    ERR_RECV_FAIL       = -4,
    ERR_RECV_TIMEOUT    = -5,
    ERR_KQUEUE_FAIL     = -6,
    ERR_FRAME_ERROR     = -7,
    ERR_PEER_CLOSE      = -8,
    ERR_PARAM_ERROR     = -9,
    ERR_MEMORY_ERROR    = -10,
    ERR_ENCODE_ERROR    = -11,
    ERR_DST_ADDR_ERROR  = -12,
};


class IMtAction : public ISession
{
public:

    IMtAction();
    virtual ~IMtAction();

    void SetMsgDstAddr(struct sockaddr_in* dst) {
        memcpy(&_addr, dst, sizeof(_addr));
    };

    struct sockaddr_in* GetMsgDstAddr() {
        return &_addr;
    };

    void SetMsgBuffSize(int buff_size) {
        _buff_size = buff_size;
    };

    int GetMsgBuffSize()     {
        return (_buff_size > 0) ? _buff_size : 65535;
    }     

    void SetSessionName(int name) {
        _ntfy_name = name;
    };

    int GetSessionName()     {
        return _ntfy_name;
    }     

    void SetProtoType(MULTI_PROTO proto) {
        _proto = proto;
    };

    MULTI_PROTO GetProtoType() {
        return _proto;
    };

    void SetConnType(MULTI_CONNECT type) {
        _conn_type = type;
    };

    MULTI_CONNECT GetConnType() {
        return _conn_type;
    };     

    void SetErrno(MULTI_ERROR err) {
        _errno = err; 
    };

    MULTI_ERROR GetErrno() {
        return _errno;
    };     

    void SetCost(int cost) {
        _time_cost = cost;
    };

    int GetCost() {
        return _time_cost;
    }; 

    void SetMsgFlag(MULTI_STATE flag) {
        _flag = flag;
    };

    MULTI_STATE GetMsgFlag() {
        return _flag;
    };

    void SetIMsgPtr(IMtMsg* msg  ) {
        _msg = msg;
    };

    IMtMsg* GetIMsgPtr() {
        return _msg;
    };

    void SetIConnection(IMtConnection* conn) {
        _conn = conn;
    };

    IMtConnection* GetIConnection() {
        return _conn;
    };

    void Init();

    void Reset();

    KqueuerObj* GetNtfyObj();

    int InitConnEnv();

    int DoEncode();
    int DoInput();
    int DoProcess();
    int DoError();

public:

    virtual int HandleEncode(void* buf, int& len, IMtMsg* msg){return 0;};

    virtual int HandleInput(void* buf, int len, IMtMsg* msg){return 0;};

    virtual int HandleProcess(void* buf, int len, IMtMsg* msg){return 0;};

    virtual int HandleError(int err, IMtMsg* msg){return 0;};


protected:

    MULTI_STATE         _flag;
    MULTI_PROTO         _proto;
    MULTI_CONNECT       _conn_type;
    MULTI_ERROR         _errno;
    struct sockaddr_in  _addr;
    int                 _time_cost;
    int                 _buff_size;
    int                 _ntfy_name;

    IMtMsg*             _msg;
    IMtConnection*      _conn;
};

}

#endif

