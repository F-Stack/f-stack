
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
 *  @file mt_connection.h
 *  @time 20130924
 **/

#ifndef __MT_CONNECTION_H__
#define __MT_CONNECTION_H__

#include <netinet/in.h>
#include <queue>
#include "mt_mbuf_pool.h"
#include "hash_list.h"
#include "mt_action.h"

namespace NS_MICRO_THREAD {

using std::queue;

enum CONN_OBJ_TYPE
{
    OBJ_CONN_UNDEF     = 0,
    OBJ_SHORT_CONN     = 1,
    OBJ_TCP_KEEP       = 2,
    OBJ_UDP_SESSION    = 3,
};

class IMtConnection
{
public:

    IMtConnection();
    virtual ~IMtConnection();

    virtual void Reset();

    CONN_OBJ_TYPE GetConnType() {
        return _type;    
    };

    void SetIMtActon(IMtAction* action  ) {
        _action = action;
    };

    IMtAction* GetIMtActon() {
        return _action;
    };

    void SetNtfyObj(KqueuerObj* obj  ) {
        _ntfy_obj = obj;
    };

    KqueuerObj* GetNtfyObj() {
        return _ntfy_obj;
    };
    
    void SetMtMsgBuff(MtMsgBuf* msg_buf) {
        _msg_buff = msg_buf;
    };

    MtMsgBuf* GetMtMsgBuff() {
        return _msg_buff;
    };   

public:

    virtual int CreateSocket() {return 0;};

    virtual int OpenCnnect() {return 0;};

    virtual int SendData() {return 0;};

    virtual int RecvData() {return 0;};

    virtual int CloseSocket() {return 0;};

protected:

    CONN_OBJ_TYPE       _type;
    IMtAction*          _action;
    KqueuerObj*         _ntfy_obj;
    MtMsgBuf*           _msg_buff;
};

class UdpShortConn : public IMtConnection
{
public:

    UdpShortConn() {
        _osfd = -1;
        _type = OBJ_SHORT_CONN;
    };    
    virtual ~UdpShortConn() {
        CloseSocket();
    };

    virtual void Reset();

    virtual int CreateSocket();

    virtual int SendData();

    virtual int RecvData();

    virtual int CloseSocket();
    
protected:
    int                 _osfd;
};


enum TcpKeepFlag
{
    TCP_KEEP_IN_LIST   = 0x1,
    TCP_KEEP_IN_KQUEUE = 0x2,
};

class UdpSessionConn : public IMtConnection
{
public:

    UdpSessionConn() {
        _type = OBJ_UDP_SESSION;
    };    
    virtual ~UdpSessionConn() {    };

    virtual int CreateSocket();

    virtual int SendData();

    virtual int RecvData();

    virtual int CloseSocket();
};

typedef TAILQ_ENTRY(TcpKeepConn) KeepConnLink;
typedef TAILQ_HEAD(__KeepConnTailq, TcpKeepConn) KeepConnList;
class TcpKeepConn : public IMtConnection, public CTimerNotify
{
public:

    int           _keep_flag;
    KeepConnLink  _keep_entry;

    TcpKeepConn() {
        _osfd = -1;
        _keep_time = 10*60*1000;
        _keep_flag = 0;
        _type = OBJ_TCP_KEEP;
        _keep_ntfy.SetKeepNtfyObj(this);
    };    
    virtual ~TcpKeepConn() {
        CloseSocket();
    };

    virtual void Reset();

    virtual int OpenCnnect();

    virtual int CreateSocket();

    virtual int SendData();

    virtual int RecvData();

    virtual int CloseSocket();

    void ConnReuseClean();

    bool IdleAttach();

    bool IdleDetach();

    void SetDestAddr(struct sockaddr_in* dst) {
        memcpy(&_dst_addr, dst, sizeof(_dst_addr));
    }

    struct sockaddr_in* GetDestAddr() {
        return &_dst_addr;
    }


    virtual void timer_notify();

    void SetKeepTime(unsigned int time) {
        _keep_time = time;    
    };
    
protected:
    int                 _osfd;
    unsigned int        _keep_time;
    TcpKeepNtfy         _keep_ntfy;
    struct sockaddr_in  _dst_addr;
    
};

class TcpKeepKey : public HashKey
{
public:

    TcpKeepKey() {
        _addr_ipv4  = 0;
        _net_port   = 0;
        TAILQ_INIT(&_keep_list);
        this->SetDataPtr(this);
    };

    TcpKeepKey(struct sockaddr_in * dst) {
        _addr_ipv4  = dst->sin_addr.s_addr;
        _net_port   = dst->sin_port;
        TAILQ_INIT(&_keep_list);
        this->SetDataPtr(this);
    };

    ~TcpKeepKey() {
        TAILQ_INIT(&_keep_list);
    };

    virtual uint32_t HashValue(){
        return _addr_ipv4 ^ ((_net_port << 16) | _net_port);
    }; 

    virtual int HashCmp(HashKey* rhs){
        TcpKeepKey* data = dynamic_cast<TcpKeepKey*>(rhs);
        if (!data) { 
            return -1;
        }
        if (this->_addr_ipv4 != data->_addr_ipv4) {
            return this->_addr_ipv4 - data->_addr_ipv4;    
        }
        if (this->_net_port != data->_net_port) {
            return this->_net_port - data->_net_port;
        }
        return 0;
    }; 

    void InsertConn(TcpKeepConn* conn) {
        if (conn->_keep_flag & TCP_KEEP_IN_LIST) {
            return;
        }
        TAILQ_INSERT_TAIL(&_keep_list, conn, _keep_entry);
        conn->_keep_flag |= TCP_KEEP_IN_LIST;
    };
    
    void RemoveConn(TcpKeepConn* conn) {
        if (!(conn->_keep_flag & TCP_KEEP_IN_LIST)) {
            return;
        }
        TAILQ_REMOVE(&_keep_list, conn, _keep_entry);
        conn->_keep_flag &= ~TCP_KEEP_IN_LIST;
    };

    TcpKeepConn* GetFirstConn() {
        return TAILQ_FIRST(&_keep_list);
    };    

private:
    uint32_t            _addr_ipv4;
    uint16_t            _net_port;
    KeepConnList        _keep_list;
    
};

class TcpKeepMgr
{
public:

    typedef CPtrPool<TcpKeepConn>   TcpKeepQueue;

    TcpKeepMgr();

    ~TcpKeepMgr();

    TcpKeepConn* GetTcpKeepConn(struct sockaddr_in*       dst);

    bool CacheTcpKeepConn(TcpKeepConn* conn);    

    bool RemoveTcpKeepConn(TcpKeepConn* conn); 

    void FreeTcpKeepConn(TcpKeepConn* conn, bool force_free);    
    
private:

    HashList*       _keep_hash;
    TcpKeepQueue    _mem_queue;
};

class ConnectionMgr
{
public:

    typedef CPtrPool<UdpShortConn>      UdpShortQueue;
    typedef CPtrPool<UdpSessionConn>    UdpSessionQueue;

    static ConnectionMgr* Instance (void);

    static void Destroy(void);

    IMtConnection* GetConnection(CONN_OBJ_TYPE type, struct sockaddr_in*     dst);

    void FreeConnection(IMtConnection* conn, bool force_free);

    void CloseIdleTcpKeep(TcpKeepConn* conn);

    ~ConnectionMgr();

private:
    ConnectionMgr();

    static ConnectionMgr * _instance;

    UdpShortQueue  _udp_short_queue;
    UdpSessionQueue  _udp_session_queue;
    TcpKeepMgr      _tcp_keep_mgr;
};

}
#endif


