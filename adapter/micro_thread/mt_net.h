
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
 *  @file mt_net.h
 **/

#ifndef __MT_NET_H__
#define __MT_NET_H__

#include "micro_thread.h"
#include "hash_list.h"
#include "mt_api.h"
#include "mt_cache.h"
#include "mt_net_api.h"

namespace NS_MICRO_THREAD {

enum MT_CONN_TYPE 
{
    TYPE_CONN_UNKNOWN   = 0,
    TYPE_CONN_SHORT     = 0x1,
    TYPE_CONN_POOL      = 0x2,
    TYPE_CONN_SESSION   = 0x4,
    TYPE_CONN_SENDONLY  = 0x8,
};

class CSockLink;

template <typename List, typename Type>
class CRecyclePool
{
public:

    CRecyclePool() {
        _expired = 60 * 1000;
        _count = 0;
        TAILQ_INIT(&_free_list);
    };

    ~CRecyclePool() {
        Type* item = NULL;
        Type* tmp = NULL;
        TAILQ_FOREACH_SAFE(item, &_free_list, _link_entry, tmp)
        {
            TAILQ_REMOVE(&_free_list, item, _link_entry);
            delete item;
        }
        _count = 0;
    };

    Type* AllocItem() {
        Type* item = TAILQ_FIRST(&_free_list);
        if (item != NULL)
        {
            TAILQ_REMOVE(&_free_list, item, _link_entry);
            _count--;
            return item;
        }
        
        item = new Type();
        if (NULL == item)
        {
            return NULL;
        }
        
        return item;
    };

    void FreeItem(Type* obj) {
        //obj->Reset();        
        TAILQ_INSERT_TAIL(&_free_list, obj, _link_entry);
        obj->_release_time = mt_time_ms();
        _count++;
    };

    void RecycleItem(uint64_t now) {
        Type* item = NULL;
        Type* tmp = NULL;
        TAILQ_FOREACH_SAFE(item, &_free_list, _link_entry, tmp)
        {
            if ((now - item->_release_time) < _expired) {
                break;
            }
        
            TAILQ_REMOVE(&_free_list, item, _link_entry);
            delete item;
            _count--;
        }
    };

    void SetExpiredTime(uint64_t expired) {
        _expired = expired;
    };

private:

    List            _free_list;
    uint64_t        _expired;
    uint32_t        _count;
};

class CNetHandler : public HashKey
{
public:

    enum {
        STATE_IN_SESSION    = 0x1,
        STATE_IN_CONNECT    = 0x2,
        STATE_IN_SEND       = 0x4,
        STATE_IN_RECV       = 0x8,
        STATE_IN_IDLE       = 0x10,
    };

    virtual uint32_t HashValue();

    virtual int HashCmp(HashKey* rhs); 

    int32_t SendRecv(void* data, uint32_t len, uint32_t timeout);

    void* GetRspBuff() {
        if (_rsp_buff != NULL) {
            return _rsp_buff->data;
        } else {
            return NULL;
        }
    };

    uint32_t GetRspLen() {
        if (_rsp_buff != NULL) {
            return _rsp_buff->data_len;
        } else {
            return 0;
        }
    };

    void SetRespBuff(TSkBuffer* buff) {
        if (_rsp_buff != NULL) {
            delete_sk_buffer(_rsp_buff);
            _rsp_buff = NULL;
        }
        
        _rsp_buff = buff;
    };

    void SetProtoType(MT_PROTO_TYPE type) {
        _proto_type = type;    
    };

    void SetConnType(MT_CONN_TYPE type) {
        _conn_type = type;
    };

	void SetDestAddress(struct sockaddr_in* dst) {
        if (dst != NULL) {
            memcpy(&_dest_ipv4, dst, sizeof(*dst));
        }
	};

	void SetSessionId(uint64_t sid) {
        _session_id = sid;
	};	

    void SetSessionCallback(CHECK_SESSION_CALLBACK function) {
        _callback = function;
    };

    CHECK_SESSION_CALLBACK GetSessionCallback() {
        return _callback;
    };
    

public:

    void Link(CSockLink* conn);

    void Unlink();

    int32_t CheckParams();

    int32_t GetConnLink();

    int32_t WaitConnect(uint64_t timeout);

    int32_t WaitSend(uint64_t timeout);
 
    int32_t WaitRecv(uint64_t timeout);

    void SwitchToConn();

    void SwitchToSend();

    void SwitchToRecv();

    void SwitchToIdle();

    void DetachConn();

    bool RegistSession();

    void UnRegistSession();

    uint32_t SkipSendPos(uint32_t len);

    void SetErrNo(int32_t err) {
        _err_no = err;
    };

    MicroThread* GetThread() {
        return _thread;
    };

    void GetSendData(void*& data, uint32_t& len) {
        data = _req_data;
        len  = _req_len;
    };

    void Reset();

    CNetHandler();
    ~CNetHandler();

    TAILQ_ENTRY(CNetHandler)    _link_entry; 
    uint64_t                    _release_time;

protected:

    MicroThread*        _thread;
    MT_PROTO_TYPE       _proto_type;    
    MT_CONN_TYPE        _conn_type;
    struct sockaddr_in  _dest_ipv4;
    uint64_t            _session_id;
    CHECK_SESSION_CALLBACK _callback;
    uint32_t            _state_flags;
    int32_t             _err_no;
    void*               _conn_ptr;
    uint32_t            _send_pos;
    uint32_t            _req_len;
    void*               _req_data;
    TSkBuffer*          _rsp_buff;

};
typedef TAILQ_HEAD(__NetHandlerList, CNetHandler) TNetItemList;
typedef CRecyclePool<TNetItemList, CNetHandler>   TNetItemPool;

class CSockLink : public KqueuerObj
{
public:

    enum {
        LINK_CONNECTING     = 0x1,
        LINK_CONNECTED      = 0x2,
    };

    enum {
        LINK_IDLE_LIST      = 1,
        LINK_CONN_LIST      = 2,
        LINK_SEND_LIST      = 3,
        LINK_RECV_LIST      = 4,
    };

    int32_t CreateSock();

    void Close();

    bool Connect();
    bool Connected() {
        return (_state & LINK_CONNECTED);
    }

    void Destroy();  

    TNetItemList* GetItemList(int32_t type);

    void AppendToList(int32_t type, CNetHandler* item);

    void RemoveFromList(int32_t type, CNetHandler* item);

    struct sockaddr_in* GetDestAddr(struct sockaddr_in* addr);

    int32_t SendData(void* data, uint32_t len);

    int32_t SendCacheUdp(void* data, uint32_t len);

    int32_t SendCacheTcp(void* data, uint32_t len);

    void ExtendRecvRsp();

    int32_t RecvDispath();

    CHECK_SESSION_CALLBACK GetSessionCallback();

    int32_t DispathTcp();

    int32_t DispathUdp();

    CNetHandler* FindSession(uint64_t sid);

    virtual int InputNotify();
    
    virtual int OutputNotify();

    virtual int HangupNotify();

    CSockLink();
    ~CSockLink();

    void Reset();

    void NotifyThread(CNetHandler* item, int32_t result);

    void NotifyAll(int32_t result);

    void SetProtoType(MT_PROTO_TYPE type);

    void SetParentsPtr(void* ptr) {
        _parents = ptr;
    };

    void* GetParentsPtr() {
        return _parents;
    };

    uint64_t GetLastAccess() {
        return _last_access;
    };

public:

    TAILQ_ENTRY(CSockLink) _link_entry; 
    uint64_t               _release_time;
    
private:

    TNetItemList        _wait_connect;
    TNetItemList        _wait_send;
    TNetItemList        _wait_recv;
    TNetItemList        _idle_list;
    MT_PROTO_TYPE       _proto_type;
    int32_t             _errno;
    uint32_t            _state;
    uint64_t            _last_access;
    TRWCache            _recv_cache;
    TSkBuffer*          _rsp_buff;
    void*               _parents;
};
typedef TAILQ_HEAD(__SocklinkList, CSockLink) TLinkList;
typedef CRecyclePool<TLinkList, CSockLink>    TLinkPool;

class CDestLinks : public CTimerNotify, public HashKey
{
public:

    CDestLinks();
    ~CDestLinks();

    void Reset();

    void StartTimer();

    CSockLink* GetSockLink();

    void FreeSockLink(CSockLink* sock);

    MT_PROTO_TYPE GetProtoType() {
        return _proto_type;
    };

    MT_CONN_TYPE GetConnType() {
        return _conn_type;
    };

    void SetKeyInfo(uint32_t ipv4, uint16_t port, MT_PROTO_TYPE proto, MT_CONN_TYPE conn) {
        _addr_ipv4  = ipv4;
        _net_port   = port;
        _proto_type = proto;
        _conn_type  = conn;
    };

    void CopyKeyInfo(CDestLinks* key) {
        _addr_ipv4  = key->_addr_ipv4;
        _net_port   = key->_net_port;
        _proto_type = key->_proto_type;
        _conn_type  = key->_conn_type;
    };

    void GetDestIP(uint32_t& ip, uint16_t& port) {
        ip = _addr_ipv4;
        port = _net_port;
    };

    virtual void timer_notify();

    virtual uint32_t HashValue() {
        return _addr_ipv4 ^ (((uint32_t)_net_port << 16) | (_proto_type << 8) | _conn_type);
    }; 

    virtual int HashCmp(HashKey* rhs) {
        CDestLinks* data = (CDestLinks*)(rhs);
        if (!data) { 
            return -1;
        }
        if (this->_addr_ipv4 != data->_addr_ipv4) {
            return (this->_addr_ipv4 > data->_addr_ipv4) ?  1 : -1;    
        }
        if (this->_net_port != data->_net_port) {
            return (this->_net_port > data->_net_port) ? 1 : -1;
        }
        if (this->_proto_type != data->_proto_type) {
            return (this->_proto_type > data->_proto_type) ? 1 : -1;
        }
        if (this->_conn_type != data->_conn_type) {
            return (this->_conn_type > data->_conn_type) ? 1 : -1;
        }
        
        return 0;
    }; 

    void SetDefaultCallback(CHECK_SESSION_CALLBACK function) {
        _dflt_callback = function;
    };

    CHECK_SESSION_CALLBACK GetDefaultCallback() {
        return _dflt_callback;
    };

    TAILQ_ENTRY(CDestLinks) _link_entry; 
    uint64_t                _release_time;

private:

    uint32_t            _timeout;
    uint32_t            _addr_ipv4;
    uint16_t            _net_port;
    MT_PROTO_TYPE       _proto_type;
    MT_CONN_TYPE        _conn_type;

    uint32_t            _max_links;
    uint32_t            _curr_link;
    TLinkList           _sock_list;
    CHECK_SESSION_CALLBACK _dflt_callback;
        
};
typedef TAILQ_HEAD(__DestlinkList, CDestLinks) TDestList;
typedef CRecyclePool<TDestList, CDestLinks>    TDestPool;

class CNetMgr
{
public:

    static CNetMgr* Instance (void);

    static void Destroy(void);

    CNetHandler* FindNetItem(CNetHandler* key);

    void InsertNetItem(CNetHandler* item);

    void RemoveNetItem(CNetHandler* item);

    CDestLinks* FindCreateDest(CDestLinks* key);

    void DeleteDestLink(CDestLinks* dst);

    CDestLinks* FindDestLink(CDestLinks* key);

    void InsertDestLink(CDestLinks* item);

    void RemoveDestLink(CDestLinks* item);

    ~CNetMgr();

    void RecycleObjs(uint64_t now);

    CNetHandler* AllocNetItem() {
        return _net_item_pool.AllocItem();
    };

    void FreeNetItem(CNetHandler* item) {
        return _net_item_pool.FreeItem(item);
    };

    CSockLink* AllocSockLink() {
        return _sock_link_pool.AllocItem();
    };

    void FreeSockLink(CSockLink* item) {
        return _sock_link_pool.FreeItem(item);
    };

    CDestLinks* AllocDestLink() {
        return _dest_ip_pool.AllocItem();
    };

    void FreeDestLink(CDestLinks* item) {
        return _dest_ip_pool.FreeItem(item);
    };

    TSkBuffMng* GetSkBuffMng(MT_PROTO_TYPE type) {
        if (type == NET_PROTO_TCP) {
            return &_tcp_pool;
        } else {
            return &_udp_pool;
        }
    };
    

private:
    CNetMgr();

    static CNetMgr *    _instance;
    HashList*           _ip_hash;
    HashList*           _session_hash;
    TSkBuffMng          _udp_pool;
    TSkBuffMng          _tcp_pool;
    TDestPool           _dest_ip_pool;
    TLinkPool           _sock_link_pool;
    TNetItemPool        _net_item_pool;
};

}

#endif


