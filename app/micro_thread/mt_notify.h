
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
 *  @file mt_notify.h
 *  @time 20130926
 **/

#ifndef __MT_NOTIFY_H__
#define __MT_NOTIFY_H__

#include <netinet/in.h>
#include <queue>
#include <map>
#include "mt_mbuf_pool.h"

namespace NS_MICRO_THREAD {

using std::queue;
using std::map;

class SessionProxy;
class TcpKeepConn;

enum NTFY_OBJ_TYPE
{
    NTFY_OBJ_UNDEF     = 0,
    NTFY_OBJ_THREAD    = 1,
    NTFY_OBJ_KEEPALIVE = 2,
    NTFY_OBJ_SESSION   = 3,
};

enum MULTI_PROTO 
{
    MT_UNKNOWN = 0,
    MT_UDP     = 0x1,
    MT_TCP     = 0x2
};

typedef TAILQ_ENTRY(SessionProxy) NtfyEntry;
typedef TAILQ_HEAD(__NtfyList, SessionProxy) NtfyList;
class ISessionNtfy : public KqueuerObj
{
public:

    virtual int GetSessionId(void* pkg, int len,  int& session) { return 0;};

    virtual int CreateSocket(){return -1;};

    virtual void CloseSocket(){};

    virtual int InputNotify(){return 0;};
    
    virtual int OutputNotify(){return 0;};

    virtual int HangupNotify(){return 0;};

    virtual int KqueueCtlAdd(void* args){return 0;};

    virtual int KqueueCtlDel(void* args){return 0;};

    ISessionNtfy(): KqueuerObj(0) {
        _proto = MT_UDP;
        _buff_size = 0;
        _msg_buff = NULL;
        TAILQ_INIT(&_write_list);
    }
    virtual ~ISessionNtfy() {   };

    void SetProtoType(MULTI_PROTO proto) {
        _proto = proto;
    };

    MULTI_PROTO GetProtoType() {
        return _proto;
    };

    void SetMsgBuffSize(int buff_size) {
        _buff_size = buff_size;
    };

    int GetMsgBuffSize()     {
        return (_buff_size > 0) ? _buff_size : 65535;
    }

    void InsertWriteWait(SessionProxy* proxy);

    void RemoveWriteWait(SessionProxy* proxy);


    virtual void NotifyWriteWait(){};
    
protected:
    MULTI_PROTO         _proto;
    int                 _buff_size;
    NtfyList            _write_list;
    MtMsgBuf*           _msg_buff;
};


class UdpSessionNtfy : public ISessionNtfy
{
public:

    virtual int GetSessionId(void* pkg, int len,  int& session) { return 0;};


public:

    UdpSessionNtfy() : ISessionNtfy(){
        ISessionNtfy::SetProtoType(MT_UDP); 
        
        _local_addr.sin_family = AF_INET;
        _local_addr.sin_addr.s_addr = 0;
        _local_addr.sin_port = 0;
    }
    virtual ~UdpSessionNtfy() {    };

    virtual void NotifyWriteWait();

    virtual int CreateSocket();

    virtual void CloseSocket();

    virtual int InputNotify();

    virtual int OutputNotify();

    virtual int HangupNotify();

    virtual int KqueueCtlAdd(void* args);

    virtual int KqueueCtlDel(void* args);

public:

    void SetLocalAddr(struct sockaddr_in* local_addr) {
        memcpy(&_local_addr, local_addr, sizeof(_local_addr));
    };

protected:

    struct sockaddr_in  _local_addr;
};


class SessionProxy  : public KqueuerObj
{
public:
    int         _flag;
    NtfyEntry   _write_entry;

    void SetRealNtfyObj(ISessionNtfy* obj) {
        _real_ntfy = obj;
        this->SetOsfd(obj->GetOsfd());
    };

    ISessionNtfy* GetRealNtfyObj() {
        return _real_ntfy;
    };

public:

    virtual void Reset() {
        _real_ntfy = NULL;
        this->KqueuerObj::Reset();
    };

    virtual int KqueueCtlAdd(void* args) {
        if (!_real_ntfy) {
            return -1;
        }
        
        int events = this->GetEvents(); 
        if (!(events & KQ_EVENT_WRITE)) {
            return 0;
        }

        if (_real_ntfy->KqueueCtlAdd(args) < 0) {
            return -2;
        }
        
        _real_ntfy->InsertWriteWait(this);
        return 0;
    };

    virtual int KqueueCtlDel(void* args) {
        if (!_real_ntfy) {
            return -1;
        } 
        
        int events = this->GetEvents(); 
        if (!(events & KQ_EVENT_WRITE)) {
            return 0;
        }
        
        _real_ntfy->RemoveWriteWait(this);        
        return _real_ntfy->KqueueCtlDel(args);
    };

private:
    ISessionNtfy*   _real_ntfy;

};

class TcpKeepNtfy: public KqueuerObj
{
public:

    TcpKeepNtfy() :     _keep_conn(NULL){};    

    virtual int InputNotify();

    virtual int OutputNotify();

    virtual int HangupNotify();

    void SetKeepNtfyObj(TcpKeepConn* obj) {
        _keep_conn = obj;
    };

    TcpKeepConn* GetKeepNtfyObj() {
        return _keep_conn;
    };

    void KeepaliveClose();
    

private:
    TcpKeepConn*   _keep_conn;

};

template<typename ValueType>
class CPtrPool
{
public:
    typedef typename std::queue<ValueType*>  PtrQueue;
    
public:

    explicit CPtrPool(int max = 500) : _max_free(max), _total(0){};

    ~CPtrPool()    {
        ValueType* ptr = NULL;
        while (!_ptr_list.empty()) {
            ptr = _ptr_list.front();
            _ptr_list.pop();
            delete ptr;
        }
    };

    ValueType* AllocPtr() {
        ValueType* ptr = NULL;
        if (!_ptr_list.empty()) {
            ptr = _ptr_list.front();
            _ptr_list.pop();
        } else {
            ptr = new ValueType;
            _total++;
        }

        return ptr;
    };

    void FreePtr(ValueType* ptr) {
        if ((int)_ptr_list.size() >= _max_free) {
            delete ptr;
            _total--;
        } else {
            _ptr_list.push(ptr);
        }
    };    
    
protected:
    PtrQueue  _ptr_list;
    int       _max_free;
    int       _total;
};

class NtfyObjMgr
{
public:

    typedef std::map<int, ISessionNtfy*>   SessionMap;
    typedef CPtrPool<KqueuerObj> NtfyThreadQueue;
    typedef CPtrPool<SessionProxy>  NtfySessionQueue;

    static NtfyObjMgr* Instance (void);

    static void Destroy(void);

    int RegisterSession(int session_name, ISessionNtfy* session);

    ISessionNtfy* GetNameSession(int session_name);

    KqueuerObj* GetNtfyObj(int type, int session_name = 0);

    void FreeNtfyObj(KqueuerObj* obj);

    ~NtfyObjMgr();
    
private:

    NtfyObjMgr();

    static NtfyObjMgr * _instance;
    SessionMap _session_map;
    NtfyThreadQueue  _fd_ntfy_pool;
    NtfySessionQueue _udp_proxy_pool;
};

}

#endif
