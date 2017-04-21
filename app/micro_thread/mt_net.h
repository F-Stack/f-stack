
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
 *  @info 微线程封装的网络接口类
 **/

#ifndef __MT_NET_H__
#define __MT_NET_H__

#include "micro_thread.h"
#include "hash_list.h"
#include "mt_api.h"
#include "mt_cache.h"
#include "mt_net_api.h"

namespace NS_MICRO_THREAD {

/**
 * @brief 连接类型定义
 */
enum MT_CONN_TYPE 
{
    TYPE_CONN_UNKNOWN   = 0,
    TYPE_CONN_SHORT     = 0x1,          ///< 短连接, 一次交互后关闭
    TYPE_CONN_POOL      = 0x2,          ///< 长连接，每次使用后, 可回收重复使用
    TYPE_CONN_SESSION   = 0x4,          ///< 长连接，按session id 复用, 防串包
    TYPE_CONN_SENDONLY  = 0x8,          ///< 只发不收
};


/******************************************************************************/
/*  内部实现部分                                                              */
/******************************************************************************/
class CSockLink;

/**
 * @brief 定时回收的对象池模板实现
 * @info  List必须是tailq, Type 需要有reset函数, releasetime, linkentry字段
 */
template <typename List, typename Type>
class CRecyclePool
{
public:

    // 构造函数, 默认60s超时
    CRecyclePool() {
        _expired = 60 * 1000;
        _count = 0;
        TAILQ_INIT(&_free_list);
    };

    // 析构函数, 删除池中元素
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

    // 复用或新创建对象
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

    // 释放管理对象
    void FreeItem(Type* obj) {
        //obj->Reset();        
        TAILQ_INSERT_TAIL(&_free_list, obj, _link_entry);
        obj->_release_time = mt_time_ms();
        _count++;
    };
    

    // 回收句柄
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

    // 设置自定义的超时时间
    void SetExpiredTime(uint64_t expired) {
        _expired = expired;
    };

private:

    List            _free_list;      ///< 空闲链表
    uint64_t        _expired;        ///< 超时时间
    uint32_t        _count;          ///< 元素计数
};



/**
 * @brief 每次IO关联一个句柄对象
 */
class CNetHandler : public HashKey
{
public:

    // 句柄状态描述
    enum {
        STATE_IN_SESSION    = 0x1,
        STATE_IN_CONNECT    = 0x2,
        STATE_IN_SEND       = 0x4,
        STATE_IN_RECV       = 0x8,
        STATE_IN_IDLE       = 0x10,
    };
    
    /**
     *  @brief 节点元素的hash算法, 获取key的hash值
     *  @return 节点元素的hash值
     */
    virtual uint32_t HashValue();

    /**
     *  @brief 节点元素的cmp方法, 同一桶ID下, 按key比较
     *  @return 节点元素的hash值
     */
    virtual int HashCmp(HashKey* rhs); 

    // 同步收发接口
    int32_t SendRecv(void* data, uint32_t len, uint32_t timeout);

    // 获取返回buff信息, 有效期直到helper析构
    void* GetRspBuff() {
        if (_rsp_buff != NULL) {
            return _rsp_buff->data;
        } else {
            return NULL;
        }
    };

    // 获取返回buff信息, 有效期直到helper析构
    uint32_t GetRspLen() {
        if (_rsp_buff != NULL) {
            return _rsp_buff->data_len;
        } else {
            return 0;
        }
    };
    
    // 设置rsp信息
    void SetRespBuff(TSkBuffer* buff) {
        if (_rsp_buff != NULL) {
            delete_sk_buffer(_rsp_buff);
            _rsp_buff = NULL;
        }
        
        _rsp_buff = buff;
    };

    // 设置协议的类型, 默认UDP
    void SetProtoType(MT_PROTO_TYPE type) {
        _proto_type = type;    
    };

    // 设置连接类型, 默认长连接
    void SetConnType(MT_CONN_TYPE type) {
        _conn_type = type;
    };

    // 设置目的IP地址
	void SetDestAddress(struct sockaddr_in* dst) {
        if (dst != NULL) {
            memcpy(&_dest_ipv4, dst, sizeof(*dst));
        }
	};

	// 设置session本次session id信息, 必须非0
	void SetSessionId(uint64_t sid) {
        _session_id = sid;
	};	

    // 设置session解析回调函数
    void SetSessionCallback(CHECK_SESSION_CALLBACK function) {
        _callback = function;
    };

    // 获取回调函数信息
    CHECK_SESSION_CALLBACK GetSessionCallback() {
        return _callback;
    };
    

public:

    // 关联连接对象
    void Link(CSockLink* conn);

    // 解耦连接对象
    void Unlink();
    
    // 检查必要的参数信息 
    int32_t CheckParams();

    // 获取链接, 同时关联到等待连接的队列中 
    int32_t GetConnLink();

    // 检查必要的参数信息 
    int32_t WaitConnect(uint64_t timeout);

    // 检查必要的参数信息 
    int32_t WaitSend(uint64_t timeout);

    // 检查必要的参数信息 
    int32_t WaitRecv(uint64_t timeout);

    // 关联在等待连接队列
    void SwitchToConn();

    // 切换到发送队列
    void SwitchToSend();

    // 切换到接收队列
    void SwitchToRecv();
    
    // 切换到空闲状态
    void SwitchToIdle();

    // 解耦连接对象
    void DetachConn();
    
    // 注册session管理
    bool RegistSession();

    // 取消注册session
    void UnRegistSession();

    // 跳过发送的请求长度
    uint32_t SkipSendPos(uint32_t len);

    // 设置返回码
    void SetErrNo(int32_t err) {
        _err_no = err;
    };

    // 获取关联的线程信息
    MicroThread* GetThread() {
        return _thread;
    };

    // 获取待发送的指针与数据长度
    void GetSendData(void*& data, uint32_t& len) {
        data = _req_data;
        len  = _req_len;
    };
 
    // 复用接口
    void Reset();

    // 构造与析构
    CNetHandler();
    ~CNetHandler();

    // 队列快捷访问的宏定义
    TAILQ_ENTRY(CNetHandler)    _link_entry; 
    uint64_t                    _release_time;

protected:

    MicroThread*        _thread;            ///< 关联线程指针对象
    MT_PROTO_TYPE       _proto_type;        ///< 协议类型       
    MT_CONN_TYPE        _conn_type;         ///< 连接类型
    struct sockaddr_in  _dest_ipv4;         ///< ipv4目的地址
    uint64_t            _session_id;        ///< 会话ID
    CHECK_SESSION_CALLBACK _callback;       ///< 会话提取回调函数
    uint32_t            _state_flags;       ///< 内部状态字段
    int32_t             _err_no;            ///< 返回码信息
    void*               _conn_ptr;          ///< socket 链路指针
    uint32_t            _send_pos;          ///< 已发送的pos位置
    uint32_t            _req_len;           ///< 请求包长度
    void*               _req_data;          ///< 请求包指针
    TSkBuffer*          _rsp_buff;          ///< 应答buff信息

};
typedef TAILQ_HEAD(__NetHandlerList, CNetHandler) TNetItemList;  ///< 高效的双链管理 
typedef CRecyclePool<TNetItemList, CNetHandler>   TNetItemPool;   ///< 定时回收的对象池


/**
 * @brief 长连接链路对象
 */
class CSockLink : public KqueuerObj
{
public:

    // 句柄状态描述
    enum {
        LINK_CONNECTING     = 0x1,
        LINK_CONNECTED      = 0x2,
    };

    // 状态队列定义
    enum {
        LINK_IDLE_LIST      = 1,
        LINK_CONN_LIST      = 2,
        LINK_SEND_LIST      = 3,
        LINK_RECV_LIST      = 4,
    };

    // 检查或创建socket句柄
    int32_t CreateSock();

    // 关闭链路的句柄
    void Close();

    // 发起连接过程
    bool Connect();
    bool Connected() {
        return (_state & LINK_CONNECTED);
    }

    // 异常终止的处理函数
    void Destroy();  

    // 获取管理链表
    TNetItemList* GetItemList(int32_t type);

    // 管理句柄信息
    void AppendToList(int32_t type, CNetHandler* item);

    // 管理句柄信息
    void RemoveFromList(int32_t type, CNetHandler* item);

    // 获取目标ip信息
    struct sockaddr_in* GetDestAddr(struct sockaddr_in* addr);

    // 发起连接过程
    int32_t SendData(void* data, uint32_t len);

    // udp发送数据
    int32_t SendCacheUdp(void* data, uint32_t len);

    // tcp发送数据
    int32_t SendCacheTcp(void* data, uint32_t len);

    // 尝试接收更多的数据到临时buff
    void ExtendRecvRsp();

    // 数据分发处理过程
    int32_t RecvDispath();

    // 或者回调函数, 优先从排队等待中获取, 备份从父节点获取
    CHECK_SESSION_CALLBACK GetSessionCallback();

    // TCP接收数据流处理与分发
    int32_t DispathTcp();

    // UDP接收数据流处理与分发
    int32_t DispathUdp();

    // 查询本地sessionid关联的session信息
    CNetHandler* FindSession(uint64_t sid);

    /**
     *  @brief 可读事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
     *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
     */
    virtual int InputNotify();
    
    /**
     *  @brief 可写事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
     *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
     */
    virtual int OutputNotify();
    
    /**
     *  @brief 异常通知接口
     *  @return 忽略返回值, 跳过其它事件处理
     */
    virtual int HangupNotify();


    // 构造与析构函数
    CSockLink();
    ~CSockLink();    
    
    // 清理置初始化逻辑
    void Reset();
    
    // 通知唤醒线程
    void NotifyThread(CNetHandler* item, int32_t result);

    // 通知唤醒线程
    void NotifyAll(int32_t result);

    // 设置协议类型, 决定buff池的指针
    void SetProtoType(MT_PROTO_TYPE type);

    // 设置上级指针信息
    void SetParentsPtr(void* ptr) {
        _parents = ptr;
    };

    // 获取上级节点指针
    void* GetParentsPtr() {
        return _parents;
    };

    // 获取上次的访问时间
    uint64_t GetLastAccess() {
        return _last_access;
    };
    
    

public:

    // 队列快捷访问的宏定义
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
typedef TAILQ_HEAD(__SocklinkList, CSockLink) TLinkList;  ///< 高效的双链管理 
typedef CRecyclePool<TLinkList, CSockLink>    TLinkPool;   ///< 定时回收的对象池


class CDestLinks : public CTimerNotify, public HashKey
{
public:

    // 构造函数
    CDestLinks();

    // 析构函数
    ~CDestLinks();

    // 重置复用的接口函数
    void Reset();

    // 启动定时器
    void StartTimer();

    // 获取一个连接link, 暂时按轮询
    CSockLink* GetSockLink();

    // 释放一个连接link
    void FreeSockLink(CSockLink* sock);

    // 获取协议类型
    MT_PROTO_TYPE GetProtoType() {
        return _proto_type;
    };

    // 获取连接类型
    MT_CONN_TYPE GetConnType() {
        return _conn_type;
    };
    

    // 设置关键信息
    void SetKeyInfo(uint32_t ipv4, uint16_t port, MT_PROTO_TYPE proto, MT_CONN_TYPE conn) {
        _addr_ipv4  = ipv4;
        _net_port   = port;
        _proto_type = proto;
        _conn_type  = conn;
    };

    // 拷贝KEY信息
    void CopyKeyInfo(CDestLinks* key) {
        _addr_ipv4  = key->_addr_ipv4;
        _net_port   = key->_net_port;
        _proto_type = key->_proto_type;
        _conn_type  = key->_conn_type;
    };
    
    // 获取IP port信息
    void GetDestIP(uint32_t& ip, uint16_t& port) {
        ip = _addr_ipv4;
        port = _net_port;
    };

    /**
     * @brief 超时通知函数, 检查空闲链路, 检查配置链路个数
     */
    virtual void timer_notify();
    
    /**
     *  @brief 节点元素的hash算法, 获取key的hash值
     *  @return 节点元素的hash值
     */
    virtual uint32_t HashValue() {
        return _addr_ipv4 ^ (((uint32_t)_net_port << 16) | (_proto_type << 8) | _conn_type);
    }; 

    /**
     *  @brief 节点元素的cmp方法, 同一桶ID下, 按key比较
     *  @return 节点元素的hash值
     */
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

    // 设置session解析回调函数
    void SetDefaultCallback(CHECK_SESSION_CALLBACK function) {
        _dflt_callback = function;
    };

    // 获取回调函数信息
    CHECK_SESSION_CALLBACK GetDefaultCallback() {
        return _dflt_callback;
    };

    // 队列快捷访问的宏定义
    TAILQ_ENTRY(CDestLinks) _link_entry; 
    uint64_t                _release_time;

private:

    uint32_t            _timeout;       ///< idle的超时时间
    uint32_t            _addr_ipv4;     ///< ip地址
    uint16_t            _net_port;      ///< port 网络序列
    MT_PROTO_TYPE       _proto_type;    ///< 协议类型
    MT_CONN_TYPE        _conn_type;     ///< 连接类型

    uint32_t            _max_links;     ///< 最大连接数
    uint32_t            _curr_link;     ///< 当前连接数
    TLinkList           _sock_list;     ///< 连接链表
    CHECK_SESSION_CALLBACK _dflt_callback; ///< 默认的check函数
        
};
typedef TAILQ_HEAD(__DestlinkList, CDestLinks) TDestList;  ///< 高效的双链管理 
typedef CRecyclePool<TDestList, CDestLinks>    TDestPool;   ///< 定时回收的对象池

/**
 * @brief 连接管理工厂模型
 */
class CNetMgr
{
public:

    /**
     * @brief 消息buff的全局管理句柄接口
     * @return 全局句柄指针
     */
    static CNetMgr* Instance (void);

    /**
     * @brief 消息清理接口
     */
    static void Destroy(void);

    // 查询是否已经存在同一个sid的对象
    CNetHandler* FindNetItem(CNetHandler* key);

    // 注册一个item, 先查询后插入, 保证无冲突
    void InsertNetItem(CNetHandler* item);

    // 移除一个item对象
    void RemoveNetItem(CNetHandler* item);

    // 查询或创建一个目标ip的links节点
    CDestLinks* FindCreateDest(CDestLinks* key);

    // 删除掉已有的目标链路信息
    void DeleteDestLink(CDestLinks* dst);
    
    // 查询是否已经存在同一个sid的对象
    CDestLinks* FindDestLink(CDestLinks* key);

    // 注册一个item, 先查询后插入, 保证无冲突
    void InsertDestLink(CDestLinks* item);
    
    // 移除一个item对象
    void RemoveDestLink(CDestLinks* item);

    /**
     * @brief 消息buff的析构函数
     */
    ~CNetMgr();

    /**
     * @brief 回收资源信息
     */
    void RecycleObjs(uint64_t now);

    // 分配一个网络管理句柄
    CNetHandler* AllocNetItem() {
        return _net_item_pool.AllocItem();
    };

    // 释放一个网络管理句柄
    void FreeNetItem(CNetHandler* item) {
        return _net_item_pool.FreeItem(item);
    };

    // 分配一个SOCK连接链路
    CSockLink* AllocSockLink() {
        return _sock_link_pool.AllocItem();
    };

    // 释放一个SOCK连接链路
    void FreeSockLink(CSockLink* item) {
        return _sock_link_pool.FreeItem(item);
    };

    // 分配一个SOCK连接链路
    CDestLinks* AllocDestLink() {
        return _dest_ip_pool.AllocItem();
    };

    // 释放一个SOCK连接链路
    void FreeDestLink(CDestLinks* item) {
        return _dest_ip_pool.FreeItem(item);
    };

    // 获取udp的buff池信息
    TSkBuffMng* GetSkBuffMng(MT_PROTO_TYPE type) {
        if (type == NET_PROTO_TCP) {
            return &_tcp_pool;
        } else {
            return &_udp_pool;
        }
    };
    

private:
    /**
     * @brief 消息buff的构造函数
     */
    CNetMgr();

    static CNetMgr *    _instance;          ///< 单例类句柄 
    HashList*           _ip_hash;           ///< 目的地址hash
    HashList*           _session_hash;      ///< session id的hash
    TSkBuffMng          _udp_pool;          ///< udp pool, 64K
    TSkBuffMng          _tcp_pool;          ///< tcp pool, 4K
    TDestPool           _dest_ip_pool;      ///< 目的ip对象池
    TLinkPool           _sock_link_pool;    ///< socket pool
    TNetItemPool        _net_item_pool;     ///< net handle pool
};





}

#endif


