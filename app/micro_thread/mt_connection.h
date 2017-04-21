
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
 *  @info 微线程连接管理定义部分
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

/**
 * @brief 连接对象类型
 */
enum CONN_OBJ_TYPE
{
    OBJ_CONN_UNDEF     = 0,     ///< 未定义的连接对象
    OBJ_SHORT_CONN     = 1,     ///< 短连接对象, fd关联会话, 每次用完CLOSE
    OBJ_TCP_KEEP       = 2,     ///< TCP的复用模型, 每次每连接使用该fd, 用完可复用
    OBJ_UDP_SESSION    = 3,     ///< UDP的session模型, 每连接可供任意线程使用
};

/**
 * @brief 微线程一个后端请求, 映射一个连接对象
 */
class IMtConnection
{
public:

    /**
     * @brief  微线程连接基类构造与析构
     */
    IMtConnection();
    virtual ~IMtConnection();

    /**
     * @brief 连接回收复用清理操作
     */
    virtual void Reset();
    
    /**
     * @brief 获取连接对象的类型信息
     */
    CONN_OBJ_TYPE GetConnType() {
        return _type;    
    };
    
    /**
     * @brief 设置内部ACTION指针
     * @return IMtConn指针
     */
    void SetIMtActon(IMtAction* action  ) {
        _action = action;
    };

    /**
     * @brief 获取内部ACTION指针
     * @return IMtConn指针
     */
    IMtAction* GetIMtActon() {
        return _action;
    };

    /**
     * @brief 设置内部ACTION指针
     * @return IMtConn指针
     */
    void SetNtfyObj(KqueuerObj* obj  ) {
        _ntfy_obj = obj;
    };

    /**
     * @brief 获取内部ACTION指针
     * @return IMtConn指针
     */
    KqueuerObj* GetNtfyObj() {
        return _ntfy_obj;
    };
    
    /**
     * @brief 设置内部msgbuff指针
     * @return IMtConn指针
     */
    void SetMtMsgBuff(MtMsgBuf* msg_buf) {
        _msg_buff = msg_buf;
    };

    /**
     * @brief 获取内部msgbuff指针
     * @return IMtConn指针
     */
    MtMsgBuf* GetMtMsgBuff() {
        return _msg_buff;
    };   

public:
    
    /**
     * @brief  连接的socket建立, 依赖连接的协议类型等
     * @return >0 -成功, 返回系统fd, < 0 失败 
     */
    virtual int CreateSocket() {return 0;};
    
    /**
     * @brief  连接打开与远端会话通道, 如TCP的connect等
     * @return 0 -成功, < 0 失败 
     */
    virtual int OpenCnnect() {return 0;};

    /**
     * @brief  连接发送数据
     * @return >0 -成功, 返回实际发送长度, < 0 失败 
     */
    virtual int SendData() {return 0;};

    /**
     * @brief  连接接收数据
     * @return >0 -成功, 返回本次接收长度, < 0 失败(-1 对端关闭; -2 接收错误)
     */
    virtual int RecvData() {return 0;};

    /**
     * @brief  关闭socket端口
     * @return >0 -成功, 返回系统fd, < 0 失败 
     */
    virtual int CloseSocket() {return 0;};

protected:

    CONN_OBJ_TYPE       _type;      // 预置的type, 可按type做工厂管理
    IMtAction*          _action;    // 关联的action指针, 上级指针, 不关心资源生存期
    KqueuerObj*         _ntfy_obj;  // EPOLL通知对象, 下级指针, 关心生存期
    MtMsgBuf*           _msg_buff;  // 动态管理的buff字段, 下级指针, 关心生存期
};

/**
 * @brief 基于sock的短连接类型
 */
class UdpShortConn : public IMtConnection
{
public:

    /**
     * @brief 基于socket的短连接的构造与析构
     */
    UdpShortConn() {
        _osfd = -1;
        _type = OBJ_SHORT_CONN;
    };    
    virtual ~UdpShortConn() {
        CloseSocket();
    };

    /**
     * @brief 连接回收复用清理操作
     */
    virtual void Reset();

    /**
     * @brief  连接的socket建立, 依赖连接的协议类型等
     * @return >0 -成功, 返回系统fd, < 0 失败 
     */
    virtual int CreateSocket();

    /**
     * @brief  连接发送数据
     * @return >0 -成功, 返回实际发送长度, < 0 失败 
     */
    virtual int SendData();

    /**
     * @brief  连接接收数据
     * @return >0 -成功, 返回本次接收长度, < 0 失败(-1 对端关闭; -2 接收错误)
     */
    virtual int RecvData();

    /**
     * @brief  关闭socket端口
     * @return >0 -成功, 返回系统fd, < 0 失败 
     */
    virtual int CloseSocket();
    
protected:
    int                 _osfd;      // 每次连接单独创建socket
};


enum TcpKeepFlag
{
    TCP_KEEP_IN_LIST   = 0x1,
    TCP_KEEP_IN_KQUEUE = 0x2,
};

/**
 * @brief 基于session的UDP复用连接
 */
class UdpSessionConn : public IMtConnection
{
public:

    /**
     * @brief 基于socket的短连接的构造与析构
     */
    UdpSessionConn() {
        _type = OBJ_UDP_SESSION;
    };    
    virtual ~UdpSessionConn() {    };

    /**
     * @brief  连接的socket建立, 依赖连接的协议类型等
     * @return >0 -成功, 返回系统fd, < 0 失败 
     */
    virtual int CreateSocket();

    /**
     * @brief  连接发送数据
     * @return >0 -成功, 返回实际发送长度, < 0 失败 
     */
    virtual int SendData();

    /**
     * @brief  连接接收数据
     * @return >0 -成功, 返回本次接收长度, < 0 失败(-1 对端关闭; -2 接收错误)
     */
    virtual int RecvData();

    /**
     * @brief  关闭socket端口
     * @return >0 -成功, 返回系统fd, < 0 失败 
     */
    virtual int CloseSocket();
};

/**
 * @brief 基于sock的TCP复用连接
 */
typedef TAILQ_ENTRY(TcpKeepConn) KeepConnLink;
typedef TAILQ_HEAD(__KeepConnTailq, TcpKeepConn) KeepConnList;
class TcpKeepConn : public IMtConnection, public CTimerNotify
{
public:

    int           _keep_flag;  // 队列状态标记
    KeepConnLink  _keep_entry; // 队列管理入口

    /**
     * @brief 基于socket的短连接的构造与析构
     */
    TcpKeepConn() {
        _osfd = -1;
        _keep_time = 10*60*1000; // 默认10分钟, 可以按需调整
        _keep_flag = 0;
        _type = OBJ_TCP_KEEP;
        _keep_ntfy.SetKeepNtfyObj(this);
    };    
    virtual ~TcpKeepConn() {
        CloseSocket();
    };

    /**
     * @brief 连接回收复用清理操作
     */
    virtual void Reset();
    
    /**
     * @brief  连接打开与远端会话通道, 如TCP的connect等
     * @return 0 -成功, < 0 失败 
     */
    virtual int OpenCnnect();

    /**
     * @brief  连接的socket建立, 依赖连接的协议类型等
     * @return >0 -成功, 返回系统fd, < 0 失败 
     */
    virtual int CreateSocket();

    /**
     * @brief  连接发送数据
     * @return >0 -成功, 返回实际发送长度, < 0 失败 
     */
    virtual int SendData();

    /**
     * @brief  连接接收数据
     * @return >0 -成功, 返回本次接收长度, < 0 失败(-1 对端关闭; -2 接收错误)
     */
    virtual int RecvData();

    /**
     * @brief  关闭socket端口
     * @return >0 -成功, 返回系统fd, < 0 失败 
     */
    virtual int CloseSocket();

    /**
     * @brief 连接保持复用
     */
    void ConnReuseClean();

    /**
     * @brief Idle缓存处理, epoll 侦听远端关闭等
     */
    bool IdleAttach();

    /**
     * @brief Idle取消缓存处理, 不再由空闲线程侦听远端关闭
     */
    bool IdleDetach();

    /**
     * @brief 存储目的地址信息, 用于复用
     */
    void SetDestAddr(struct sockaddr_in* dst) {
        memcpy(&_dst_addr, dst, sizeof(_dst_addr));
    }

    /**
     * @brief 获取目的地址信息
     */
    struct sockaddr_in* GetDestAddr() {
        return &_dst_addr;
    }

    /**
     * @brief 超时通知函数, 子类实现逻辑
     */
    virtual void timer_notify();

    /**
     * @brief 设置超时时间, 毫秒单位
     */
    void SetKeepTime(unsigned int time) {
        _keep_time = time;    
    };
    
protected:
    int                 _osfd;      // 每次连接单独创建socket
    unsigned int        _keep_time; // 设置保活的时间
    TcpKeepNtfy         _keep_ntfy; // 关联一个保活连接对象
    struct sockaddr_in  _dst_addr;  // 远端地址信息
    
};



/**
 * @brief 按地址hash缓存长连接
 */
class TcpKeepKey : public HashKey
{
public:

    /**
     * @brief 构造与析构函数
     */
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

    /**
     * @brief 这里暂不清理conn
     */
    ~TcpKeepKey() {
        TAILQ_INIT(&_keep_list);
    };

    /**
     *  @brief 节点元素的hash算法, 获取key的hash值
     *  @return 节点元素的hash值
     */
    virtual uint32_t HashValue(){
        return _addr_ipv4 ^ ((_net_port << 16) | _net_port);
    }; 

    /**
     *  @brief 节点元素的cmp方法, 同一桶ID下, 按key比较
     *  @return 节点元素的hash值
     */
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


    /**
     * @brief 连接对象管理
     */
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
    uint32_t            _addr_ipv4;     ///< ip地址
    uint16_t            _net_port;      ///< port 网络序列
    KeepConnList        _keep_list;     ///< 实际的空闲队列
    
};


/**
 * @brief TCP长连接的连接对象管理与内存cache
 */
class TcpKeepMgr
{
public:

    typedef CPtrPool<TcpKeepConn>   TcpKeepQueue;   ///< 内存缓冲池

    /**
     * @brief 构造与析构函数
     */
    TcpKeepMgr();

    ~TcpKeepMgr();


    /**
     * @brief 按IP地址获取TCP的保持连接
     */
    TcpKeepConn* GetTcpKeepConn(struct sockaddr_in*       dst);
    
    /**
     * @brief 按IP地址缓存TCP的保持连接
     */
    bool CacheTcpKeepConn(TcpKeepConn* conn);    

    /**
     * @brief 按IP地址缓存TCP的保持连接, 去除CACHE
     */
    bool RemoveTcpKeepConn(TcpKeepConn* conn); 

    /**
     * @brief 关闭或缓存tcp长连接
     */
    void FreeTcpKeepConn(TcpKeepConn* conn, bool force_free);    
    
private:

    HashList*       _keep_hash;            ///< hash表, 存储按IP索引的连接队列
    TcpKeepQueue    _mem_queue;            ///< mem队列, 管理conn内存块
};


/**
 * @brief 连接管理工厂模型
 */
class ConnectionMgr
{
public:

    typedef CPtrPool<UdpShortConn>      UdpShortQueue;
    typedef CPtrPool<UdpSessionConn>    UdpSessionQueue;

    /**
     * @brief 消息buff的全局管理句柄接口
     * @return 全局句柄指针
     */
    static ConnectionMgr* Instance (void);

    /**
     * @brief 消息清理接口
     */
    static void Destroy(void);

    /**
     * @brief 获取接口
     */
    IMtConnection* GetConnection(CONN_OBJ_TYPE type, struct sockaddr_in*     dst);
    
    /**
     * @brief 回收接口
     */
    void FreeConnection(IMtConnection* conn, bool force_free);

    /**
     * @brief 关闭idle的tcp长连接
     */
    void CloseIdleTcpKeep(TcpKeepConn* conn);

    /**
     * @brief 消息buff的析构函数
     */
    ~ConnectionMgr();

private:
    /**
     * @brief 消息buff的构造函数
     */
    ConnectionMgr();

    static ConnectionMgr * _instance;         ///< 单例类句柄 

    UdpShortQueue  _udp_short_queue;          ///< 短连接的队列池 
    UdpSessionQueue  _udp_session_queue;      ///< udp session 连接池
    TcpKeepMgr      _tcp_keep_mgr;            ///< tcp keep 管理器
};

}
#endif


