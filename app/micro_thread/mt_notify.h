
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
 *  @info 微线程注册的通知对象定义与管理
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

/**
 * @brief 通知对象类型
 */
enum NTFY_OBJ_TYPE
{
    NTFY_OBJ_UNDEF     = 0,     ///< 未定义的连接对象
    NTFY_OBJ_THREAD    = 1,     ///< 短连接对象, 一个fd对应一个thread
    NTFY_OBJ_KEEPALIVE = 2,     ///< TCP心跳保持的notify对象, 不关联 thread
    NTFY_OBJ_SESSION   = 3,     ///< UDP的session模型, 代理的长连接对象
};

/**
 * @brief 协议类型定义
 */
enum MULTI_PROTO 
{
    MT_UNKNOWN = 0,
    MT_UDP     = 0x1,                ///< 连接类型 UDP
    MT_TCP     = 0x2                 ///< 连接类型 TCP
};

/**
 * @brief 长连接session模型, 批量收发调度管理接口
 */
typedef TAILQ_ENTRY(SessionProxy) NtfyEntry;
typedef TAILQ_HEAD(__NtfyList, SessionProxy) NtfyList;
class ISessionNtfy : public KqueuerObj
{
public:

    /**
     *  @brief 检查报文完整性, 同时提取sessionid信息
     *  @param pkg 报文指针
     *  @param len 报文已接收长度
     *  @param session 解析的sessionid, 输出参数
     *  @return <=0 失败, >0 实际报文长度
     */
    virtual int GetSessionId(void* pkg, int len,  int& session) { return 0;};

    /**
     *  @brief 创建socket, 监听可读事件
     *  @return fd的句柄, <0 失败
     */
    virtual int CreateSocket(){return -1;};

    /**
     *  @brief 关闭socket, 停止监听可读事件
     */
    virtual void CloseSocket(){};

    /**
     *  @brief 可读事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
     *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
     */
    virtual int InputNotify(){return 0;};
    
    /**
     *  @brief 可写事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
     *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
     */
    virtual int OutputNotify(){return 0;};
    
    /**
     *  @brief 异常通知接口
     *  @return 忽略返回值, 跳过其它事件处理
     */
    virtual int HangupNotify(){return 0;};

    /**
     *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
     *  @param args fd引用对象的指针
     *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
     */
    virtual int KqueueCtlAdd(void* args){return 0;};

    /**
     *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
     *  @param args fd引用对象的指针
     *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
     */
    virtual int KqueueCtlDel(void* args){return 0;};

    /**
     * @brief 构造函数析构函数
     */
    ISessionNtfy(): KqueuerObj(0) {
        _proto = MT_UDP;
        _buff_size = 0;
        _msg_buff = NULL;
        TAILQ_INIT(&_write_list);
    }
    virtual ~ISessionNtfy() {   };

    /**
     * @brief 设置本次处理的proto信息
     */
    void SetProtoType(MULTI_PROTO proto) {
        _proto = proto;
    };

    /**
     * @brief 获取本次处理的proto信息
     * @return proto type
     */
    MULTI_PROTO GetProtoType() {
        return _proto;
    };
    
    /**
     * @brief 设置buff大小, 决定实际使用的msgbuff队列
     * @return  0成功
     */
    void SetMsgBuffSize(int buff_size) {
        _buff_size = buff_size;
    };

    /**
     * @brief 获取预置的buff大小, 如无设置, 返回65535
     * @return  框架申请的消息buff最大长度
     */
    int GetMsgBuffSize()     {
        return (_buff_size > 0) ? _buff_size : 65535;
    }

    /**
     * @brief 通知代理进入等待状态
     */
    void InsertWriteWait(SessionProxy* proxy);

    /**
     * @brief 通知代理取消等待状态
     */
    void RemoveWriteWait(SessionProxy* proxy);

    /**
     * @brief 观察者模式, 通知写等待线程
     * @info UDP可以通知每个线程执行写操作, TCP需要排队写
     */
    virtual void NotifyWriteWait(){};
    
protected:
    MULTI_PROTO         _proto;         // 协议类型 UDP/TCP
    int                 _buff_size;     // 最大消息长度
    NtfyList            _write_list;    // 可写等待队列
    MtMsgBuf*           _msg_buff;      // 临时收包存放缓冲区
};


/**
 * @brief UDP长连接session模型的基类接口
 * @info  业务session需要继承该接口, 设置属性, 实现获取GetSessionId函数
 * @info  保留扩展, 如指定本地端口等
 */
class UdpSessionNtfy : public ISessionNtfy
{
public:
    
    /**
     *  @brief 检查报文完整性, 同时提取sessionid信息, 由继承类实现它
     *  @param pkg 报文指针
     *  @param len 报文已接收长度
     *  @param session 解析的sessionid, 输出参数
     *  @return <=0 失败, >0 实际报文长度
     */
    virtual int GetSessionId(void* pkg, int len,  int& session) { return 0;};


public:

    /**
     * @brief 构造与析构函数
     */
    UdpSessionNtfy() : ISessionNtfy(){
        ISessionNtfy::SetProtoType(MT_UDP); 
        
        _local_addr.sin_family = AF_INET;
        _local_addr.sin_addr.s_addr = 0;
        _local_addr.sin_port = 0;
    }
    virtual ~UdpSessionNtfy() {    };

    /**
     * @brief 观察者模式, 通知写等待线程
     * @info UDP可以通知每个线程执行写操作, TCP需要排队写
     */
    virtual void NotifyWriteWait();

    /**
     *  @brief 创建socket, 监听可读事件
     *  @return fd的句柄, <0 失败
     */
    virtual int CreateSocket();

    /**
     *  @brief 关闭socket, 停止监听可读事件
     */
    virtual void CloseSocket();

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

    /**
     *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
     *  @param args fd引用对象的指针
     *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
     */
    virtual int KqueueCtlAdd(void* args);

    /**
     *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
     *  @param args fd引用对象的指针
     *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
     */
    virtual int KqueueCtlDel(void* args);

public:

    /**
     * @brief 设置udp本地的本地bind地址, 多进程bind会冲突, 暂时停用
     *      后续开放, 能保证每进程唯一port可使用
     */
    void SetLocalAddr(struct sockaddr_in* local_addr) {
        memcpy(&_local_addr, local_addr, sizeof(_local_addr));
    };

protected:

    struct sockaddr_in  _local_addr;
};



/**
 * @brief UDP模式session模型的代理通知对象, 多个代理映射到某一个session notify
 * @info  session proxy 本身不在epoll注册, 不会有事件通知, 但需要关心超时等
 */
class SessionProxy  : public KqueuerObj
{
public:
    int         _flag;                ///< 0-不在队列中, 1-在等待队列
    NtfyEntry   _write_entry;         ///< 关联可写等待队列的管理入口

    /**
     *  @brief 设置代理对象, 关联代理的fd句柄
     */
    void SetRealNtfyObj(ISessionNtfy* obj) {
        _real_ntfy = obj;
        this->SetOsfd(obj->GetOsfd());
    };
    
    /**
     *  @brief 获取代理对象指针
     */
    ISessionNtfy* GetRealNtfyObj() {
        return _real_ntfy;
    };

public:

    /**
     * @brief 回收处理, 设置清理动作
     */
    virtual void Reset() {
        _real_ntfy = NULL;
        this->KqueuerObj::Reset();
    };

    /**
     *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
     *  @param args fd引用对象的指针
     *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
     */
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

    /**
     *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
     *  @param args fd引用对象的指针
     *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
     */
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
    ISessionNtfy*   _real_ntfy;         // 实际的执行者

};

/**
 * @brief TCP模式的keepalive通知对象, 仅仅关心可读事件, 确认是否对端关闭
 */
class TcpKeepNtfy: public KqueuerObj
{
public:

    /**
     * @brief 构造函数
     */
    TcpKeepNtfy() :     _keep_conn(NULL){};    

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

    /**
     *  @brief 设置代理对象
     */
    void SetKeepNtfyObj(TcpKeepConn* obj) {
        _keep_conn = obj;
    };

    /**
     *  @brief 获取代理对象指针
     */
    TcpKeepConn* GetKeepNtfyObj() {
        return _keep_conn;
    };
    
    /**
     *  @brief 触发实际连接关闭操作
     */
    void KeepaliveClose();
    

private:
    TcpKeepConn*   _keep_conn;         // 实际的连接器对象

};


/**
 * @brief 动态内存池模板类, 对于反复new/delete的对象操作, 可一定程度上提高性能
 */
template<typename ValueType>
class CPtrPool
{
public:
    typedef typename std::queue<ValueType*>  PtrQueue; ///< 内存指针队列
    
public:

    /**
     * @brief 动态内存池构造函数
     * @param max 最大空闲队列保存的指针元素, 默认500
     */
    explicit CPtrPool(int max = 500) : _max_free(max), _total(0){};
    
    /**
     * @brief 动态内存池析构函数, 仅仅清理掉freelist
     */
    ~CPtrPool()    {
        ValueType* ptr = NULL;
        while (!_ptr_list.empty()) {
            ptr = _ptr_list.front();
            _ptr_list.pop();
            delete ptr;
        }
    };

    /**
     * @brief 分配内存指针, 优先从缓存获取, 无空闲可用则动态 new 申请
     * @return 模板类型的指针元素, 空表示内存申请失败
     */
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

    /**
     * @brief 释放内存指针, 若空闲队列超过配额, 则直接释放, 否则队列缓存
     */
    void FreePtr(ValueType* ptr) {
        if ((int)_ptr_list.size() >= _max_free) {
            delete ptr;
            _total--;
        } else {
            _ptr_list.push(ptr);
        }
    };    
    
protected:
    PtrQueue  _ptr_list;           ///<  空闲队列
    int       _max_free;           ///<  最大空闲元素 
    int       _total;              ///<  所有new的对象个数统计
};


/**
 * @brief 通知对象全局管理器
 */
class NtfyObjMgr
{
public:

    typedef std::map<int, ISessionNtfy*>   SessionMap;
    typedef CPtrPool<KqueuerObj> NtfyThreadQueue;
    typedef CPtrPool<SessionProxy>  NtfySessionQueue;
    
    /**
     * @brief 会话上下文的全局管理句柄接口
     * @return 全局句柄指针
     */
    static NtfyObjMgr* Instance (void);

    /**
     * @brief 清理接口
     */
    static void Destroy(void);

    /**
     * @brief 注册长连接session信息
     * @param session_name 长连接的标识, 每个连接处理一类session封装格式
     * @param session 长连接对象指针, 定义连接属性
     * @return 0 成功, < 0 失败
     */
    int RegisterSession(int session_name, ISessionNtfy* session);

    /**
     * @brief 获取注册长连接session信息
     * @param session_name 长连接的标识, 每个连接处理一类session封装格式
     * @return 长连接指针, 失败为NULL
     */
    ISessionNtfy* GetNameSession(int session_name);

    /**
     * @brief 获取通用通知对象, 如线程通知对象与session通知代理对象
     * @param type 类型, 线程通知类型，UDP/TCP SESSION通知等
     * @param session_name proxy模型,一并获取session对象
     * @return 通知对象的指针, 失败为NULL
     */
    KqueuerObj* GetNtfyObj(int type, int session_name = 0);

    
    /**
     * @brief 释放通知对象指针
     * @param obj 通知对象
     */
    void FreeNtfyObj(KqueuerObj* obj);

    /**
     * @brief 析构函数
     */
    ~NtfyObjMgr();
    
private:

    /**
     * @brief 消息buff的构造函数
     */
    NtfyObjMgr();

    static NtfyObjMgr * _instance;         ///<  单例类句柄
    SessionMap _session_map;               ///<  全局的注册session管理
    NtfyThreadQueue  _fd_ntfy_pool;        ///<  fd通知对象
    NtfySessionQueue _udp_proxy_pool;      ///<  fd通知对象
};



}

#endif


