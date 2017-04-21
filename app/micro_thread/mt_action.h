
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
 *  @file mt_action.h
 *  @info 微线程ACTION基类定义
 **/

#ifndef __MT_ACTION_H__
#define __MT_ACTION_H__

#include <netinet/in.h>
#include <queue>
#include "mt_msg.h"
#include "mt_session.h"
#include "mt_notify.h"

namespace NS_MICRO_THREAD {


/**
 * @brief 并发处理状态标记定义
 */
enum MULTI_STATE 
{
    MULTI_FLAG_UNDEF   = 0x0,       ///< 初始化, 未启动
    MULTI_FLAG_INIT    = 0x1,       ///< socket创建已成功
    MULTI_FLAG_OPEN    = 0x2,       ///< socket连接已打开
    MULTI_FLAG_SEND    = 0x4,       ///< 请求报文已经发送
    MULTI_FLAG_FIN     = 0x8,       ///< 应答报文已经接收到
};

/**
 * @brief 协议连接类型定义
 */
enum MULTI_CONNECT 
{
    CONN_UNKNOWN        = 0,
    CONN_TYPE_SHORT     = 0x1,          ///< 短连接, 一次交互后关闭
    CONN_TYPE_LONG      = 0x2,          ///< 长连接，每次使用后, 可回收重复使用
    CONN_TYPE_SESSION   = 0x4,          ///< 长连接，按session id 复用, 防串包
};

/**
 * @brief 错误码定义
 */
enum MULTI_ERROR 
{
    ERR_NONE            =  0,          
    ERR_SOCKET_FAIL     = -1,          ///< 创建sock失败
    ERR_CONNECT_FAIL    = -2,          ///< 连接失败
    ERR_SEND_FAIL       = -3,          ///< 发送报文失败
    ERR_RECV_FAIL       = -4,          ///< 接收失败
    ERR_RECV_TIMEOUT    = -5,          ///< 接收超时
    ERR_KQUEUE_FAIL     = -6,          ///< epoll失败
    ERR_FRAME_ERROR     = -7,          ///< 框架失败
    ERR_PEER_CLOSE      = -8,          ///< 对方关闭 
    ERR_PARAM_ERROR     = -9,          ///< 参数错误  
    ERR_MEMORY_ERROR    = -10,         ///< 内存申请失败
    ERR_ENCODE_ERROR    = -11,         ///< 封包失败
    ERR_DST_ADDR_ERROR  = -12,         ///< 目标地址获取失败
};




/**
 * @brief  微线程的后端交互抽象基类
 */
class IMtAction : public ISession
{
public:

    /**
     * @brief 微线程并发行为基类
     */
    IMtAction();
    virtual ~IMtAction();

	/**
	 * @brief 设置请求报文信息 (保证接口最大灵活兼容, 不使用inline)
     * @param  dst -请求包待发送的地址
	 */
	void SetMsgDstAddr(struct sockaddr_in* dst) {
        memcpy(&_addr, dst, sizeof(_addr));
	};
	
	/**
	 * @brief 获取消息目的地址信息
     * @return  注册的目的地址
	 */
	struct sockaddr_in* GetMsgDstAddr() {
        return &_addr;
	};

    /**
     * @brief 设置buff大小, 决定实际使用的msgbuff队列
     * @return  0成功
     */
    void SetMsgBuffSize(int buff_size) {
        _buff_size = buff_size;
    };

    /**
     * @brief 获取预置的buff大小
     * @return  框架申请的消息buff最大长度
     */
    int GetMsgBuffSize()     {
        return (_buff_size > 0) ? _buff_size : 65535;
    }	 

    /**
     * @brief 设置长连接session的名字id
     * @return  0成功
     */
    void SetSessionName(int name) {
        _ntfy_name = name;
    };

    /**
     * @brief 获取连接session的名字id
     * @return  session 注册名
     */
    int GetSessionName()     {
        return _ntfy_name;
    }	 

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
     * @brief 设置本次处理的连接类型信息
     */
    void SetConnType(MULTI_CONNECT type) {
        _conn_type = type;
    };

    /**
     * @brief 获取本次处理的连接类型信息
     * @return conn type
     */
    MULTI_CONNECT GetConnType() {
        return _conn_type;
    };     

    /**
     * @brief 设置本次处理的errno
     */
    void SetErrno(MULTI_ERROR err) {
        _errno = err; 
    };

    /**
     * @brief 获取本次处理的ERRNO信息
     * @return ERRONO
     */
    MULTI_ERROR GetErrno() {
        return _errno;
    };     

    /**
     * @brief 设置本次处理的timecost
     */
    void SetCost(int cost) {
        _time_cost = cost;
    };

    /**
     * @brief 获取本次处理的timecost信息
     * @return timecost
     */
    int GetCost() {
        return _time_cost;
    }; 

	/**
	 * @brief 设置处理状态信息
     * @param  flag -消息处理状态
	 */
	void SetMsgFlag(MULTI_STATE flag) {
        _flag = flag;
	};
	 
    /**
     * @brief 获取处理状态信息
     * @return flag -消息处理状态
     */
    MULTI_STATE GetMsgFlag() {
        return _flag;
    };

    /**
     * @brief 设置内部消息指针
     * @return IMtConn指针
     */
    void SetIMsgPtr(IMtMsg* msg  ) {
        _msg = msg;
    };

    /**
     * @brief 获取内部消息指针
     * @return IMtConn指针
     */
    IMtMsg* GetIMsgPtr() {
        return _msg;
    };
     
    /**
     * @brief 设置内部连接器指针
     * @return IMtConn指针
     */
    void SetIConnection(IMtConnection* conn) {
        _conn = conn;
    };

    /**
     * @brief 获取内部连接器指针
     * @return IMtConn指针
     */
    IMtConnection* GetIConnection() {
        return _conn;
    };

    /**
     * @brief 初始化必要字段信息
     */
    void Init();

    /**
     * @brief 允许复用, 清理Action状态
     */
    void Reset();

    /**
     * @brief 获取连接对象, 通知对象, 消息对象
     */
    KqueuerObj* GetNtfyObj();

    /**
     * @brief 获取连接对象, 通知对象, 消息对象
     */
    int InitConnEnv();

    /**
     * @brief 代理虚函数, 简化接口与实现部分
     */
    int DoEncode();
    int DoInput();
    int DoProcess();
    int DoError();

public:

    /**
     * @brief 本次连接的消息打包接口
     * @return >0 -成功, < 0 失败 
     */
    virtual int HandleEncode(void* buf, int& len, IMtMsg* msg){return 0;};

    /**
     * @brief 本次连接的CHECK接口, TCP的分包接口
     * @return > 0 已经成功接收,返回完整包大小, =0 继续等待, <0 出错(其中-65535 UDP串包) 
     */
    virtual int HandleInput(void* buf, int len, IMtMsg* msg){return 0;};

    /**
     * @brief 本次连接的应答处理接口, 接收一个完整分段包后调用
     * @return 0 成功, 其他失败
     */
    virtual int HandleProcess(void* buf, int len, IMtMsg* msg){return 0;};

    /**
     * @brief 本次连接处理的错误通知, 定义参见 MULTI_ERROR 枚举
     * @info  除handleprocess失败, 其它异常都调用该接口
     * @return 0 成功, 其他失败
     */
    virtual int HandleError(int err, IMtMsg* msg){return 0;};


protected:

    MULTI_STATE         _flag;      // 处理结束标记信息, 当前状态信息
    MULTI_PROTO         _proto;     // 协议类型 UDP/TCP
    MULTI_CONNECT       _conn_type; // 连接类型 长短连接
	MULTI_ERROR         _errno;     // 错误码信息, 0成功其他错误	
	struct sockaddr_in  _addr;      // 请求时填写，指定发送的stAddr	
	int                 _time_cost; // 本次请求应答耗时, 毫秒
	int                 _buff_size; // 本次请求最大请求与应答长度
	int                 _ntfy_name; // 关联的session ntfy的名字, session模型适用
	
	IMtMsg*             _msg;       // 消息指针, 上级指针
	IMtConnection*      _conn;      // 连接器指针, 下级指针, 管理生存期

};

}

#endif

