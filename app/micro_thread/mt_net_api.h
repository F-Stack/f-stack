
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
 *  @info 微线程封装的网络接口类
 **/

#ifndef __MT_NET_API_H__
#define __MT_NET_API_H__

#include <netinet/in.h>

namespace NS_MICRO_THREAD {

/**
 * @brief 协议类型定义
 */
enum MT_PROTO_TYPE 
{
    NET_PROTO_UNDEF      = 0,
    NET_PROTO_UDP        = 0x1,                ///< 连接类型 UDP
    NET_PROTO_TCP        = 0x2                 ///< 连接类型 TCP
};

/**
 * @brief 返回类型定义
 */
enum MT_RC_TYPE 
{
    RC_SUCCESS          = 0,
    RC_ERR_SOCKET       = -1,           ///< 创建socket失败
    RC_SEND_FAIL        = -2,           ///< 发送失败
    RC_RECV_FAIL        = -3,           ///< 接收失败
    RC_CONNECT_FAIL     = -4,           ///< 连接失败
    RC_CHECK_PKG_FAIL   = -5,           ///< 报文检测失败
    RC_NO_MORE_BUFF     = -6,           ///< 空间超过限制
    RC_REMOTE_CLOSED    = -7,           ///< 后端关闭连接

    RC_INVALID_PARAM    = -10,          ///< 无效参数
    RC_INVALID_HANDLER  = -11,          ///< 无效的句柄
    RC_MEM_ERROR        = -12,          ///< 内存异常
    RC_CONFLICT_SID     = -13,          ///< SESSION ID冲突
    RC_KQUEUE_ERROR     = -14,          ///< rst信号等
};


/**
 * @brief 检查报文是否完整, 并获取session的回调函数
 * @info  提供need_len参数的原因, 对于无法确认报文长度时, 可以每次扩展希望长度
 *        如果依赖返回值的隐含规则, 将无法处理这种情况
 * @param data  -实际接收的数据指针
 * @param len   -已经接收或准备的长度
 * @param session_id -成功解析的sessionid信息
 * @param need_len   -希望扩展一下buff, 目前最大100M
 * @return >0 成功解析返回实际的包长度; =0 报文不完整, 期望接收更多数据; <0 解析失败
 */
typedef int32_t (*CHECK_SESSION_CALLBACK)(const void* data, uint32_t len,
                                        uint64_t* session_id, uint32_t* need_len);


/**
 * @brief 网络接口类定义
 */
class CNetHelper
{
public:

    // 转发返回码信息, 按需获取
    static char* GetErrMsg(int32_t result);

    // 同步收发接口
    int32_t SendRecv(void* data, uint32_t len, uint32_t timeout);

    // 获取返回buff信息, 有效期直到helper析构
    void* GetRspBuff();

    // 获取返回包的长度
    uint32_t GetRspLen();    

    // 设置协议的类型, 默认UDP
    void SetProtoType(MT_PROTO_TYPE type);

    // 设置目的IP地址
	void SetDestAddress(struct sockaddr_in* dst);

	// 设置session本次session id信息, 必须非0
	void SetSessionId(uint64_t sid);	

    // 设置session解析回调函数
    void SetSessionCallback(CHECK_SESSION_CALLBACK function);

    // 构造与虚构
    CNetHelper();
    ~CNetHelper();

private:

    void*    handler;               // 私有句柄, 利于扩展
};


}

#endif


