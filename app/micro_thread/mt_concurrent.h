
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
 *  @file mt_concurrent.h
 *  @info 扩展状态线程的处理模型
 *  @time 20130515
 **/

#ifndef __MT_CONCURRENT_H__
#define __MT_CONCURRENT_H__

#include <netinet/in.h>
#include <vector>

namespace NS_MICRO_THREAD {

using std::vector;

class IMtAction;
typedef vector<IMtAction*>  IMtActList;

/******************************************************************************/
/*  微线程用户接口定义: 微线程Action多路并发模型接口定义                      */
/******************************************************************************/

/**
 * @brief 多路IO并发接收处理接口, 封装ACTON接口模型, 内部关联msg
 * @param req_list -action list 实现封装函数接口
 * @param timeout -超时时间, 单位ms
 * @return  0 成功, -1 打开socket失败, -2 发送请求失败, -100 接收应答部分失败, 可打印errno
 */
int mt_msg_sendrcv(IMtActList& req_list, int timeout);

/******************************************************************************/
/*  内部实现定义部分                                                          */
/******************************************************************************/

/**
 * @brief 多路IO的处理优化, 异步调度等待处理
 * @param req_list - 连接列表
 * @param how - EPOLLIN  EPOLLOUT
 * @param timeout - 超时时长 毫秒单位
 * @return 0 成功, <0失败 -3 处理超时
 */
int mt_multi_netfd_poll(IMtActList& req_list, int how, int timeout);

/**
 * @brief 为每个ITEM建立上下文的socket
 * @param req_list - 连接列表
 * @return 0 成功, <0失败
 */
int mt_multi_newsock(IMtActList& req_list);

/**
 * @brief 多路IO的处理, 打开连接
 * @param req_list - 连接列表
 * @param timeout - 超时时长 毫秒单位
 * @return 0 成功, <0失败
 */
int mt_multi_open(IMtActList& req_list, int timeout);

/**
 * @brief 多路IO的处理, 发送数据
 * @param req_list - 连接列表
 * @param timeout - 超时时长 毫秒单位
 * @return 0 成功, <0失败
 */
int mt_multi_sendto(IMtActList& req_list, int timeout);

/**
 * @brief 多路IO并发接收处理
 */
int mt_multi_recvfrom(IMtActList& req_list, int timeout);

/**
 * @brief 多路IO并发接收处理
 */
int mt_multi_sendrcv_ex(IMtActList& req_list, int timeout);

}



#endif


