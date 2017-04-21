
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
 *  @file mt_msg.h
 *  @info 微线程同步消息的基类
 **/

#ifndef __MT_MSG_H__
#define __MT_MSG_H__

namespace NS_MICRO_THREAD {

/**
 * @brief  微线程消息处理基类
 */
class IMtMsg
{
public:

    /**
     * @brief  微线程消息类的处理流程入口函数
     * @return 0 -成功, < 0 失败 
     */
    virtual int HandleProcess() { return -1; };
 
    /**
     * @brief  微线程消息基类构造与析构
     */
    IMtMsg() {};
    virtual ~IMtMsg() {};
};


}

#endif

