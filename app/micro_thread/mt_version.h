
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
 *  @file mt_version.h
 *  @info 微线程版本更新与记录信息文件
 *  @time 20131018
 *  ------------------------------------------------------------------------
 *  @brief v0.2.0 - 支持UDP按session模式映射上下文
 *         v0.2.1 - 支持TCP的sendrcv接口
 *         v0.2.3 - 实时时间戳
 *         v0.2.4 - 支持TCP的sendrcv接口动态扩展接收buf
 */

#ifndef _MT_VERSION_EX__
#define _MT_VERSION_EX__

namespace NS_MICRO_THREAD {

__attribute__((weak)) char IMT_VERSION[64] = "mt version: 0.2.4";

} // NAMESPACE NS_MICRO_THREAD

#endif

