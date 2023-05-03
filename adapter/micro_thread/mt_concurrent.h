
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


int mt_msg_sendrcv(IMtActList& req_list, int timeout);

int mt_multi_netfd_poll(IMtActList& req_list, int how, int timeout);

int mt_multi_newsock(IMtActList& req_list);

int mt_multi_open(IMtActList& req_list, int timeout);

int mt_multi_sendto(IMtActList& req_list, int timeout);

int mt_multi_recvfrom(IMtActList& req_list, int timeout);

int mt_multi_sendrcv_ex(IMtActList& req_list, int timeout);

}



#endif


