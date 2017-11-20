
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
 * @file  heap_timer.cpp
 */

#include "heap_timer.h"
#include "micro_thread.h"

using namespace NS_MICRO_THREAD;

CTimerMng::CTimerMng(uint32_t max_item)
{
    #define TIMER_MIN 100000

    if (max_item < TIMER_MIN)
    {
        max_item = TIMER_MIN;
    }

    _heap = new HeapList(max_item);
}

CTimerMng::~CTimerMng()
{
    if (_heap) {
        delete _heap;
        _heap = NULL;
    }
}

bool CTimerMng::start_timer(CTimerNotify* timerable, uint32_t interval)
{
    if (!_heap || !timerable) {
        return false;
    }

    utime64_t now_ms = MtFrame::Instance()->GetLastClock();
    timerable->set_expired_time(now_ms + interval);
    int32_t ret = _heap->HeapPush(timerable);
    if (ret < 0) {
        MTLOG_ERROR("timer start failed(%p), ret(%d)", timerable, ret);
        return false;
    }

    return true;
}

void CTimerMng::stop_timer(CTimerNotify* timerable)
{
    if (!_heap || !timerable) {
        return;
    }
    
    _heap->HeapDelete(timerable);
    return;
}

void CTimerMng::check_expired() 
{
    if (!_heap) {
        return;
    }
    
    utime64_t now = MtFrame::Instance()->GetLastClock();
    CTimerNotify* timer = dynamic_cast<CTimerNotify*>(_heap->HeapTop());
    while (timer && (timer->get_expired_time() <= now))
    {
        _heap->HeapDelete(timer);
        timer->timer_notify();
        timer = dynamic_cast<CTimerNotify*>(_heap->HeapTop());
    }    
};
