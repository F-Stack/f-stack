
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
 * @file  heap_timer.h
 */

#ifndef _MICRO_THREAD_TIMER_H_
#define _MICRO_THREAD_TIMER_H_

#include <stdint.h>
#include "heap.h"

namespace NS_MICRO_THREAD
{

class CTimerNotify : public HeapEntry
{
public:

    virtual void timer_notify() { return;};

    virtual unsigned long long HeapValue() {
        return (unsigned long long)_time_expired;
    }; 

    CTimerNotify() : _time_expired(0) {};

    virtual ~CTimerNotify(){};

    void set_expired_time(uint64_t expired) {
        _time_expired = expired;    
    };

    uint64_t get_expired_time() {
        return _time_expired;        
    };

private:

    uint64_t        _time_expired;
};


class CTimerMng
{
public:


    explicit CTimerMng(uint32_t max_item = 100000);    

    ~CTimerMng();

    bool start_timer(CTimerNotify* timerable, uint32_t interval);    

    void stop_timer(CTimerNotify* timerable);

    void check_expired();

private:
    
    HeapList*           _heap;
};

}

#endif

