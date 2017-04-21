
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

/**
 * @brief 定时器对象基类
 */
class CTimerNotify : public HeapEntry
{
public:

    /**
     * @brief 超时通知函数, 子类实现逻辑
     */
    virtual void timer_notify() { return;};
    
    /**
     *  @brief 堆元素取值函数, 用于返回值比较, 需子函数实现, 否则默认无序
     *  @return 堆元素映射的值
     */
    virtual unsigned long long HeapValue() {
        return (unsigned long long)_time_expired;
    }; 

    /**
     * @brief 构造函数
     */
    CTimerNotify() : _time_expired(0) {};

    /**
     * @brief 虚析构函数
     */
    virtual ~CTimerNotify(){};

    /**
     * @brief 设置绝对超时时间, 单位ms
     * @param expired 绝对超时时间 ms单位
     */
    void set_expired_time(uint64_t expired) {
        _time_expired = expired;    
    };

    /**
     * @brief 获取绝对超时时间, 单位ms
     * @return 绝对超时时间 ms单位
     */
    uint64_t get_expired_time() {
        return _time_expired;        
    };

private:

    uint64_t        _time_expired;     // 绝对的超时时间ms单位
};


/**
 * @brief 定时器管理单例类
 */
class CTimerMng
{
public:


    /**
     * @brief 构造函数
     * @param max_item 最大可管理的定时器对象数目(指针数目)
     */
    explicit CTimerMng(uint32_t max_item = 100000);    

    /**
     * @brief 析构函数
     */
    ~CTimerMng();

    /**
     * @brief 定时器设置函数
     * @param timerable 定时器对象
     * @param interval  超时的间隔 ms单位
     * @return 成功返回true, 否则失败
     */
    bool start_timer(CTimerNotify* timerable, uint32_t interval);    

    /**
     * @brief 定时器停止接口函数
     * @param timerable 定时器对象
     */
    void stop_timer(CTimerNotify* timerable);

    /**
     * @brief 定时器超时检测函数
     */
    void check_expired();

private:
    
    HeapList*           _heap;      // 最小堆指针
};

}

#endif

