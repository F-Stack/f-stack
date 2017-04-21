
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
 *  @file mt_mbuf_pool.h
 *  @info 微线程同步消息buf池
 **/

#ifndef __MT_MBUF_POOL_H__
#define __MT_MBUF_POOL_H__

#include <netinet/in.h>
#include <queue>
#include "hash_list.h"

namespace NS_MICRO_THREAD {

using std::queue;

enum BUFF_TYPE
{
    BUFF_UNDEF          =  0,           ///< 未定义类型
    BUFF_RECV           =  1,           ///< 接收buff
    BUFF_SEND           =  2,           ///< 发送buff
};

/**
 * @brief 消息投递的buffer类
 */
typedef TAILQ_ENTRY(MtMsgBuf) MsgBufLink;
typedef TAILQ_HEAD(__MtbuffTailq, MtMsgBuf) MsgBufQueue;
class MtMsgBuf
{
private:
    int   _max_len;         // 最大的空间长度
    int   _msg_len;         // 实际的消息长度
    int   _buf_type;        // buff是发送还是接收
    int   _recv_len;        // 已接收的消息长度
    int   _send_len;        // 已发送的消息长度
    void* _msg_buff;        // buffer 实际头指针

public:

    MsgBufLink _entry;

    /**
     * @brief 构造函数, 指定最大buff长度
     */
    MtMsgBuf(int max_len) {
        _max_len  = max_len;
        _msg_len  = 0;
        _buf_type = BUFF_UNDEF;
        _recv_len = 0;
        _send_len = 0;
        _msg_buff = malloc(max_len);
    };

    ~MtMsgBuf() {
        if (_msg_buff) {
            free(_msg_buff);
            _msg_buff = NULL;
        }
    };

    /**
     * @brief 消息类型的设置与读取
     */
    void SetBuffType(BUFF_TYPE type) {
        _buf_type = (int)type;
    };
    BUFF_TYPE GetBuffType() {
        return (BUFF_TYPE)_buf_type;
    };

    /**
     * @brief 复用接口, 恢复初始状态
     */
    void Reset() {
        _msg_len  = 0;
        _recv_len = 0;
        _send_len = 0;
        _buf_type = BUFF_UNDEF;
    };

    /**
     * @brief 消息长度的设置与读取
     */
    void SetMsgLen(int msg_len) {
        _msg_len = msg_len;
    };
    int GetMsgLen() {
        return _msg_len;
    };

    /**
     * @brief 最大长度与buffer指针获取
     */
    int GetMaxLen() {
        return _max_len;
    };
    void* GetMsgBuff() {
        return _msg_buff;
    };

    /**
     * @brief 中间状态获取与更新
     */
    int GetHaveSndLen() {
        return _send_len;
    };
    void SetHaveSndLen(int snd_len) {
        _send_len = snd_len;
    };

    /**
     * @brief 中间状态获取与更新
     */
    int GetHaveRcvLen() {
        return _recv_len;
    };
    void SetHaveRcvLen(int rcv_len) {
        _recv_len = rcv_len;
    };
};

/**
 * @brief 指定大小的buffer, 按最大长度映射成空闲队列
 */
class MsgBufMap : public HashKey
{
public:

    /**
     *  @brief 消息buff管理的构造
     *  @param buff_size 该map元素上的所有buff, 其最大buff空间大小值
     *  @param max_free 该队列管理元素, 最大保持的free数目
     */
    MsgBufMap(int buff_size, int max_free) {
        _max_buf_size = buff_size;
        _max_free     = max_free;
        this->SetDataPtr(this);
        _queue_num    = 0;
        TAILQ_INIT(&_msg_queue);
    };

    /**
     *  @brief 消息buff管理的构造, 简单构造, 仅设置key信息
     *  @param buff_size 该map元素上的所有buff, 其最大buff空间大小值
     */
    explicit MsgBufMap(int buff_size) {
        _max_buf_size = buff_size;
        TAILQ_INIT(&_msg_queue);
    };

    /**
     *  @brief 消息buff管理的析构清理
     */
    ~MsgBufMap() {
        MtMsgBuf* ptr = NULL;
        MtMsgBuf* tmp = NULL;
        TAILQ_FOREACH_SAFE(ptr, &_msg_queue, _entry, tmp)
        {
            TAILQ_REMOVE(&_msg_queue, ptr, _entry);
            delete ptr;
            _queue_num--;
        }
        
        TAILQ_INIT(&_msg_queue);
    };
    
    /**
     *  @brief 获取消息buff元素
     *  @return msgbuf指针, 失败为NULL
     */
    MtMsgBuf* GetMsgBuf(){
        MtMsgBuf* ptr = NULL;        
        if (!TAILQ_EMPTY(&_msg_queue)) {
            ptr = TAILQ_FIRST(&_msg_queue);
            TAILQ_REMOVE(&_msg_queue, ptr, _entry);
            _queue_num--;
        } else {
            ptr = new MtMsgBuf(_max_buf_size);
        }
        
        return ptr;
    };

    /**
     *  @brief 释放消息buff元素
     *  @param msgbuf指针
     */
    void FreeMsgBuf(MtMsgBuf* ptr){
        if (_queue_num >= _max_free) {
            delete ptr;
        } else {
            ptr->Reset();
            TAILQ_INSERT_TAIL(&_msg_queue, ptr, _entry);
            _queue_num++;
        }
    };

    /**
     *  @brief 节点元素的hash算法, 获取key的hash值
     *  @return 节点元素的hash值
     */
    virtual uint32_t HashValue(){
        return _max_buf_size;
    }; 

    /**
     *  @brief 节点元素的cmp方法, 同一桶ID下, 按key比较
     *  @return 节点元素的hash值
     */
    virtual int HashCmp(HashKey* rhs){
        return this->_max_buf_size - (int)rhs->HashValue();
    }; 

private:
    int _max_free;              ///< 最大空闲保留个数
    int _max_buf_size;          ///< 本队列最大的buffsize
    int _queue_num;             ///< 空闲队列个数
    MsgBufQueue _msg_queue;     ///< 实际的空闲队列
};


/**
 * @brief 全局的buffer池对象, 统一分配与回收buffer
 */
class MsgBuffPool
{
public:

    /**
     * @brief 消息buff的全局管理句柄接口
     * @return 全局句柄指针
     */
    static MsgBuffPool* Instance (void);

    /**
     * @brief 消息清理接口
     */
    static void Destroy(void);

    /**
     * @brief 消息buff的全局管理设置默认最大的空闲个数
     * @param max_free 最大空闲保留数目, 需要在分配元素前设置
     */
    void SetMaxFreeNum(int max_free) {
        _max_free = max_free;
    };

    /**
     *  @brief 获取消息buff元素
     *  @return msgbuf指针, 失败为NULL
     */
    MtMsgBuf* GetMsgBuf(int max_size);

    /**
     *  @brief 释放消息buff元素
     *  @param msgbuf指针
     */
    void FreeMsgBuf(MtMsgBuf* msg_buf);

    /**
     * @brief 消息buff的全局类析构函数
     */
    ~MsgBuffPool();

private:

    /**
     * @brief 消息buff的构造函数
     */
    explicit MsgBuffPool(int max_free = 300);

    static MsgBuffPool * _instance;         ///<  单例类句柄    
    int  _max_free;                         ///<  最大保留空闲数目
    HashList* _hash_map;                    ///<  按size hashmap 保存空闲队列

};



}

#endif


