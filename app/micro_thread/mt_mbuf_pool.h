
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
    BUFF_UNDEF          =  0,
    BUFF_RECV           =  1,
    BUFF_SEND           =  2,
};

typedef TAILQ_ENTRY(MtMsgBuf) MsgBufLink;
typedef TAILQ_HEAD(__MtbuffTailq, MtMsgBuf) MsgBufQueue;
class MtMsgBuf
{
private:
    int   _max_len;
    int   _msg_len;
    int   _buf_type;
    int   _recv_len;
    int   _send_len;
    void* _msg_buff;

public:

    MsgBufLink _entry;

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

    void SetBuffType(BUFF_TYPE type) {
        _buf_type = (int)type;
    };
    BUFF_TYPE GetBuffType() {
        return (BUFF_TYPE)_buf_type;
    };

    void Reset() {
        _msg_len  = 0;
        _recv_len = 0;
        _send_len = 0;
        _buf_type = BUFF_UNDEF;
    };

    void SetMsgLen(int msg_len) {
        _msg_len = msg_len;
    };
    int GetMsgLen() {
        return _msg_len;
    };

    int GetMaxLen() {
        return _max_len;
    };
    void* GetMsgBuff() {
        return _msg_buff;
    };

    int GetHaveSndLen() {
        return _send_len;
    };
    void SetHaveSndLen(int snd_len) {
        _send_len = snd_len;
    };


    int GetHaveRcvLen() {
        return _recv_len;
    };
    void SetHaveRcvLen(int rcv_len) {
        _recv_len = rcv_len;
    };
};

class MsgBufMap : public HashKey
{
public:

    MsgBufMap(int buff_size, int max_free) {
        _max_buf_size = buff_size;
        _max_free     = max_free;
        this->SetDataPtr(this);
        _queue_num    = 0;
        TAILQ_INIT(&_msg_queue);
    };

    explicit MsgBufMap(int buff_size) {
        _max_buf_size = buff_size;
        TAILQ_INIT(&_msg_queue);
    };

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

    void FreeMsgBuf(MtMsgBuf* ptr){
        if (_queue_num >= _max_free) {
            delete ptr;
        } else {
            ptr->Reset();
            TAILQ_INSERT_TAIL(&_msg_queue, ptr, _entry);
            _queue_num++;
        }
    };

    virtual uint32_t HashValue(){
        return _max_buf_size;
    }; 

    virtual int HashCmp(HashKey* rhs){
        return this->_max_buf_size - (int)rhs->HashValue();
    }; 

private:
    int _max_free;
    int _max_buf_size;
    int _queue_num;
    MsgBufQueue _msg_queue;
};

class MsgBuffPool
{
public:

    static MsgBuffPool* Instance (void);

    static void Destroy(void);

    void SetMaxFreeNum(int max_free) {
        _max_free = max_free;
    };

    MtMsgBuf* GetMsgBuf(int max_size);

    void FreeMsgBuf(MtMsgBuf* msg_buf);

    ~MsgBuffPool();

private:

    explicit MsgBuffPool(int max_free = 300);

    static MsgBuffPool * _instance; 
    int  _max_free;
    HashList* _hash_map;

};

}

#endif


