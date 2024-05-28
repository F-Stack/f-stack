
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
 *  @filename mt_cache.h
 */

#ifndef ___MT_BUFFER_CACHE_H
#define ___MT_BUFFER_CACHE_H

#include <stdint.h>
#include <sys/queue.h>


namespace NS_MICRO_THREAD {

#define SK_DFLT_BUFF_SIZE   64*1024   
#define SK_DFLT_ALIGN_SIZE  8 

#define SK_ERR_NEED_CLOSE   10000


typedef struct _sk_buffer_tag
{
    TAILQ_ENTRY(_sk_buffer_tag) entry;
    uint32_t                    last_time;
    uint32_t                    size;
    uint8_t*                    head;
    uint8_t*                    end;
    uint8_t*                    data;
    uint32_t                    data_len;
    uint8_t                     buff[0];
} TSkBuffer;
typedef TAILQ_HEAD(__sk_buff_list, _sk_buffer_tag) TSkBuffList;


TSkBuffer* new_sk_buffer(uint32_t size = SK_DFLT_BUFF_SIZE);

void delete_sk_buffer(TSkBuffer* buff);

TSkBuffer* reserve_sk_buffer(TSkBuffer* buff, uint32_t size);

typedef struct _sk_buff_mng_tag
{
    TSkBuffList                 free_list;
    uint32_t                    expired;
    uint32_t                    size;
    uint32_t                    count;
} TSkBuffMng;

void sk_buffer_mng_init(TSkBuffMng* mng, uint32_t expired, uint32_t size = SK_DFLT_BUFF_SIZE);

void sk_buffer_mng_destroy(TSkBuffMng * mng);

TSkBuffer* alloc_sk_buffer(TSkBuffMng* mng);

void free_sk_buffer(TSkBuffMng* mng, TSkBuffer* buff);

void recycle_sk_buffer(TSkBuffMng* mng, uint32_t now);

typedef struct _sk_rw_cache_tag
{
    TSkBuffList                 list;
    uint32_t                    len;
    uint32_t                    count;
    TSkBuffMng                 *pool;
} TRWCache;

void rw_cache_init(TRWCache* cache, TSkBuffMng* pool);

void rw_cache_destroy(TRWCache* cache);

void cache_skip_data(TRWCache* cache, uint32_t len);

TSkBuffer* cache_skip_first_buffer(TRWCache* cache);

int32_t cache_append_data(TRWCache* cache, const void* data, uint32_t len);

void cache_append_buffer(TRWCache* cache, TSkBuffer* buff);

uint32_t cache_copy_out(TRWCache* cache, void* buff, uint32_t len);

int32_t cache_udp_recv(TRWCache* cache, uint32_t fd, struct sockaddr_in* remote_addr);

int32_t cache_tcp_recv(TRWCache* cache, uint32_t fd);

int32_t cache_tcp_send(TRWCache* cache, uint32_t fd);

int32_t cache_tcp_send_buff(TRWCache* cache, uint32_t fd, const void* data, uint32_t len);


// interface
typedef void*  TBuffVecPtr;
typedef void*  TBuffBlockPtr;

uint32_t get_data_len(TBuffVecPtr multi);

uint32_t get_block_count(TBuffVecPtr multi);

TBuffBlockPtr get_first_block(TBuffVecPtr multi);

TBuffBlockPtr get_next_block(TBuffVecPtr multi, TBuffBlockPtr block);

void get_block_data(TBuffBlockPtr block, const void** data, int32_t* len);

uint32_t read_cache_data(TBuffVecPtr multi, void* data, uint32_t len);

uint32_t read_cache_begin(TBuffVecPtr multi, uint32_t begin, void* data, uint32_t len);

};

#endif
