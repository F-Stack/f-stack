
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
 *  @filename mt_cache.cpp
 */
 
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include "mt_incl.h"
#include "kqueue_proxy.h"
#include "micro_thread.h"
#include "mt_sys_hook.h"
#include "ff_hook.h"

#include "mt_cache.h"

namespace NS_MICRO_THREAD {

TSkBuffer* new_sk_buffer(uint32_t size)
{
    uint32_t total = sizeof(TSkBuffer) + size;
    total = (total + SK_DFLT_ALIGN_SIZE - 1) / SK_DFLT_ALIGN_SIZE * SK_DFLT_ALIGN_SIZE;
    TSkBuffer* block = (TSkBuffer*)malloc(total);
    if (block == NULL) 
    {
        MTLOG_ERROR("malloc failed, no more memory[%u]", total);
        return NULL;
    }

    block->last_time = 0;
    block->size = size;
    block->head = block->buff;
    block->end  = block->buff + size;
    
    block->data = block->head;
    block->data_len = 0;

    return block;
}

void delete_sk_buffer(TSkBuffer* block)
{
    if (NULL == block) {
        return;
    }

    free(block);
}

TSkBuffer* reserve_sk_buffer(TSkBuffer* buff, uint32_t size)
{
    if (NULL == buff) {
        return new_sk_buffer(size);   
    }

    if (buff->size >= size) {
        return buff;
    }

    TSkBuffer* new_buff = new_sk_buffer(size);
    if (NULL == new_buff) {
        return buff;
    }
    memcpy(new_buff->data, buff->data, buff->data_len);
    new_buff->data_len = buff->data_len;
    delete_sk_buffer(buff);

    return new_buff;
}

void sk_buffer_mng_init(TSkBuffMng* mng, uint32_t expired, uint32_t size)
{
    TAILQ_INIT(&mng->free_list);
    mng->expired  = expired;
    mng->count = 0;
    mng->size = size;
}

void sk_buffer_mng_destroy(TSkBuffMng * mng)
{
    TSkBuffer* item = NULL;
    TSkBuffer* tmp = NULL;
    TAILQ_FOREACH_SAFE(item, &mng->free_list, entry, tmp)
    {
        TAILQ_REMOVE(&mng->free_list, item, entry);
        delete_sk_buffer(item);
    }
    mng->count = 0;
}

TSkBuffer* alloc_sk_buffer(TSkBuffMng* mng)
{
    if (NULL == mng) {
        return NULL;
    }

    TSkBuffer* item = TAILQ_FIRST(&mng->free_list);
    if (item != NULL)
    {
        TAILQ_REMOVE(&mng->free_list, item, entry);
        mng->count--;
        return item;
    }

    item = new_sk_buffer(mng->size);
    if (NULL == item)
    {
        return NULL;
    }

    return item;
}

void free_sk_buffer(TSkBuffMng* mng, TSkBuffer* buff)
{
    if ((NULL == mng) || (NULL == buff)) {
        return;
    }
    
    TAILQ_INSERT_TAIL(&mng->free_list, buff, entry);
    mng->count++;
    
    buff->last_time = (uint32_t)(mt_time_ms() / 1000);
    buff->data = buff->head;
    buff->data_len = 0;
}

void recycle_sk_buffer(TSkBuffMng* mng, uint32_t now)
{
    TSkBuffer* item = NULL;
    TSkBuffer* tmp = NULL;
    TAILQ_FOREACH_SAFE(item, &mng->free_list, entry, tmp)
    {
        if ((now - item->last_time) < mng->expired)
        {
            break;
        }
    
        TAILQ_REMOVE(&mng->free_list, item, entry);
        delete_sk_buffer(item);
        mng->count--;
    }
}

void rw_cache_init(TRWCache* cache, TSkBuffMng* pool)
{
    TAILQ_INIT(&cache->list);
    cache->len = 0;
    cache->count = 0;
    cache->pool = pool;
}

void rw_cache_destroy(TRWCache* cache)
{
    if ((cache == NULL) || (cache->pool == NULL)) {
        return;
    }

    TSkBuffer* item = NULL;
    TSkBuffer* tmp = NULL;
    TAILQ_FOREACH_SAFE(item, &cache->list, entry, tmp)
    {
        TAILQ_REMOVE(&cache->list, item, entry);
        free_sk_buffer(cache->pool, item);
    }
    cache->count = 0;
    cache->len = 0;
    cache->pool = NULL;
}

uint32_t cache_copy_out(TRWCache* cache, void* buff, uint32_t len)
{
    if ((cache == NULL) || (cache->pool == NULL)) {
        return 0;
    }
    
    char* out_buff = (char*)buff;
    uint32_t left = len, skip_len = 0;
    TSkBuffer* item = NULL;
    TSkBuffer* tmp = NULL;
    TAILQ_FOREACH_SAFE(item, &cache->list, entry, tmp)
    {
        skip_len = (item->data_len > left) ? left : item->data_len;
        if (out_buff != NULL)
        {
            memcpy(out_buff, item->data, skip_len);
            out_buff += skip_len;
        }
        
        left -= skip_len;
        item->data_len -= skip_len;
        item->data += skip_len;
        if (item->data_len > 0)
        {
            break;
        }
  
        if (cache->count > 0) {
            cache->count--;
        }
        TAILQ_REMOVE(&cache->list, item, entry);
        free_sk_buffer(cache->pool, item);

        if (left == 0)
        {
            break;
        }
    }

    skip_len = len - left;
    if (cache->len > skip_len) 
    { 
        cache->len -= skip_len;
    }
    else
    {
        cache->len = 0;
    }

    return skip_len;
}

void cache_skip_data(TRWCache* cache, uint32_t len)
{
    cache_copy_out(cache, NULL, len);
}

void cache_append_buffer(TRWCache* cache, TSkBuffer* buff)
{
    if ((NULL == cache) || (NULL == buff)) 
    {
        return;
    }

    TAILQ_INSERT_TAIL(&cache->list, buff, entry);
    cache->len += buff->data_len;
    cache->count++;
}

TSkBuffer* cache_skip_first_buffer(TRWCache* cache)
{
    TSkBuffer* buff = TAILQ_FIRST(&cache->list);
    if ((NULL == cache) || (NULL == buff)) 
    {
        return NULL;
    }

    TAILQ_REMOVE(&cache->list, buff, entry);
    if (cache->len >= buff->data_len) 
    {
        cache->len -= buff->data_len;
    }

    if (cache->count > 0)
    {   
        cache->count--;
    }

    return buff;
}

int32_t cache_append_data(TRWCache* cache, const void* data, uint32_t len)
{
    if ((NULL == data) || (NULL == cache) || (NULL == cache->pool)) 
    {
        return -1;
    }

    if (len == 0)
    {
        return 0;
    }

    uint32_t left = len;
    uint32_t remain = 0;

    TSkBuffer* tail = TAILQ_LAST(&cache->list, __sk_buff_list);
    if (tail != NULL)
    {
        if (tail->end > (tail->data + tail->data_len))
        {
            remain = tail->end - tail->data - tail->data_len;
        }
        
        if (remain >= len)
        {
            memcpy(tail->data + tail->data_len, data, len);
            tail->data_len += len;
            cache->len += len;
            return (int32_t)len;
        }
    }

    TRWCache keep_list;
    rw_cache_init(&keep_list, cache->pool);
    left -= remain;
    while (left > 0)
    {
        TSkBuffer* item = alloc_sk_buffer(cache->pool);
        if (item == NULL) 
        {
            rw_cache_destroy(&keep_list);
            return -2;
        }
        cache_append_buffer(&keep_list, item);

        if (left <= item->size)
        {
            memcpy(item->head, (char*)data + len - left, left);
            item->data_len = left;
            break;
        }
        
        memcpy(item->head, (char*)data + len - left, item->size);
        item->data_len = item->size;
        left -= item->size;
    }

    if ((tail != NULL) && (remain > 0))
    {
        memcpy(tail->data + tail->data_len, data, remain);
        tail->data_len += remain;
    }

    cache->len += len;
    cache->count += keep_list.count;
    TAILQ_CONCAT(&cache->list, &keep_list.list, entry);

    return (int32_t)len;
}

int32_t cache_udp_recv(TRWCache* cache, uint32_t fd, struct sockaddr_in* remote_addr)
{
    if (NULL == cache)
    {
        return -1;
    }

    int32_t total = 0;
    for (uint32_t i = 0; i < 100; i++)
    {
        TSkBuffer* item = alloc_sk_buffer(cache->pool);
        if (NULL == item)
        {
            return -2;
        }

        socklen_t addr_len = sizeof(*remote_addr); 
        mt_hook_syscall(recvfrom);
        int32_t rc = ff_hook_recvfrom(fd, item->data, item->size, 0, (struct sockaddr*)remote_addr, &addr_len);
        if (rc <= 0)
        {
            free_sk_buffer(cache->pool, item);
            
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
            {
                break;
            }
            else
            {
                MTLOG_ERROR("recvfrom failed, fd[%d] ret %d[%m]", fd, rc);
                return -3;
            }
        }
        
        item->data_len += rc;
        cache_append_buffer(cache, item);
        total += rc;
    }
    
    return total;
}

int32_t cache_tcp_recv(TRWCache* cache, uint32_t fd)
{
    if (NULL == cache)
    {
        return -1;
    }

    int32_t total = 0;
    for (uint32_t i = 0; i < 100; i++)
    {
        TSkBuffer* item = TAILQ_LAST(&cache->list, __sk_buff_list);
        if ((NULL == item) 
            || ((item->data_len + item->data) >= item->end))
        {
            item = alloc_sk_buffer(cache->pool);
            if (item == NULL)
            {
               return -2;
            }
            cache_append_buffer(cache, item);
        }

        uint8_t* buff = item->data + item->data_len;
        uint32_t remain = item->end - item->data - item->data_len;
        mt_hook_syscall(recv);
        int32_t recvd_len = ff_hook_recv(fd, buff, remain, 0);
        if (recvd_len == 0)
        {
            MTLOG_DEBUG("remote close, socket: %d", fd);
            return -SK_ERR_NEED_CLOSE;
        }
        else if (recvd_len < 0)
        {
            if (errno == EAGAIN)
            {
                return total;
            }
            else
            {
                MTLOG_ERROR("recv tcp socket failed, error: %d[%m]", errno);
                return -2;
            }
        }
        else
        {
            item->data_len += recvd_len;
            cache->len += recvd_len;
            total += recvd_len;
            if (recvd_len < (int32_t)remain)
            {
                return total;
            }
        }
    }
   
    return total;
}

int32_t cache_tcp_send(TRWCache* cache, uint32_t fd)
{
    if ((NULL == cache) || (NULL == cache->pool))
    {
        return -1;
    }

    if (cache->len == 0)
    {
        return 0;
    }

    int32_t ret = 0, total = 0;
    TSkBuffer* item = NULL;
    TSkBuffer* tmp = NULL;
    TAILQ_FOREACH_SAFE(item, &cache->list, entry, tmp)
    {
        mt_hook_syscall(send);
        ret = ff_hook_send(fd, item->data, item->data_len, 0);
        if (ret < 0)
        {
            break;
        }
        
        total += ret;
        if (ret < (int32_t)item->data_len)
        {
            break;
        }
    }

    cache_skip_data(cache, total);
    if (ret < 0)
    {
        if (errno != EAGAIN)
        {
            MTLOG_ERROR("tcp socket send failed, error: %d[%m]", errno);
            return -2;
        }
    }

    return total;
}

int32_t cache_tcp_send_buff(TRWCache* cache, uint32_t fd, const void* data, uint32_t len)
{
    if ((NULL == cache) || (NULL == data))
    {
        return -1;
    }

    int32_t ret = cache_tcp_send(cache, fd);
    if (ret < 0)
    {
        MTLOG_ERROR("tcp socket[%d] send cache data failed, rc: %d", fd, ret);
        return ret;
    }

    int32_t send_len = 0;
    if (cache->len == 0)
    {
        mt_hook_syscall(send);
        ret = ff_hook_send(fd, data, len, 0);
        if (ret >= 0)
        {
            send_len += ret;
        }
        else
        {
            if (errno != EAGAIN)
            {
                MTLOG_ERROR("tcp socket[%d] send failed, error: %d[%m]", fd, errno);
                return -2;
            }
        }
    }

    int32_t rc = cache_append_data(cache, (char*)data + send_len, len - send_len);
    if (rc < 0)
    {
        MTLOG_ERROR("tcp socket[%d] apend data failed, rc: %d", fd, rc);
        return -3;
    }

    return send_len;
}

uint32_t get_data_len(TBuffVecPtr multi)
{
    TRWCache* cache = (TRWCache*)multi;
    if (NULL == cache) {
        return 0;
    } else {
        return cache->len;
    }
}

uint32_t get_block_count(TBuffVecPtr multi)
{
    TRWCache* cache = (TRWCache*)multi;
    if (NULL == cache) {
        return 0;
    } else {
        return cache->count;
    }
}

TBuffBlockPtr get_first_block(TBuffVecPtr multi)
{
    TRWCache* cache = (TRWCache*)multi;
    if (NULL == cache) {
        return NULL;
    } else {
        return (TBuffBlockPtr)TAILQ_FIRST(&cache->list);
    }
}

TBuffBlockPtr get_next_block(TBuffVecPtr multi, TBuffBlockPtr block)
{
    TRWCache* cache = (TRWCache*)multi;
    TSkBuffer* item = (TSkBuffer*)block;
    if ((NULL == cache) || (NULL == item))
    {
        return NULL;
    }

    return (TBuffBlockPtr)TAILQ_NEXT(item, entry);

}

void get_block_data(TBuffBlockPtr block, const void** data, int32_t* len)
{
    TSkBuffer* item = (TSkBuffer*)block;
    if (NULL == block)
    {
        return;
    }

    if (data != NULL) 
    {
        *(uint8_t**)data = item->data;
    }

    if (len != NULL)
    {
        *len = (int32_t)item->data_len;
    }
}

uint32_t read_cache_data(TBuffVecPtr multi, void* data, uint32_t len)
{
    TRWCache* cache = (TRWCache*)multi;
    if (NULL == cache) {
        return 0;
    }
    
    uint32_t left_len = len;
    uint32_t offset = 0;
    TSkBuffer* item = NULL;
    TSkBuffer* tmp = NULL;
    TAILQ_FOREACH_SAFE(item, &cache->list, entry, tmp)
    {
        uint32_t copy_len = 0;
        if (left_len <= item->data_len)
        {
            copy_len = left_len;
        }
        else
        {
            copy_len = item->data_len;
        }

        if (data != NULL)
        {
            memcpy((char*)data + offset, item->data, copy_len);
        }
        offset += copy_len;
        left_len -= copy_len;

        if (left_len <= 0)
        {
            break;
        }
    }

    return offset;
}

uint32_t read_cache_begin(TBuffVecPtr multi, uint32_t begin, void* data, uint32_t len)
{
    TRWCache* cache = (TRWCache*)multi;
    if (NULL == cache) {
        return 0;
    }

    if (begin >= cache->len) {
        return 0;
    }

    uint32_t pos_left = begin;
    uint32_t copy_left = len;
    uint32_t offset = 0;
    TSkBuffer* item = NULL;
    TAILQ_FOREACH(item, &cache->list, entry)
    {
        uint8_t* start_ptr = item->data;
        uint32_t real_left = item->data_len;
        if (pos_left > 0)
        {
            uint32_t skip_len = pos_left > real_left ? real_left : pos_left;
            pos_left -= skip_len;
            real_left -= skip_len;
            start_ptr += skip_len;
        }

        if (real_left == 0)
        {
            continue;
        }

        uint32_t copy_len = copy_left > real_left ? real_left : copy_left;
        if (data != NULL)
        {
            memcpy((char*)data + offset, start_ptr, copy_len);
        }
        offset += copy_len;
        copy_left -= copy_len;
        if (copy_left == 0)
        {
            break;
        }
    }

    return offset;
}

};
