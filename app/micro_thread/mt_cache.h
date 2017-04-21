
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
 *  @info   TCP接入buffer管理定义
 */

#ifndef ___MT_BUFFER_CACHE_H
#define ___MT_BUFFER_CACHE_H

#include <stdint.h>
#include <sys/queue.h>


namespace NS_MICRO_THREAD {


// 默认的buff大小
#define SK_DFLT_BUFF_SIZE   64*1024   
#define SK_DFLT_ALIGN_SIZE  8 

#define SK_ERR_NEED_CLOSE   10000

/**
 * @brief  用户态 buffer 结构定义
 */
typedef struct _sk_buffer_tag
{
    TAILQ_ENTRY(_sk_buffer_tag) entry;     // list entry buffer LRU等
    uint32_t                    last_time; // 上次使用时间戳
    uint32_t                    size;      // buffer节点的空间大小
    uint8_t*                    head;      // buff数据区头指针
    uint8_t*                    end;       // buff数据区结束指针
    uint8_t*                    data;      // 有效数据的头指针
    uint32_t                    data_len;  // 有效的数据长度
    uint8_t                     buff[0];   // 原始指针区域
} TSkBuffer;
typedef TAILQ_HEAD(__sk_buff_list, _sk_buffer_tag) TSkBuffList;  // multi 事务命令队列


/**
 * @brief 申请指定大小的buff块
 * @param size 有效数据区大小
 * @return 非NULL为成功返回的buff指针
 */
TSkBuffer* new_sk_buffer(uint32_t size = SK_DFLT_BUFF_SIZE);

/**
 * @brief 释放指定的buff块
 * @param 待释放的buff指针
 */
void delete_sk_buffer(TSkBuffer* buff);


/**
 * @brief 保留更大长度信息(非资源池化的buff,可扩展)
 * @param buff -已有的buff指针
 * @param size -需要扩展的最终长度大小
 * @return 实际的buff信息
 */
TSkBuffer* reserve_sk_buffer(TSkBuffer* buff, uint32_t size);


/**
 * @brief  buffer cache 管理
 */
typedef struct _sk_buff_mng_tag
{
    TSkBuffList                 free_list;      // buff链表 
    uint32_t                    expired;        // 超时时间
    uint32_t                    size;           // buff大小
    uint32_t                    count;          // 块个数
} TSkBuffMng;


/**
 * @brief  cache 池的初始化接口
 * @param  mng -管理池的指针
 * @param  expired -保活的时间, 单位秒
 * @param  size -本管理块默认生成的块大小
 */
void sk_buffer_mng_init(TSkBuffMng* mng, uint32_t expired, uint32_t size = SK_DFLT_BUFF_SIZE);

/**
 * @brief  cache 池的销毁接口
 * @param  mng -管理池的指针
 */
void sk_buffer_mng_destroy(TSkBuffMng * mng);


/**
 * @brief  申请或复用一块buff
 * @param  mng -管理池的指针
 * @return 非NULL为成功获取的buff块指针
 */
TSkBuffer* alloc_sk_buffer(TSkBuffMng* mng);

/**
 * @brief 释放指定的buff块
 * @param  mng -管理池的指针
 * @param  buff -待释放的buff指针
 */
void free_sk_buffer(TSkBuffMng* mng, TSkBuffer* buff);

/**
 * @brief 回收过期的buff块
 * @param  mng -管理池的指针
 * @param  now -当前的时间, 秒级别
 */
void recycle_sk_buffer(TSkBuffMng* mng, uint32_t now);


/**
 * @brief 原始的 buffer cache 定义
 */
typedef struct _sk_rw_cache_tag
{
    TSkBuffList                 list;      // buff链表 
    uint32_t                    len;       // 数据长度
    uint32_t                    count;     // 块个数
    TSkBuffMng                 *pool;      // 全局buff池指针
} TRWCache;


/**
 * @brief Cache管理链初始化
 * @param cache -管理块指针
 * @param pool -buff池指针
 */
void rw_cache_init(TRWCache* cache, TSkBuffMng* pool);

/**
 * @brief Cache管理链销毁
 * @param cache -管理块指针
 */
void rw_cache_destroy(TRWCache* cache);

/**
 * @brief Cache删除掉指定长度数据
 * @param cache -管理块指针
 * @param len -待删除的长度
 */
void cache_skip_data(TRWCache* cache, uint32_t len);

/**
 * @brief Cache移除第一块内存
 * @param cache -管理块指针
 */
TSkBuffer* cache_skip_first_buffer(TRWCache* cache);


/**
 * @brief Cache追加指定长度数据
 * @param cache -管理块指针
 * @param data -待追加的指针
 * @param len -待追加的长度
 */
int32_t cache_append_data(TRWCache* cache, const void* data, uint32_t len);

/**
 * @brief Cache追加指定长度数据
 * @param cache -管理块指针
 * @param buff -待追加的块指针
 */
void cache_append_buffer(TRWCache* cache, TSkBuffer* buff);

/**
 * @brief Cache删除并拷贝指定长度数据
 * @param cache -管理块指针
 * @param buff -存放buff的指针
 * @param len -待删除的长度
 * @return 实际拷贝长度
 */
uint32_t cache_copy_out(TRWCache* cache, void* buff, uint32_t len);


/**
 * @brief Cache整合的UDP收报接口, 消耗内存比较多, 不建议32位使用
 * @param cache -管理块指针
 * @param fd - 准备收报的fd句柄
 * @param remote_addr -对端ip地址
 * @return 实际接收长度
 */
int32_t cache_udp_recv(TRWCache* cache, uint32_t fd, struct sockaddr_in* remote_addr);

/**
 * @brief Cache整合的TCP收报接口
 * @param cache -管理块指针
 * @param fd - 准备收报的fd句柄
 * @return 实际接收长度
 */
int32_t cache_tcp_recv(TRWCache* cache, uint32_t fd);

/**
 * @brief Cache整合的TCP发送接口
 * @param cache -管理块指针
 * @param fd - 准备发包的fd句柄
 * @return 实际发送长度
 */
int32_t cache_tcp_send(TRWCache* cache, uint32_t fd);

/**
 * @brief Cache整合的TCP发送接口, 未使用IOVEC
 * @param cache -管理块指针
 * @param fd - 准备发包的fd句柄
 * @param data -发送完cache后, 继续发送的buff
 * @param len  -继续发送的buff长度
 * @return 实际发送长度
 */
int32_t cache_tcp_send_buff(TRWCache* cache, uint32_t fd, const void* data, uint32_t len);





// interface
typedef void*  TBuffVecPtr;        ///< 多个block的cache管理指针句柄
typedef void*  TBuffBlockPtr;      ///< 单个管理块指针句柄


/**
 * @brief 获取cache有效数据总长度
 * @param multi -管理块指针
 * @return 实际有效数据长度
 */
uint32_t get_data_len(TBuffVecPtr multi);

/**
 * @brief 获取cache有效数据块个数
 * @param multi -管理块指针
 * @return 实际有效数据块个数
 */
uint32_t get_block_count(TBuffVecPtr multi);

/**
 * @brief 获取cache的第一块数据指针
 * @param multi -管理块指针
 * @return 第一块数据指针
 */
TBuffBlockPtr get_first_block(TBuffVecPtr multi);

/**
 * @brief 获取cache的下一块数据指针
 * @param multi -管理块指针
 * @param block -当前块指针
 * @return 下一块数据指针
 */
TBuffBlockPtr get_next_block(TBuffVecPtr multi, TBuffBlockPtr block);

/**
 * @brief 获取数据块的指针与数据长度
 * @param block -当前块指针
 * @param data -数据指针-modify参数
 * @param len  -长度指针 modify参数
 */
void get_block_data(TBuffBlockPtr block, const void** data, int32_t* len);


/**
 * @brief 获取数据块的指针与数据长度
 * @param multi -管理块指针
 * @param data -数据写入区域指针
 * @param len  -长度
 * @return 数据读取的数据长度
 */
uint32_t read_cache_data(TBuffVecPtr multi, void* data, uint32_t len);


/**
 * @brief 获取数据块的指针与数据长度
 * @param multi -管理块指针
 * @param data -数据写入区域指针
 * @param len  -长度
 * @return 数据读取的数据长度
 */
uint32_t read_cache_begin(TBuffVecPtr multi, uint32_t begin, void* data, uint32_t len);


};

#endif
