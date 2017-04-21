
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
  *   @filename  hash_list.h
  *   @info  开链hash类, 简单hash存储实现; 继承来实现hash映射, 注意插入元素的
  *          生命周期, 如栈变量等会自动析构的元素, 不要存放于此, 否则会坏链
  *   @time  2013-06-11
  */

#ifndef __HASH_LIST_FILE__
#define __HASH_LIST_FILE__

#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

namespace NS_MICRO_THREAD {

/**
 *  @brief Hash存放元素的基类, 继承该元素即可实现扩展
 */
class HashKey
{
private:
    HashKey*  _next_entry;          ///< 开链hash的链接元素
    uint32_t  _hash_value;          ///< hash value信息, 节约比较的时间
    void*     _data_ptr;            ///< hash data数据指针, 可key - value 聚合存储
    
public:

    friend class HashList;          ///< hash表可以直接访问next指针

    /**
     *  @brief 构造与虚析构函数
     */
    HashKey():_next_entry(NULL), _hash_value(0), _data_ptr(NULL) {};
    virtual ~HashKey(){};

    /**
     *  @brief 节点元素的hash算法, 获取key的hash值
     *  @return 节点元素的hash值
     */
    virtual uint32_t HashValue() = 0; 

    /**
     *  @brief 节点元素的cmp方法, 同一桶ID下, 按key比较
     *  @return 节点元素的hash值
     */
    virtual int HashCmp(HashKey* rhs) = 0; 
    
    /**
     *  @brief 堆遍历接口, 用于调试, 在遍历每个元素时被调用, 可选实现
     */
    virtual void HashIterate() {  
        return;
    };

    /**
     *  @brief 节点元素的实际数据指针设置与获取
     */
    void* GetDataPtr() {
        return _data_ptr;
    }; 
    void SetDataPtr(void* data) {
        _data_ptr = data;
    };
    

};


/**
 *  @brief Hash管理类, 开链式hash, 注意选择合适的hash函数, 避免冲突过长
 */
class HashList
{
public:

    /**
     *  @brief 构造函数与析构函数
     */
	explicit HashList(int max = 100000) {
        _max = GetMaxPrimeNum((max > 2) ? max : 100000);
		_buckets = (HashKey**)calloc(_max, sizeof(HashKey*));
		_count = 0;
	};
	virtual ~HashList()  {
		if (_buckets) {
		    free(_buckets);
			_buckets = NULL;
		}
        _count = 0;
	};

    /**
     *  @brief 获取hash的元素个数
     *  @return 堆元素实际数目
     */
    int HashSize() {
        return _count;
    };

    /**
     *  @brief hash插入元素, 要在该元素析构前, 调用remove
     *  @param key 待插入的元素指针, 注意元素的生命周期, 不要插入栈变量
     *  @return 0 成功, -1 参数无效或未初始化, -2 重复插入或脏数据
     */
    int HashInsert(HashKey* key) {
        if (!key || !_buckets) {
            return -1;
        }

        if ((key->_hash_value != 0) || (key->_next_entry != NULL)) {
            return -2;
        }        
        
        key->_hash_value = key->HashValue();
        int idx = (key->_hash_value) % _max;        

        HashKey* next_item = _buckets[idx];
        _buckets[idx]      = key;
        key->_next_entry   = next_item;
        _count++;
        return 0; 
    }

    /**
     *  @brief hash查找元素
     *  @param key 待查询的key指针
     *  @return 查询结果对象指针, NULL表明无数据
     */
    HashKey* HashFind(HashKey* key) {
        if (!key || !_buckets) {
            return NULL;
        }
        
        uint32_t hash = key->HashValue();
        int idx = hash % _max;
        HashKey* item = _buckets[idx];
        
        for (; item != NULL; item = item->_next_entry) {
            if (item->_hash_value != hash) {
                continue;
            }

            if (item->HashCmp(key) == 0) {
                break;
            }
        }
        
        return item; 
    }
    
    /**
     *  @brief hash查找元素
     *  @param key 待查询的key指针
     *  @return 查询结果对象指针, NULL表明无数据
     */
    void* HashFindData(HashKey* key) {
        HashKey* item = HashFind(key);
        if (!item) {
            return NULL;
        } else {
            return item->_data_ptr;
        }
    };
    

    /**
     *  @brief hash删除元素
     *  @param key 待删除的key指针
     */
    void HashRemove(HashKey* key) {
        if (!key || !_buckets) {
            return;
        }
        
        uint32_t hash = key->HashValue();
        int idx = hash % _max;
        HashKey* item = _buckets[idx];
        HashKey* prev = NULL;
        
        for (; item != NULL; prev = item, item = item->_next_entry) {
            if ((item->_hash_value == hash) && (item->HashCmp(key) == 0)){
                if (prev == NULL) {
                    _buckets[idx] = item->_next_entry;
                } else {
                    prev->_next_entry = item->_next_entry;
                }
                item->_hash_value = 0;
                item->_next_entry = NULL;                
                _count--;
                break;
            }
        }
    }

    /**
     *  @brief hash遍历元素, 调用迭代函数
     */
    void HashForeach() {
        if (!_buckets) {
            return;
        }
        
        for (int i = 0; i < _max; i++) {
            HashKey* item = _buckets[i];
            for (; item != NULL; item = item->_next_entry) {
                item->HashIterate();
            }
        }
    }
    
    /**
     *  @brief hash清理遍历, 性能低下, 只用于最终遍历清理
     */
    HashKey* HashGetFirst() {
        if (!_buckets) {
            return NULL;
        }
        
        for (int i = 0; i < _max; i++) {
            if (_buckets[i]) {
                return _buckets[i];
            }
        }
        
        return NULL;
    }    

private:

    /**
     *  @brief 获取桶长度的最大质数
     */
    int GetMaxPrimeNum(int num) 
    {
    	int sqrt_value = (int)sqrt(num);
    	for (int i = num; i > 0; i--)
    	{
    		int flag = 1;
    		for (int k = 2; k <= sqrt_value; k++)
    		{
    			if (i % k == 0)
    			{
    				flag = 0;
    				break;
    			}
    		}

    		if (flag == 1)
    		{
    			return i;
    		}
    	}

    	return 0;
    };


private:
    HashKey** _buckets;             ///< 桶指针
    int       _count;               ///< 有效元素个数
    int       _max;                 ///< 最大节点个数
};

}


#endif

