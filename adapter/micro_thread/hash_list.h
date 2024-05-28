
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

class HashKey
{
private:
    HashKey*  _next_entry;
    uint32_t  _hash_value;
    void*     _data_ptr;
    
public:

    friend class HashList;

    HashKey():_next_entry(NULL), _hash_value(0), _data_ptr(NULL) {};
    virtual ~HashKey(){};

    virtual uint32_t HashValue() = 0; 

    virtual int HashCmp(HashKey* rhs) = 0; 

    virtual void HashIterate() {  
        return;
    };

    void* GetDataPtr() {
        return _data_ptr;
    }; 
    void SetDataPtr(void* data) {
        _data_ptr = data;
    };
};

class HashList
{
public:

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

    int HashSize() {
        return _count;
    };

    /**
     *  @brief hash insert key.
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
     *  @brief hash lookup key.
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
     *  @brief hash lookup key.
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
     *  @brief hash remove key.
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
     *  @brief hash loop.
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
     *  @brief traverse hash list, low performance, only for remove.
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
    HashKey** _buckets;
    int       _count;
    int       _max;
};

}


#endif

