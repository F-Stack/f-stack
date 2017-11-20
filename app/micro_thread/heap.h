
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
  *   @filename  heap.h
  *   @info flexible insert and delete heap, if no random deletion, use std::make_heap
  *   @time  2013-06-11
  */

#ifndef  __HEAP_ENTRY_FILE__
#define __HEAP_ENTRY_FILE__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define  heap_assert(statement)
//#define  heap_assert(statement)   assert(statement)

namespace NS_MICRO_THREAD {

class HeapEntry;
class HeapList;

/**
 *  @brief definition of heap elements for minimum heap
 */
class HeapEntry
{    
private:    
    int  _index;
    
public:
    friend class HeapList;

    HeapEntry():_index(0){};
    virtual ~HeapEntry(){};

    virtual unsigned long long HeapValue() = 0; 

    virtual void HeapIterate() {  
        return;
    };

    inline int InsertIntoHeap(HeapList* list); 

    inline int DeleteFromHeap(HeapList* list); 

    inline int GetIndex() {
        return _index;
    };

private:
    
    inline int HeapValueCmp(HeapEntry* rhs) {
        if (this->HeapValue() == rhs->HeapValue()) {
            return 0;
        } else if (this->HeapValue() > rhs->HeapValue()) {
            return 1;
        } else {
            return -1;
        }
    };

    inline void SetIndex(int index) {
        _index = index;
    };


};


/**
 *  @brief minimum heap queue.
 */
class HeapList 
{
private:
    HeapEntry**  _list;
    int          _max;
    int          _count;   
    
public:

    explicit HeapList(int max = 100000) {
        _max = (max > 0) ? max : 100000;
        _list = (HeapEntry**)malloc (sizeof(HeapEntry*) * (_max+1));
        heap_assert(_list);
        memset(_list, 0, sizeof(HeapEntry*) * (_max+1));
        _count = 0;
    };
    virtual ~HeapList()  {
        if (_list) {
            free(_list);
            _list = NULL;
        }
        _max = 0;
        _count = 0;
    };

    int HeapResize(int size) {
        if (_max >= size) {
            return 0;
        }
        
        HeapEntry** new_list = (HeapEntry**)malloc(sizeof(HeapEntry*) * (size+1));
        if (NULL == new_list) {
            return -1;
        }
        memset(new_list, 0, sizeof(HeapEntry*) * (size+1));
        memcpy(new_list, _list, sizeof(HeapEntry*) * (_max+1));
        free(_list);
        _list = new_list;
        _max = size;

        return 0;
    };
    

    int HeapPush(HeapEntry* entry);

    HeapEntry* HeapPop();

    int HeapDelete(HeapEntry* entry);

    void HeapForeach();

    int HeapSize() {
        return _count;
    };

    HeapEntry* HeapTop() {
        return (_count > 0) ? _list[1] : NULL;
    };

private:

    bool HeapFull() {
        return (_count >= _max);
    };


    bool HeapEmpty() {
        return (_count == 0);
    };

    void HeapUp();

    void HeapDown(int index);

};


inline void HeapList::HeapUp()
{
    for (int pos = _count; pos > 0; pos = pos/2)  
    {
        if (pos/2 < 1)   // pos == 1 peaked, 0 reserved.
        {
            break;
        }

        if (_list[pos]->HeapValueCmp(_list[pos/2]) < 0)
        {
            HeapEntry* tmp = _list[pos/2];
            _list[pos/2] = _list[pos];
            _list[pos] = tmp;

            _list[pos]->SetIndex(pos);
            _list[pos/2]->SetIndex(pos/2);
        }
        else
        {
            break;
        }
    }
}


inline void HeapList::HeapDown(int index)
{
    int  min_son;    
    for (int pos = index; pos <= _count;  pos = min_son)
    {
        if  (pos*2 > _count)  // pos is a leaf node.
        {
            break;
        }
        else if (pos*2 == _count)
        {
            min_son = pos*2;
        }
        else 
        {
            if (_list[pos*2+1]->HeapValueCmp(_list[pos*2]) < 0)
            {
                min_son = pos*2+1;
            }
            else
            {
                min_son = pos*2;
            }
        }

        if  (_list[pos]->HeapValueCmp(_list[min_son]) > 0)
        {
            HeapEntry* tmp = _list[min_son];
            _list[min_son] = _list[pos];
            _list[pos] = tmp;

            _list[pos]->SetIndex(pos);
            _list[min_son]->SetIndex(min_son);
        }
        else
        {
            break;
        }
    }
}


inline int HeapList::HeapPush(HeapEntry*  item)
{
    if (HeapFull()) {
        heap_assert(0); // it's possible in theory but not in fact.
        return -1;
    }
    
    if (item->GetIndex() != 0) {
        heap_assert(0); // duplicated insertion.
        return -2;
    }     
    
    _count++;
    _list[_count] = item;
    item->SetIndex(_count);

    HeapUp();

    return 0;
}


inline HeapEntry* HeapList::HeapPop()
{
    if  (HeapEmpty()) {
        return NULL;
    }

    HeapEntry* top = _list[1];    // 0 reserved.

    _list[1] = _list[_count];
    _list[1]->SetIndex(1);
    _list[_count] = 0;
    
    _count--;
    HeapDown(1);
    
    heap_assert(top->GetIndex() == 1);
    top->SetIndex(0);
    return top;
}

inline int  HeapList::HeapDelete(HeapEntry* item)
{
    if  (HeapEmpty()) {
        return -1;
    }

    int pos = item->GetIndex() ;
    if  ((pos > _count)  ||(pos <= 0))
    {
        heap_assert(0); // duplicated deletion or illegal data.
        return -2;
    }

    HeapEntry* del = _list[pos];
    _list[pos] = _list[_count];
    _list[pos]->SetIndex(pos);

    _list[_count] = 0;
    _count--;

    HeapDown(pos);
    heap_assert(pos == del->GetIndex());
    del->SetIndex(0);
    return 0;
}


inline void HeapList::HeapForeach()
{
    int per = 1;
    for (int i = 1; i <= _count; i++)
    {
        if (i >= per*2)
        {
            printf("\n");
            per *=2;
        }
        printf("%llu ", _list[i]->HeapValue());

        _list[i]->HeapIterate();
    }
}

inline int HeapEntry::InsertIntoHeap(HeapList* list) {
    return list->HeapPush(this);
};

inline int HeapEntry::DeleteFromHeap(HeapList* list) {
    return list->HeapDelete(this);
};

} // namespace end

#endif


