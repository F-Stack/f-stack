
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
  *   @info 灵活插入删除的堆,  如果是没有随机删除需求, 可以用std::make_heap
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

class HeapEntry;            //  堆元素类, 继承实现扩展
class HeapList;             //  堆管理类, 通用

/**
 *  @brief 最小堆的堆元素定义, 用于构建通用的堆, 继承该元素即可扩展
 */
class HeapEntry
{    
private:    
    int  _index;          ///<  堆元素下标, 利于快速索引删除操作
    
public:
	friend class HeapList;

    /**
     *  @brief 构造与虚析构函数
     */
	HeapEntry():_index(0){};
	virtual ~HeapEntry(){};

    /**
     *  @brief 堆元素取值函数, 用于返回值比较, 需子函数实现, 否则默认无序
     *  @return 堆元素映射的值
     */
    virtual unsigned long long HeapValue() = 0; 

    
    /**
     *  @brief 堆遍历接口, 用于调试, 在遍历每个元素时被调用, 可选实现
     */
    virtual void HeapIterate() {  
        return;
    };

    /**
     *  @brief 堆元素插入堆中
     *  @param list 堆指针
     *  @return 0 成功; 其它失败  -1 堆满; -2 重复插入
     */
    inline int InsertIntoHeap(HeapList* list); 

    /**
     *  @brief 堆元素从堆中删除
     *  @param list 堆指针
     *  @return 0 成功; 其它失败  -1 堆空; -2 重复删除或脏数据
     */
    inline int DeleteFromHeap(HeapList* list); 

    
    /**
     *  @brief 堆元素下标信息获取, 内部管理使用
     *  @return 堆元素在堆中下标信息
     */
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
 *  @brief 最小堆队列类, 通用类
 */
class HeapList 
{
private:
	HeapEntry**  _list;         // 堆元素的指针数组, 目前定长
	int          _max;          // 堆可管理最大元素个数
	int          _count;        // 堆已经管理的元素个数    
    
public:
    
    /**
     *  @brief 构造函数与析构函数
     */
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

    /**
     *  @brief 扩展heap的大小, 缩小则忽略
     *  @param size 新的堆元素个数
     *  @return 0 成功; -1 失败
     */
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
	

    /**
     *  @brief 插入堆元素
     *  @param entry 堆元素指针
     *  @return 0 成功; 其它失败  -1 堆满; -2 重复插入
     */
	int HeapPush(HeapEntry* entry);

    /**
     *  @brief 取堆顶元素, 并移除该元素
     *  @return 堆顶元素指针, NULL 表示堆为空
     */
	HeapEntry* HeapPop();

    /**
     *  @brief 移除任意堆元素
     *  @param entry 堆元素指针
     *  @return 0 成功; 其它失败  -1 堆空; -2 重复删除或脏数据
     */
	int HeapDelete(HeapEntry* entry);

    /**
     *  @brief 调试接口, 按2叉堆方式打印元素, 同时调用每元素的迭代接口
     */
	void HeapForeach();

    /**
     *  @brief 获取堆的元素个数
     *  @return 堆元素实际数目
     */
    int HeapSize() {
        return _count;
    };

    /**
     *  @brief 取堆顶元素, 不移除该元素
     *  @return 堆顶元素指针, NULL 表示堆为空
     */
    HeapEntry* HeapTop() {
        return (_count > 0) ? _list[1] : NULL;
    };

private:

    /**
     *  @brief 判定堆是否满
     *  @return true 满
     */
	bool HeapFull() {
		return (_count >= _max);
	};

    /**
     *  @brief 判定堆是否空
     *  @return true 空
     */
	bool HeapEmpty() {
		return (_count == 0);
	};

    /**
     *  @brief 按比较函数, 向上重排堆元素
     */
	void HeapUp();

    /**
     *  @brief 按比较函数, 向下重排堆元素
     */    
	void HeapDown(int index);

};

/**
 *  @brief 按比较函数, 向上重排堆元素
 */
inline void HeapList::HeapUp()
{
	for (int pos = _count; pos > 0; pos = pos/2)  
	{
		if (pos/2 < 1)   // pos == 1 已经到顶, 0 属于保留
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


/**
 *  @brief 按比较函数, 向下重排堆元素
 *  @param index 从该位置开始重排
 */   
inline void HeapList::HeapDown(int index)
{
	int  min_son;	
	for (int pos = index; pos <= _count;  pos = min_son)
	{
		if  (pos*2 > _count)  // pos是叶子节点了
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


/**
 *  @brief 插入堆元素
 *  @param entry 堆元素指针
 *  @return 0 成功; 其它失败  -1 堆满; -2 重复插入
 */
inline int HeapList::HeapPush(HeapEntry*  item)
{
	if (HeapFull()) {
        heap_assert(0); // 满, 理论上是可能的, 实际运行不太可能过10W
		return -1;
	}
    
    if (item->GetIndex() != 0) {
        heap_assert(0); // 重复插入
        return -2;
    }     
    
	_count++;
	_list[_count] = item;
    item->SetIndex(_count);

	HeapUp();

	return 0;
}


/**
 *  @brief 取堆顶元素, 并移除该元素
 *  @return 堆顶元素指针, NULL 表示堆为空
 */
inline HeapEntry* HeapList::HeapPop()
{
	if  (HeapEmpty()) {
		return NULL;
	}

	HeapEntry* top = _list[1];	// 0 保留

	_list[1] = _list[_count];
    _list[1]->SetIndex(1);
    _list[_count] = 0;
    
	_count--;
	HeapDown(1);
	
    heap_assert(top->GetIndex() == 1);
	top->SetIndex(0);
	return top;
}

/**
 *  @brief 移除任意堆元素
 *  @param entry 堆元素指针
 *  @return 0 成功; 其它失败  -1 堆空; -2 重复删除或脏数据
 */
inline int  HeapList::HeapDelete(HeapEntry* item)
{
	if  (HeapEmpty()) {
		return -1;
	}

	int pos = item->GetIndex() ;
	if  ((pos > _count)  ||(pos <= 0))
	{
        heap_assert(0); // 非法数据或重复删除
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


/**
 *  @brief 调试接口, 按2叉堆方式打印元素, 同时调用每元素的迭代接口
 */
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

/**
 *  @brief 堆元素插入堆中
 *  @param list 堆指针
 *  @return 0 成功; 其它失败  -1 堆满; -2 重复插入
 */
inline int HeapEntry::InsertIntoHeap(HeapList* list) {
    return list->HeapPush(this);
};

/**
 *  @brief 堆元素从堆中删除
 *  @param list 堆指针
 *  @return 0 成功; 其它失败  -1 堆空; -2 重复删除或脏数据
 */
inline int HeapEntry::DeleteFromHeap(HeapList* list) {
    return list->HeapDelete(this);
};

} // namespace end

#endif


