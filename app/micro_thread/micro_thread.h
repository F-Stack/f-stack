
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
 *  @filename micro_thread.h
 *  @info  micro thread manager
 */

#ifndef ___MICRO_THREAD_H__
#define ___MICRO_THREAD_H__

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <setjmp.h>

#include <set>
#include <vector>
#include <queue>
#include "heap.h"
#include "kqueue_proxy.h"
#include "heap_timer.h"

using std::vector;
using std::set;
using std::queue;

namespace NS_MICRO_THREAD {

#define STACK_PAD_SIZE      128         ///< 栈上下隔离区域的大小
#define MEM_PAGE_SIZE       4096        ///< 内存页默认大小
#define DEFAULT_STACK_SIZE  128*1024    ///< 默认栈大小128K
#define DEFAULT_THREAD_NUM  2000        ///< 默认2000个初始线程

typedef unsigned long long  utime64_t;  ///< 64位的时间定义
typedef void (*ThreadStart)(void*);      ///< 微线程入口函数定义

/**
 * @brief 线程调度的适配对象定义, 框架类最小接口封装
 */
class ScheduleObj
{
public:

    /**
     * @brief 单例类访问句柄入口
     */
    static ScheduleObj* Instance (void); 

    /**
     * @brief 获取全局的时间戳, 毫秒单位
     */
    utime64_t ScheduleGetTime(void);    

    /**
     * @brief 调度其它微线程来运行
     */
    void ScheduleThread(void);

    /**
     * @brief 线程调度主动进入sleep状态
     */
    void ScheduleSleep(void);

    /**
     * @brief 线程调度主动进入pend状态
     */
    void SchedulePend(void);

    /**
     * @brief 线程调度取消pend状态, 外部调度取消
     */
    void ScheduleUnpend(void* thread);

    /**
     * @brief 线程执行完毕后, 回收处理
     */
    void ScheduleReclaim(void);

    /**
     * @brief 调度器调度初始执行
     */
    void ScheduleStartRun(void);

private:
    static ScheduleObj* _instance;   // 私有句柄 
};


/**
 * @brief 线程通用的栈帧结构定义
 */
struct MtStack
{
    int  _stk_size;              ///< 栈的大小, 有效使用空间
    int  _vaddr_size;            ///< 申请的buff总大小
    char *_vaddr;                ///< 申请的内存基地址
    void *_esp;                  ///< 栈的esp寄存器
    char *_stk_bottom;           ///< 栈最低的地址空间
    char *_stk_top;              ///< 栈最高的地址空间
    void *_private;              ///< 线程私有数据
	int valgrind_id;			 ///< valgrind id
};


/**
 * @brief 通用的线程模型定义
 */
class Thread : public  HeapEntry
{
public:

    /**
     * @brief 构造与析构函数
     */
    explicit Thread(int stack_size = 0);
    virtual ~Thread(){};

    /**
     * @brief 线程的实际工作函数
     */
    virtual void Run(void){};

    /**
     * @brief 初始化线程,如堆栈与上下文初始化
     */
    bool Initial(void);

    /**
     * @brief 终止线程,如堆栈与上下文释放
     */
    void Destroy(void);

    /**
     * @brief 线程状态重置, 可复用状态
     */
    void Reset(void);

    /**
     * @brief 线程主动进入睡眠, 单位毫秒
     * @param ms 睡眠毫秒数
     */
    void sleep(int ms); 

    /**
     * @brief 线程主动进入等待, 让二级线程先运行
     */
    void Wait();

    /**
     * @brief 主动切换, 保存状态, 触发调度
     */
    void SwitchContext(void);

    /**
     * @brief 恢复上下文, 切换运行
     */
    void RestoreContext(void);

    /**
     * @brief 获取最后唤醒时间
     * @return 线程的唤醒时间点
     */
    utime64_t GetWakeupTime(void) { 
        return _wakeup_time; 
    };

    /**
     * @brief 设置最后唤醒时间
     * @param waketime 线程的唤醒时间点
     */
    void SetWakeupTime(utime64_t waketime) { 
        _wakeup_time = waketime;
    };

    /**
     * @brief 设置线程私有数据
     * @param data 线程私有数据指针，使用者需自己申请内存，这里只保存指针
     */
    void SetPrivate(void *data)
    {
        _stack->_private = data;
    }
    
    /**
     * @brief 获取线程私有数据
     */
    void* GetPrivate()
    {
        return _stack->_private;
    }

	/**
     * @brief 初始化上下文,设置寄存器,堆栈
     */
    bool CheckStackHealth(char *esp);

protected: 

    /**
     * @brief 清理线程处理状态, 准备复用
     */
    virtual void CleanState(void){};

    /**
     * @brief 初始化堆栈信息
     */
    virtual bool InitStack(void);

    /**
     * @brief 释放堆栈信息
     */
    virtual void FreeStack(void);

    /**
     * @brief 初始化上下文,设置寄存器,堆栈
     */
    virtual void InitContext(void);
    
private:
    MtStack* _stack;        ///< 私有栈指针
    jmp_buf _jmpbuf;        ///< 上下文jmpbuff
    int _stack_size;        ///< 栈大小字段
    utime64_t _wakeup_time; ///< 睡眠唤醒时间
};


/**
 * @brief 微线程数据结构定义
 */
class MicroThread : public Thread
{
public:
    enum ThreadType
    {
        NORMAL          =   0,   ///< 默认普通线程, 没有动态申请的栈信息
        PRIMORDIAL      =   1,   ///< 原生线程, main函数开启
        DAEMON          =   2,   ///< 守护线程, 底层IO EPOLL管理与调度触发
        SUB_THREAD      =   3,   ///< 二级线程, 仅执行简单工作
    };
    
    enum ThreadFlag
    {
        NOT_INLIST	=  0x0,     ///< 无队列状态
        FREE_LIST	=  0x1,     ///< 空闲队列中
        IO_LIST		=  0x2,     ///< IO等待队列中
        SLEEP_LIST	=  0x4,     ///< 主动SLEEP中
        RUN_LIST	=  0x8,     ///< 可运行队列中
        PEND_LIST   =  0x10,    ///< 阻塞队列中
        SUB_LIST    =  0x20,    ///< 二级线程队列中
        
    };

    enum ThreadState
    {
        INITIAL         =  0,   ///< 初始化状态
        RUNABLE         =  1,   ///< 可运行状态
        RUNNING         =  2,   ///< 正在运行中
        SLEEPING        =  3,   ///< IO等待或SLEEP中
        PENDING         =  4,   ///< 阻塞状态中, 等待子线程OK等
    };

    typedef TAILQ_ENTRY(MicroThread) ThreadLink;        ///< 微线程链接
    typedef TAILQ_HEAD(__ThreadSubTailq, MicroThread) SubThreadList;  ///< 微线程队列定义
    
public:   

    /**
     * @brief 微线程构造与析构
     */
    MicroThread(ThreadType type = NORMAL);
    ~MicroThread(){};    
    
    ThreadLink _entry;          ///<  状态队列入口
    ThreadLink _sub_entry;      ///<  子线程队列入口

    /**
     * @brief 微线程堆排序函数实现,按唤醒时间从早到晚排序
     * @return 线程的实际唤醒时间
     */
    virtual utime64_t HeapValue() {
        return GetWakeupTime();
    };

    /**
     * @brief 线程的实际工作函数
     */
    virtual void Run(void);    
    
    /**
     * @breif fd侦听管理对列操作
     */
    void ClearAllFd(void) {
        TAILQ_INIT(&_fdset);
    };
    void AddFd(KqueuerObj* efpd) {
        TAILQ_INSERT_TAIL(&_fdset, efpd, _entry);
    };
    void AddFdList(KqObjList* fdset) {
        TAILQ_CONCAT(&_fdset, fdset, _entry);
    };    
    KqObjList& GetFdSet(void) {
        return _fdset;
    };

    /**
     * @breif 微线程类型管理操作
     */
    void SetType(ThreadType type) {
        _type = type;   
    }; 
    ThreadType GetType(void) {
        return _type;
    };

    /**
     * @breif 微线程类型检查接口
     */
    bool IsDaemon(void) {
        return (DAEMON == _type);
    };
    bool IsPrimo(void) {
        return (PRIMORDIAL == _type);
    };
    bool IsSubThread(void) {
        return (SUB_THREAD == _type);
    };  

    /**
     * @brief  父线程设置与更新
     */
    void SetParent(MicroThread* parent) {
        _parent = parent;
    };
    MicroThread* GetParent() {
        return _parent;
    };
    void WakeupParent();

    /**
     * @brief  子线程的管理
     */
    void AddSubThread(MicroThread* sub);
    void RemoveSubThread(MicroThread* sub);
    bool HasNoSubThread();

    /**
     * @brief 微线程类型状态操作
     */
    void SetState(ThreadState state) {
        _state = state;   
    };
    ThreadState GetState(void) {
        return _state;
    }

    /**
     * @breif 微线程标记位处理
     */
    void SetFlag(ThreadFlag flag) {
	_flag = (ThreadFlag)(_flag | flag);
    }; 
    void UnsetFlag(ThreadFlag flag) {
        _flag = (ThreadFlag)(_flag & ~flag);
    };    
    bool HasFlag(ThreadFlag flag) {
	return _flag & flag;
    };
    ThreadFlag GetFlag() {
        return _flag;
    };

    /**
     * @breif 微线程入口函数管理注册
     */    
    void SetSartFunc(ThreadStart func, void* args) {
        _start = func;
        _args  = args;
    };

    void* GetThreadArgs() {
        return _args;
    }
    
protected: 

    /**
     * @breif 微线程复用状态清理
     */    
    virtual void CleanState(void);
    
private:    
    ThreadState _state;         ///< 微线程当前状态
    ThreadType _type;           ///< 微线程类型
    ThreadFlag _flag;           ///< 微线程标记位
    KqObjList _fdset;           ///< 微线程关注的socket列表
    SubThreadList _sub_list;    ///< 二级线程的队列
    MicroThread* _parent;       ///< 二级线程的父线程
    ThreadStart _start;         ///< 微线程注册函数
    void* _args;                ///< 微线程注册参数

};
typedef std::set<MicroThread*> ThreadSet;       ///< 微线程set管理结构
typedef std::queue<MicroThread*> ThreadList;    ///< 微线程queue管理结构


/**
 * @brief 微线程日志接口, 底层库, 日志由调用者注入
 */
class LogAdapter
{
public:

    /**
     * @brief 日志构造与析构
     */
    LogAdapter(){};
    virtual ~LogAdapter(){};

    /**
     * @brief 日志优先按等级过滤, 减少解析参数的开销
     * @return true 可以打印该级别, false 跳过不打印该级别
     */
    virtual bool CheckDebug(){ return true;};
    virtual bool CheckTrace(){ return true;};
    virtual bool CheckError(){ return true;};

    /**
     * @brief 日志分级记录接口
     */    
    virtual void LogDebug(char* fmt, ...){};
    virtual void LogTrace(char* fmt, ...){};
    virtual void LogError(char* fmt, ...){};

    /**
     * @brief 属性上报接口
     */
    virtual void AttrReportAdd(int attr, int iValue){};
    virtual void AttrReportSet(int attr, int iValue){};
    
};


/**
 * @brief 微线程池简单实现
 */
class ThreadPool
{
public:

    static unsigned int default_thread_num;   ///< 默认2000微线程待命
    static unsigned int default_stack_size;   ///< 默认128K栈大小 

    /**
     * @brief 设置微线程的最小保留数目
     */
    static void SetDefaultThreadNum(unsigned int num) {
        default_thread_num = num;   
    }; 

    /**
     * @brief 设置微线程的默认栈大小, 需初始化前设置
     */
    static void SetDefaultStackSize(unsigned int size) {
        default_stack_size = (size + MEM_PAGE_SIZE - 1) / MEM_PAGE_SIZE * MEM_PAGE_SIZE;   
    }; 
    
    /**
     * @brief 微线程池初始化
     */
    bool InitialPool(int max_num);

    /**
     * @brief 微线程池反初始化
     */
    void DestroyPool (void); 

    /**
     * @brief 微线程分配接口
     * @return 微线程对象
     */
    MicroThread* AllocThread(void);

    /**
     * @brief 微线程释放接口
     * @param thread 微线程对象
     */
    void FreeThread(MicroThread* thread);

	/**
     * @brief 获取当前微线程数量
     * @param thread 微线程对象
     */
    int GetUsedNum(void);
    
private:
    ThreadList      _freelist;      ///< 空闲待命的微线程队列
    int             _total_num;     ///< 目前总的微线程数目，后续按需控制上限
    int             _use_num;       ///< 当前正在使用的微线程数目
    int             _max_num;       ///< 最大并发限制数, 放置内存过度使用
};

typedef TAILQ_HEAD(__ThreadTailq, MicroThread) ThreadTailq;  ///< 微线程队列定义

/**
 * @brief 微线程框架类, 全局的单例类
 */
class MtFrame : public KqueueProxy, public ThreadPool
{
private:
    static MtFrame* _instance;          ///< 单例指针
    LogAdapter*     _log_adpt;          ///< 日志接口
	ThreadList      _runlist;           ///< 可运行queue, 无优先级
	ThreadTailq     _iolist;            ///< 等待队列，可随机脱离队列 
	ThreadTailq     _pend_list;         ///< 等待队列，可随机脱离队列 
	HeapList        _sleeplist;         ///< 等待超时的堆, 可随机脱离, 且随时获取最小堆首
	MicroThread*    _daemon;            ///< 守护线程, 执行epoll wait, 超时检测
	MicroThread*    _primo;             ///< 原生线程, 使用的是原生堆栈
	MicroThread*    _curr_thread;       ///< 当前运行线程
	utime64_t       _last_clock;        ///< 全局时间戳, 每次idle获取一次
    int             _waitnum;           ///< 等待运行的总线程数, 可调节调度的节奏
    CTimerMng*      _timer;             ///< TCP保活专用的timer定时器
    int             _realtime;  /// < 使用实时时间0, 未设置

public:
    friend class ScheduleObj;           ///< 调度器对象, 是框架类的门面模式, 友元处理
    
public:  

    /**
     * @brief 微线程框架类, 全局实例获取
     */
    static MtFrame* Instance (void);
    
    /**
     * @brief 微线程包裹的系统IO函数 sendto
     * @param fd 系统socket信息
     * @param msg 待发送的消息指针
     * @param len 待发送的消息长度
     * @param to 目的地址的指针
     * @param tolen 目的地址的结构长度
     * @param timeout 最长等待时间, 毫秒
     * @return >0 成功发送长度, <0 失败
     */
    static int sendto(int fd, const void *msg, int len, int flags, const struct sockaddr *to, int tolen, int timeout);

    /**
     * @brief 微线程包裹的系统IO函数 recvfrom
     * @param fd 系统socket信息
     * @param buf 接收消息缓冲区指针
     * @param len 接收消息缓冲区长度
     * @param from 来源地址的指针
     * @param fromlen 来源地址的结构长度
     * @param timeout 最长等待时间, 毫秒
     * @return >0 成功接收长度, <0 失败
     */
    static int recvfrom(int fd, void *buf, int len, int flags, struct sockaddr *from, socklen_t *fromlen, int timeout);

    /**
     * @brief 微线程包裹的系统IO函数 connect
     * @param fd 系统socket信息
     * @param addr 指定server的目的地址
     * @param addrlen 地址的长度
     * @param timeout 最长等待时间, 毫秒
     * @return >0 成功发送长度, <0 失败
     */
    static int connect(int fd, const struct sockaddr *addr, int addrlen, int timeout);

    /**
     * @brief 微线程包裹的系统IO函数 accept
     * @param fd 监听套接字
     * @param addr 客户端地址
     * @param addrlen 地址的长度
     * @param timeout 最长等待时间, 毫秒
     * @return >=0 accept的socket描述符, <0 失败
     */
    static int accept(int fd, struct sockaddr *addr, socklen_t *addrlen, int timeout);

    /**
     * @brief 微线程包裹的系统IO函数 read
     * @param fd 系统socket信息
     * @param buf 接收消息缓冲区指针
     * @param nbyte 接收消息缓冲区长度
     * @param timeout 最长等待时间, 毫秒
     * @return >0 成功接收长度, <0 失败
     */
    static ssize_t read(int fd, void *buf, size_t nbyte, int timeout);

    /**
     * @brief 微线程包裹的系统IO函数 write
     * @param fd 系统socket信息
     * @param buf 发送消息缓冲区指针
     * @param nbyte 发送消息缓冲区长度
     * @param timeout 最长等待时间, 毫秒
     * @return >0 成功发送长度, <0 失败
     */
    static ssize_t write(int fd, const void *buf, size_t nbyte, int timeout);

    /**
     * @brief 微线程包裹的系统IO函数 recv
     * @param fd 系统socket信息
     * @param buf 接收消息缓冲区指针
     * @param len 接收消息缓冲区长度
     * @param timeout 最长等待时间, 毫秒
     * @return >0 成功接收长度, <0 失败
     */
    static int recv(int fd, void *buf, int len, int flags, int timeout);

    /**
     * @brief 微线程包裹的系统IO函数 send
     * @param fd 系统socket信息
     * @param buf 待发送的消息指针
     * @param nbyte 待发送的消息长度
     * @param timeout 最长等待时间, 毫秒
     * @return >0 成功发送长度, <0 失败
     */
    static ssize_t send(int fd, const void *buf, size_t nbyte, int flags, int timeout);


    /**
     * @brief 微线程主动sleep接口, 单位ms
     */
    static void sleep(int ms);

    /**
     * @brief 微线程仅等待事件,不做额外的操作
     * @param fd 系统socket信息
     * @param events 事件类型  EPOLLIN or EPOLLOUT
     * @param timeout 最长等待时间, 毫秒
     * @return >0 成功接收长度, <0 失败
     */
    static int WaitEvents(int fd, int events, int timeout);

    /**
     * @brief 微线程创建接口
     * @param entry 线程入口函数
     * @param args  线程入口参数
     * @return 微线程指针, NULL表示失败
     */
    static MicroThread* CreateThread(ThreadStart entry, void *args, bool runable = true);

    /**
     * @brief 守护线程入口函数, 函数指针要求static类型
     * @param args  线程入口参数
     */
    static void DaemonRun(void* args);
	static int Loop(void* args);

    /**
     * @brief 获取当前线程的根线程
     */
    MicroThread *GetRootThread();

    /**
     * @brief 框架初始化, 默认不带日志运行
     */
    bool InitFrame(LogAdapter* logadpt = NULL, int max_thread_num = 50000);

    /**
     * @brief HOOK系统api的设置
     */
    void SetHookFlag();

    /**
     * @brief 框架反初始化
     */
    void Destroy (void);
    
    /**
     * @brief 微线程框架版本获取
     */
    char* Version(void);

    /**
     * @brief 框架获取全局时间戳
     */
    utime64_t GetLastClock(void) {
    	if(_realtime)
    	{
        	return GetSystemMS();
        }	
        return _last_clock;
    };


    /**
     * @brief 框架获取当前线程
     */
    MicroThread* GetActiveThread(void) {
        return _curr_thread;
    }; 

    /**
     * @brief 返回当前待运行的线程数, 直接计数, 效率高
     * @return 等待线程数
     */
    int RunWaitNum(void) {
        return _waitnum;        
    };

    /**
     * @brief 框架被注入的日志句柄访问
     */
    LogAdapter* GetLogAdpt(void) {
        return _log_adpt;
    };

    /**
     * @brief 获取框架保活定时器指针 
     */
    CTimerMng* GetTimerMng(void) {
        return _timer;
    };

    /**
     * @brief 框架调用epoll wait前, 判定等待时间信息
     */
    virtual int KqueueGetTimeout(void);
    
    /**
     * @brief 微线程触发切换函数,调用成功 则让出cpu, 内部接口
     * @param fdlist 多路并发的socket列表
     * @param fd 单个请求的fd信息
     * @param timeout 最长等待时间, 毫秒
     * @return true 成功, false 失败
     */
    virtual bool KqueueSchedule(KqObjList* fdlist, KqueuerObj* fd, int timeout);    

    
    /**
     * @brief 微线程主动切换, 等待其它线程的唤醒
     * @param timeout 最长等待时间, 毫秒
     */
    void WaitNotify(utime64_t timeout);

    /**
     * @brief 框架管理线程单元, 移除IO等待状态, 内部接口
     * @param thread 微线程对象
     */
    void RemoveIoWait(MicroThread* thread);    

    /**
     * @brief 框架管理线程单元, 插入可运行队列, 内部接口
     * @param thread 微线程对象
     */
    void InsertRunable(MicroThread* thread);

    /**
     * @brief 框架管理线程单元, 执行pend等待状态
     * @param thread 微线程对象
     */
    void InsertPend(MicroThread* thread);
    
    /**
     * @brief 框架管理线程单元, 移除PEND等待状态
     * @param thread 微线程对象
     */
    void RemovePend(MicroThread* thread);

	void SetRealTime(int realtime_)
	{
		_realtime =realtime_;
	}
private:

    /**
     * @brief 微线程私有构造
     */
    MtFrame():_realtime(1){ _curr_thread = NULL; }; 

    /**
     * @brief 微线程私有获取守护线程
     */
    MicroThread* DaemonThread(void){
        return _daemon;
    };	

    /**
     * @brief 框架调度线程运行
     */
    void ThreadSchdule(void);

    /**
     * @brief 框架处理定时回调函数
     */
    void CheckExpired();
    
    /**
     * @brief 框架检测到超时, 唤醒所有的超时线程
     */
    void WakeupTimeout(void);
    
    /**
     * @brief 框架更新全局时间戳
     */
    void SetLastClock(utime64_t clock) {
        _last_clock = clock;
    };

    /**
     * @brief 框架设置当前线程
     */
    void SetActiveThread(MicroThread* thread) {
        _curr_thread = thread;
    };    

    /**
     * @brief 框架的时钟源接口, 返回毫秒级别时钟
     */
    utime64_t GetSystemMS(void) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL);
    };

    /**
     * @brief 框架管理线程单元, 执行IO等待状态
     * @param thread 微线程对象
     */
    void InsertSleep(MicroThread* thread);

    /**
     * @brief 框架管理线程单元, 移除IO等待状态
     * @param thread 微线程对象
     */
    void RemoveSleep(MicroThread* thread);

    /**
     * @brief 框架管理线程单元, 执行IO等待状态
     * @param thread 微线程对象
     */
    void InsertIoWait(MicroThread* thread);

    /**
     * @brief 框架管理线程单元, 移出可运行队列
     * @param thread 微线程对象
     */
    void RemoveRunable(MicroThread* thread);    

};

/**
 * @brief 日志宏的定义部分
 */
#define MTLOG_DEBUG(fmt, args...)                                              \
do {                                                                           \
       register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
       if (fm && fm->GetLogAdpt() && fm->GetLogAdpt()->CheckDebug())           \
       {                                                                       \
          fm->GetLogAdpt()->LogDebug((char*)"[%-10s][%-4d][%-10s]"fmt,         \
                __FILE__, __LINE__, __FUNCTION__, ##args);                     \
       }                                                                       \
} while (0)

#define MTLOG_TRACE(fmt, args...)                                              \
do {                                                                           \
       register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
       if (fm && fm->GetLogAdpt() && fm->GetLogAdpt()->CheckTrace())           \
       {                                                                       \
          fm->GetLogAdpt()->LogTrace((char*)"[%-10s][%-4d][%-10s]"fmt,         \
                __FILE__, __LINE__, __FUNCTION__, ##args);                     \
       }                                                                       \
} while (0)

#define MTLOG_ERROR(fmt, args...)                                              \
do {                                                                           \
       register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
       if (fm && fm->GetLogAdpt() && fm->GetLogAdpt()->CheckError())           \
       {                                                                       \
          fm->GetLogAdpt()->LogError((char*)"[%-10s][%-4d][%-10s]"fmt,         \
                __FILE__, __LINE__, __FUNCTION__, ##args);                     \
       }                                                                       \
} while (0)

#define MT_ATTR_API(ATTR, VALUE)                                               \
do {                                                                           \
       register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
       if (fm && fm->GetLogAdpt())                                             \
       {                                                                       \
          fm->GetLogAdpt()->AttrReportAdd(ATTR, VALUE);                        \
       }                                                                       \
} while (0)

#define MT_ATTR_API_SET(ATTR, VALUE)                                               \
	   do { 																		  \
			  register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
			  if (fm && fm->GetLogAdpt())											  \
			  { 																	  \
				 fm->GetLogAdpt()->AttrReportSet(ATTR, VALUE);						  \
			  } 																	  \
	   } while (0)



}// NAMESPACE NS_MICRO_THREAD

#endif

