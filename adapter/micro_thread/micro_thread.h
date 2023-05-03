
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
#include <stdarg.h>

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

#define STACK_PAD_SIZE      128
#define MEM_PAGE_SIZE       4096
#define DEFAULT_STACK_SIZE  STACK_PAD_SIZE * 1024
#define DEFAULT_THREAD_NUM  5000
#define MAX_THREAD_NUM  800000

typedef unsigned long long  utime64_t;
typedef void (*ThreadStart)(void*);

class ScheduleObj
{
public:

    static ScheduleObj* Instance (void); 

    utime64_t ScheduleGetTime(void);    

    void ScheduleThread(void);

    void ScheduleSleep(void);

    void SchedulePend(void);

    void ScheduleUnpend(void* thread);

    void ScheduleReclaim(void);

    void ScheduleStartRun(void);

private:
    static ScheduleObj* _instance;
};

struct MtStack
{
    int  _stk_size;
    int  _vaddr_size;
    char *_vaddr;
    void *_esp;
    char *_stk_bottom;
    char *_stk_top;
    void *_private;
    int valgrind_id;
};

class Thread : public  HeapEntry
{
public:

    explicit Thread(int stack_size = 0);
    virtual ~Thread(){};

    virtual void Run(void){};

    bool Initial(void);

    void Destroy(void);

    void Reset(void);

    void sleep(int ms); 

    void Wait();

    void SwitchContext(void);

    int SaveContext(void);

    void RestoreContext(void);

    utime64_t GetWakeupTime(void) { 
        return _wakeup_time; 
    };

    void SetWakeupTime(utime64_t waketime) { 
        _wakeup_time = waketime;
    };

    void SetPrivate(void *data)
    {
        _stack->_private = data;
    }
    
    void* GetPrivate()
    {
        return _stack->_private;
    }

    bool CheckStackHealth(char *esp);

protected: 

    virtual void CleanState(void){};

    virtual bool InitStack(void);

    virtual void FreeStack(void);

    virtual void InitContext(void);
    
private:
    MtStack* _stack;
    jmp_buf _jmpbuf;
    int _stack_size;
    utime64_t _wakeup_time;
};

class MicroThread : public Thread
{
public:
    enum ThreadType
    {
        NORMAL          =   0,   ///< normal thread, no dynamic allocated stack infomations.
        PRIMORDIAL      =   1,   ///< primordial thread, created when frame initialized.
        DAEMON          =   2,   ///< daemon thread, IO event management and scheduling trigger.
        SUB_THREAD      =   3,   ///< sub thread, run simple task.
    };
    
    enum ThreadFlag
    {
        NOT_INLIST    =  0x0,
        FREE_LIST    =  0x1,
        IO_LIST        =  0x2,
        SLEEP_LIST    =  0x4,
        RUN_LIST    =  0x8,
        PEND_LIST   =  0x10,
        SUB_LIST    =  0x20,
        
    };

    enum ThreadState
    {
        INITIAL         =  0,
        RUNABLE         =  1,
        RUNNING         =  2,
        SLEEPING        =  3,
        PENDING         =  4,
    };

    typedef TAILQ_ENTRY(MicroThread) ThreadLink;
    typedef TAILQ_HEAD(__ThreadSubTailq, MicroThread) SubThreadList;
    
public:   

    MicroThread(ThreadType type = NORMAL);
    ~MicroThread(){};    
    
    ThreadLink _entry;
    ThreadLink _sub_entry;

    virtual utime64_t HeapValue() {
        return GetWakeupTime();
    };

    virtual void Run(void);    

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

    void SetType(ThreadType type) {
        _type = type;   
    }; 
    ThreadType GetType(void) {
        return _type;
    };

    bool IsDaemon(void) {
        return (DAEMON == _type);
    };
    bool IsPrimo(void) {
        return (PRIMORDIAL == _type);
    };
    bool IsSubThread(void) {
        return (SUB_THREAD == _type);
    };  

    void SetParent(MicroThread* parent) {
        _parent = parent;
    };
    MicroThread* GetParent() {
        return _parent;
    };
    void WakeupParent();

    void AddSubThread(MicroThread* sub);
    void RemoveSubThread(MicroThread* sub);
    bool HasNoSubThread();

    void SetState(ThreadState state) {
        _state = state;   
    };
    ThreadState GetState(void) {
        return _state;
    }

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

    void SetSartFunc(ThreadStart func, void* args) {
        _start = func;
        _args  = args;
    };

    void* GetThreadArgs() {
        return _args;
    }
    
protected: 

    virtual void CleanState(void);
    
private:    
    ThreadState _state;
    ThreadType _type;
    ThreadFlag _flag;
    KqObjList _fdset;
    SubThreadList _sub_list;
    MicroThread* _parent;
    ThreadStart _start;
    void* _args;

};
typedef std::set<MicroThread*> ThreadSet;
typedef std::queue<MicroThread*> ThreadList;


class LogAdapter
{
public:

    LogAdapter(){};
    virtual ~LogAdapter(){};

    virtual bool CheckDebug(){ return true;};
    virtual bool CheckTrace(){ return true;};
    virtual bool CheckError(){ return true;};

    virtual void LogDebug(char* fmt, ...){};
    virtual void LogTrace(char* fmt, ...){};
    virtual void LogError(char* fmt, ...){};

    virtual void AttrReportAdd(int attr, int iValue){};
    virtual void AttrReportSet(int attr, int iValue){};
    
};

class DefaultLogAdapter :public LogAdapter
{
public:


    bool CheckDebug(){ return false;};
    bool CheckTrace(){ return false;};
    bool CheckError(){ return false;};

    inline void LogDebug(char* fmt, ...){
        va_list args;
        char szBuff[1024];
        va_start(args, fmt);
        memset(szBuff, 0, sizeof(szBuff));
        vsprintf(szBuff, fmt, args);
        va_end(args);
        printf("%s\n",szBuff);
    };
    inline void LogTrace(char* fmt, ...){
        va_list args;
        char szBuff[1024];
        va_start(args, fmt);
        memset(szBuff, 0, sizeof(szBuff));
        vsprintf(szBuff, fmt, args);
        va_end(args);
        printf("%s\n",szBuff);
    };
    inline void LogError(char* fmt, ...){
        va_list args;
        char szBuff[1024];
        va_start(args, fmt);
        memset(szBuff, 0, sizeof(szBuff));
        vsprintf(szBuff, fmt, args);
        va_end(args);
        printf("%s\n",szBuff);
    };
    
};

class ThreadPool
{
public:

    static unsigned int default_thread_num;
    static unsigned int last_default_thread_num;
    static unsigned int default_stack_size;

    static void SetDefaultThreadNum(unsigned int num) {
        default_thread_num = num;   
    }; 

    static void SetDefaultStackSize(unsigned int size) {
        default_stack_size = (size + MEM_PAGE_SIZE - 1) / MEM_PAGE_SIZE * MEM_PAGE_SIZE;   
    }; 
    
    bool InitialPool(int max_num);

    void DestroyPool (void); 

    MicroThread* AllocThread(void);

    void FreeThread(MicroThread* thread);

    int GetUsedNum(void);
    
private:
    ThreadList      _freelist;
    int             _total_num;
    int             _use_num;
    int             _max_num;
};

typedef TAILQ_HEAD(__ThreadTailq, MicroThread) ThreadTailq;

class MtFrame : public KqueueProxy, public ThreadPool
{
private:
    static MtFrame* _instance;
    LogAdapter*     _log_adpt;
    ThreadList      _runlist;
    ThreadTailq     _iolist;
    ThreadTailq     _pend_list;
    HeapList        _sleeplist;
    MicroThread*    _daemon;
    MicroThread*    _primo;
    MicroThread*    _curr_thread;
    utime64_t       _last_clock;
    int             _waitnum;
    CTimerMng*      _timer;
    int             _realtime;

public:
    friend class ScheduleObj;

public:  

    static MtFrame* Instance (void);

    static int sendto(int fd, const void *msg, int len, int flags, const struct sockaddr *to, int tolen, int timeout);

    static int recvfrom(int fd, void *buf, int len, int flags, struct sockaddr *from, socklen_t *fromlen, int timeout);

    static int connect(int fd, const struct sockaddr *addr, int addrlen, int timeout);

    static int accept(int fd, struct sockaddr *addr, socklen_t *addrlen, int timeout);

    static ssize_t read(int fd, void *buf, size_t nbyte, int timeout);

    static ssize_t write(int fd, const void *buf, size_t nbyte, int timeout);

    static int recv(int fd, void *buf, int len, int flags, int timeout);

    static ssize_t send(int fd, const void *buf, size_t nbyte, int flags, int timeout);

    static void sleep(int ms);

    static int WaitEvents(int fd, int events, int timeout);

    static MicroThread* CreateThread(ThreadStart entry, void *args, bool runable = true);

    static void DaemonRun(void* args);
    static int Loop(void* args);

    MicroThread *GetRootThread();

    bool InitFrame(LogAdapter* logadpt = NULL, int max_thread_num = MAX_THREAD_NUM);

    void SetHookFlag();

    void Destroy (void);
    
    char* Version(void);

    utime64_t GetLastClock(void) {
        if(_realtime)
        {
            return GetSystemMS();
        }    
        return _last_clock;
    };

    MicroThread* GetActiveThread(void) {
        return _curr_thread;
    }; 

    int RunWaitNum(void) {
        return _waitnum;        
    };

    LogAdapter* GetLogAdpt(void) {
        return _log_adpt;
    };

    CTimerMng* GetTimerMng(void) {
        return _timer;
    };

    virtual int KqueueGetTimeout(void);
    
    virtual bool KqueueSchedule(KqObjList* fdlist, KqueuerObj* fd, int timeout);    

    void WaitNotify(utime64_t timeout);

    void NotifyThread(MicroThread* thread);

    void SwapDaemonThread();

    void RemoveIoWait(MicroThread* thread);    

    void InsertRunable(MicroThread* thread);

    void InsertPend(MicroThread* thread);

    void RemovePend(MicroThread* thread);

    void SetRealTime(int realtime_)
    {
        _realtime =realtime_;
    }
private:

    MtFrame():_realtime(1){ _curr_thread = NULL; }; 

    MicroThread* DaemonThread(void){
        return _daemon;
    };

    void ThreadSchdule(void);

    void CheckExpired();
    
    void WakeupTimeout(void);
    
    void SetLastClock(utime64_t clock) {
        _last_clock = clock;
    };

    void SetActiveThread(MicroThread* thread) {
        _curr_thread = thread;
    };

    utime64_t GetSystemMS(void) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL);
    };

    void InsertSleep(MicroThread* thread);

    void RemoveSleep(MicroThread* thread);

    void InsertIoWait(MicroThread* thread);

    void RemoveRunable(MicroThread* thread);    

};

#define MTLOG_DEBUG(fmt, args...)                                              \
do {                                                                           \
       register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
       if (fm && fm->GetLogAdpt() && fm->GetLogAdpt()->CheckDebug())           \
       {                                                                       \
          fm->GetLogAdpt()->LogDebug((char*)"[%-10s][%-4d][%-10s]" fmt,        \
                __FILE__, __LINE__, __FUNCTION__, ##args);                     \
       }                                                                       \
} while (0)

#define MTLOG_TRACE(fmt, args...)                                              \
do {                                                                           \
       register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
       if (fm && fm->GetLogAdpt() && fm->GetLogAdpt()->CheckTrace())           \
       {                                                                       \
          fm->GetLogAdpt()->LogTrace((char*)"[%-10s][%-4d][%-10s]" fmt,        \
                __FILE__, __LINE__, __FUNCTION__, ##args);                     \
       }                                                                       \
} while (0)

#define MTLOG_ERROR(fmt, args...)                                              \
do {                                                                           \
       register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
       if (fm && fm->GetLogAdpt() && fm->GetLogAdpt()->CheckError())           \
       {                                                                       \
          fm->GetLogAdpt()->LogError((char*)"[%-10s][%-4d][%-10s]" fmt,        \
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
       do {                                                                           \
              register NS_MICRO_THREAD::MtFrame *fm = NS_MICRO_THREAD::MtFrame::Instance(); \
              if (fm && fm->GetLogAdpt())                                              \
              {                                                                       \
                 fm->GetLogAdpt()->AttrReportSet(ATTR, VALUE);                          \
              }                                                                       \
       } while (0)



}// NAMESPACE NS_MICRO_THREAD

#endif

