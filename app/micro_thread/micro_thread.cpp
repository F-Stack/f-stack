
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
 *  @filename micro_thread.cpp
 *  @info  micro thread manager
 */
#include "mt_version.h"
#include "micro_thread.h"
#include "mt_net.h"
#include "valgrind.h"
#include <assert.h>
#include "mt_sys_hook.h"
#include "ff_hook.h"
#include "ff_api.h"

using namespace NS_MICRO_THREAD;

#define  ASSERT(statement)
//#define  ASSERT(statement)   assert(statement)

extern "C"  int save_context(jmp_buf jbf);

extern "C"  void restore_context(jmp_buf jbf, int ret);

extern "C"  void replace_esp(jmp_buf jbf, void* esp);

Thread::Thread(int stack_size)
{
    _stack_size  = stack_size ? stack_size : ThreadPool::default_stack_size;
    _wakeup_time = 0;
    _stack       = NULL;
    memset(&_jmpbuf, 0, sizeof(_jmpbuf));
}

static DefaultLogAdapter def_log_adapt;
/**
 *  @brief LINUX x86/x86_64's allocated stacks.
 */
bool Thread::InitStack()
{
    if (_stack) {
        return true;
    }

    ///< stack index and memory are separated to prevent out of bounds.
    _stack = (MtStack*)calloc(1, sizeof(MtStack));
    if (NULL == _stack)
    {
        MTLOG_ERROR("calloc stack failed, size %u", sizeof(MtStack));
        return false;
    }

    int memsize = MEM_PAGE_SIZE*2 + _stack_size;
    memsize = (memsize + MEM_PAGE_SIZE - 1)/MEM_PAGE_SIZE*MEM_PAGE_SIZE;

    static int zero_fd = -1;
    int mmap_flags = MAP_PRIVATE | MAP_ANON;
    void* vaddr = mmap(NULL, memsize, PROT_READ | PROT_WRITE, mmap_flags, zero_fd, 0);
    if (vaddr == (void *)MAP_FAILED)
    {
        MTLOG_ERROR("mmap stack failed, size %d,errmsg: %s.", memsize,strerror(errno));
        free(_stack);
        _stack = NULL;
        return false;
    }
    _stack->_vaddr = (char*)vaddr;
    _stack->_vaddr_size = memsize;
    _stack->_stk_size = _stack_size;
    _stack->_stk_bottom = _stack->_vaddr + MEM_PAGE_SIZE;
    _stack->_stk_top = _stack->_stk_bottom + _stack->_stk_size;
    // valgrind support: register stack frame
    _stack->valgrind_id = VALGRIND_STACK_REGISTER(_stack->_stk_bottom, _stack->_stk_top);
   
    _stack->_esp = _stack->_stk_top - STACK_PAD_SIZE;
    
    mprotect(_stack->_vaddr, MEM_PAGE_SIZE, PROT_NONE);
    mprotect(_stack->_stk_top, MEM_PAGE_SIZE, PROT_NONE);

    return true;
}


void Thread::FreeStack()
{
    if (!_stack) {
        return;
    }
    munmap(_stack->_vaddr, _stack->_vaddr_size);
    // valgrind support: deregister stack frame
    VALGRIND_STACK_DEREGISTER(_stack->valgrind_id);
    free(_stack);
    _stack = NULL;
}

void Thread::InitContext()
{
    if (save_context(_jmpbuf) != 0)
    {
        ScheduleObj::Instance()->ScheduleStartRun();
    }
    
    if (_stack != NULL)
    {
        replace_esp(_jmpbuf, _stack->_esp);
    }
}

void Thread::SwitchContext()
{
    if (save_context(_jmpbuf) == 0)
    {
        ScheduleObj::Instance()->ScheduleThread();
    }
}


int Thread::SaveContext()
{
    return save_context(_jmpbuf);
}

void Thread::RestoreContext()
{
    restore_context(_jmpbuf, 1);    
}


bool Thread::Initial()
{
    if (!InitStack())
    {
        MTLOG_ERROR("init stack failed");
        return false;
    }

    InitContext();  

    return true;
}

void Thread::Destroy()
{
    FreeStack();
    memset(&_jmpbuf, 0, sizeof(_jmpbuf));
}

void Thread::Reset()
{
    _wakeup_time = 0;
    SetPrivate(NULL);
    
    InitContext();
    CleanState();
}

void Thread::sleep(int ms)
{
    utime64_t now = ScheduleObj::Instance()->ScheduleGetTime();    
    _wakeup_time = now + ms;
   
    if (save_context(_jmpbuf) == 0)
    {
        ScheduleObj::Instance()->ScheduleSleep();
    }    
}

void Thread::Wait()
{
    if (save_context(_jmpbuf) == 0)
    {
        ScheduleObj::Instance()->SchedulePend();
    }
}

bool Thread::CheckStackHealth(char *esp)
{
    if (!_stack)
        return false;

    if (esp > _stack->_stk_bottom && esp < _stack->_stk_top)
        return true;
    else
        return false;
}

MicroThread::MicroThread(ThreadType type)
{
    memset(&_entry, 0, sizeof(_entry));
    TAILQ_INIT(&_fdset);
    TAILQ_INIT(&_sub_list);
    _flag = NOT_INLIST;
    _type = type;
    _state = INITIAL;
    _start = NULL;
    _args = NULL;
    _parent = NULL;
}

void MicroThread::CleanState()
{
    TAILQ_INIT(&_fdset);
    TAILQ_INIT(&_sub_list);
    _flag = NOT_INLIST;
    _type = NORMAL;
    _state = INITIAL;
    _start = NULL;
    _args = NULL;
    _parent = NULL;
}

void MicroThread::Run()
{
    if (_start) {
        _start(_args);
    }

    if (this->IsSubThread()) {
        this->WakeupParent();
    }

    ScheduleObj::Instance()->ScheduleReclaim();
    ScheduleObj::Instance()->ScheduleThread();
}

void MicroThread::WakeupParent()
{
    MicroThread* parent = this->GetParent();
    if (parent) 
    {
        parent->RemoveSubThread(this);
        if (parent->HasNoSubThread())
        {
            ScheduleObj::Instance()->ScheduleUnpend(parent);
        }
    }
    else
    {
        MTLOG_ERROR("Sub thread no parent, error");
    }
}

bool MicroThread::HasNoSubThread()
{
    return TAILQ_EMPTY(&_sub_list);
}

void MicroThread::AddSubThread(MicroThread* sub)
{
    ASSERT(!sub->HasFlag(MicroThread::SUB_LIST));
    if (!sub->HasFlag(MicroThread::SUB_LIST)) 
    {
        TAILQ_INSERT_TAIL(&_sub_list, sub, _sub_entry);
        sub->_parent = this;
    }

    sub->SetFlag(MicroThread::SUB_LIST);
}

void MicroThread::RemoveSubThread(MicroThread* sub)
{
    ASSERT(sub->HasFlag(MicroThread::SUB_LIST));
    if (sub->HasFlag(MicroThread::SUB_LIST))
    {
        TAILQ_REMOVE(&_sub_list, sub, _sub_entry);
        sub->_parent = NULL;
    }

    sub->UnsetFlag(MicroThread::SUB_LIST);
}

ScheduleObj *ScheduleObj::_instance = NULL;
inline ScheduleObj* ScheduleObj::Instance()
{
    if (NULL == _instance)
    {
        _instance = new ScheduleObj();
    }

    return _instance;
}

void ScheduleObj::ScheduleThread()
{
    MtFrame* frame = MtFrame::Instance();
    frame->ThreadSchdule();
}

utime64_t ScheduleObj::ScheduleGetTime()
{
    MtFrame* frame = MtFrame::Instance();
    if (frame) 
    {
        return frame->GetLastClock();
    }
    else
    {
        MTLOG_ERROR("frame time failed, maybe not init");
        return 0;
    }
}

void ScheduleObj::ScheduleSleep()
{
    MtFrame* frame = MtFrame::Instance();
    MicroThread* thread = frame->GetActiveThread();
    if ((!frame) || (!thread)) {
        MTLOG_ERROR("frame and act thread null, %p, %p", frame, thread);
        return;
    }
    
    frame->InsertSleep(thread);
    frame->ThreadSchdule();
}

void ScheduleObj::SchedulePend()
{
    MtFrame* frame = MtFrame::Instance();
    MicroThread* thread = frame->GetActiveThread();
    if ((!frame) || (!thread)) {
        MTLOG_ERROR("frame and act thread null, %p, %p", frame, thread);
        return;
    }
    
    frame->InsertPend(thread);
    frame->ThreadSchdule();
}

void ScheduleObj::ScheduleUnpend(void* pthread)
{
    MtFrame* frame = MtFrame::Instance();
    MicroThread* thread = (MicroThread*)pthread;
    if ((!frame) || (!thread)) {
        MTLOG_ERROR("frame and act thread null, %p, %p", frame, thread);
        return;
    }

    frame->RemovePend(thread);
    frame->InsertRunable(thread);
}

void ScheduleObj::ScheduleReclaim()
{
    MtFrame* frame = MtFrame::Instance();
    MicroThread* thread = frame->GetActiveThread();
    if ((!frame) || (!thread)) {
        MTLOG_ERROR("frame and act thread null, %p, %p", frame, thread);
        return;
    }

    frame->FreeThread(thread);
}

void ScheduleObj::ScheduleStartRun()
{
    MtFrame* frame = MtFrame::Instance();
    MicroThread* thread = frame->GetActiveThread();
    if ((!frame) || (!thread)) {
        MTLOG_ERROR("frame and act thread null, %p, %p", frame, thread);
        return;
    }

    thread->Run();
}


unsigned int ThreadPool::default_thread_num = DEFAULT_THREAD_NUM;   ///< 2000 micro threads.
unsigned int ThreadPool::last_default_thread_num = DEFAULT_THREAD_NUM;   ///< 2000 micro threads.
unsigned int ThreadPool::default_stack_size = DEFAULT_STACK_SIZE;   ///< 128k stack. 

bool ThreadPool::InitialPool(int max_num)
{
    MicroThread *thread = NULL;
    for (unsigned int i = 0; i < default_thread_num; i++)
    {
        thread = new MicroThread();
        if ((NULL == thread) || (false == thread->Initial()))
        {
            MTLOG_ERROR("init pool, thread %p init failed", thread);
            if (thread)  delete thread;
            continue;
        }
        thread->SetFlag(MicroThread::FREE_LIST);
        _freelist.push(thread);
    }
    
    _total_num = _freelist.size();
    _max_num  = max_num;
    _use_num = 0;
    if (_total_num <= 0)
    {
        return false;
    }
    else
    {
        return true;
    }    
}

void ThreadPool::DestroyPool()
{
    MicroThread* thread = NULL;
    while (!_freelist.empty())
    {
        thread = _freelist.front();
        _freelist.pop();
        thread->Destroy();
        delete thread;
    }

    _total_num = 0;
    _use_num = 0;
}

MicroThread* ThreadPool::AllocThread()
{
    MT_ATTR_API_SET(492069, _total_num);

    MicroThread* thread = NULL;
    if (!_freelist.empty())
    {   
        thread = _freelist.front();
        _freelist.pop();

        ASSERT(thread->HasFlag(MicroThread::FREE_LIST));

        thread->UnsetFlag(MicroThread::FREE_LIST);
        _use_num++;
        return thread;
    }

    MT_ATTR_API(320846, 1); // pool no nore
    if (_total_num >= _max_num)
    {
        MT_ATTR_API(361140, 1); // no more quota
        MTLOG_ERROR("total %d is outof max: %d", _total_num,_max_num);
        return NULL;
    }
    
    thread = new MicroThread();
    if ((NULL == thread) || (false == thread->Initial()))
    {
        MT_ATTR_API(320847, 1); // pool init fail
        MTLOG_ERROR("thread alloc failed, thread: %p", thread);
        if (thread)  delete thread;
        return NULL;
    }
    _total_num++;
    _use_num++;
    if(_use_num >(int) default_thread_num){
        if(((int) default_thread_num * 2 )< _max_num){
            last_default_thread_num = default_thread_num;
            default_thread_num = default_thread_num * 2;
        }
    }

    return thread;    
}

void ThreadPool::FreeThread(MicroThread* thread)
{
    ASSERT(!thread->HasFlag(MicroThread::FREE_LIST));
    thread->Reset();
    _use_num--;
    _freelist.push(thread);
    thread->SetFlag(MicroThread::FREE_LIST);

    unsigned int free_num = _freelist.size();
    if ((free_num > default_thread_num) && (free_num > 1))
    {
        thread = _freelist.front();
        _freelist.pop();
        thread->Destroy();
        delete thread;
        _total_num--;
        if(default_thread_num / 2 >= DEFAULT_THREAD_NUM){
            last_default_thread_num = default_thread_num;
            default_thread_num = default_thread_num / 2;
        }
    }
}

int ThreadPool::GetUsedNum(void)
{
    return _use_num;
}

MtFrame *MtFrame::_instance = NULL;
inline MtFrame* MtFrame::Instance ()
{
    if (NULL == _instance )
    {
        _instance = new MtFrame();
    }

    return _instance;
}

void MtFrame::SetHookFlag() {
    mt_set_hook_flag();
};

bool MtFrame::InitFrame(LogAdapter* logadpt, int max_thread_num)
{
    if(logadpt == NULL){
        _log_adpt = &def_log_adapt;
    }else{
        _log_adpt = logadpt;
    }

    if ((this->InitKqueue(max_thread_num) < 0) || !this->InitialPool(max_thread_num))
    {
        MTLOG_ERROR("Init epoll or thread pool failed");
        this->Destroy();
        return false;
    }
    if (_sleeplist.HeapResize(max_thread_num * 2) < 0)
    {
        MTLOG_ERROR("Init heap list failed");
        this->Destroy();
        return false;
    }
    
    _timer = new CTimerMng(max_thread_num * 2);
    if (NULL == _timer)
    {
        MTLOG_ERROR("Init heap timer failed");
        this->Destroy();
        return false;
    }

    _daemon = AllocThread();
    if (NULL == _daemon)
    {
        MTLOG_ERROR("Alloc daemon thread failed");
        this->Destroy();
        return false;
    }    
    _daemon->SetType(MicroThread::DAEMON);
    _daemon->SetState(MicroThread::RUNABLE);
    _daemon->SetSartFunc(MtFrame::DaemonRun, this);

    _primo = new MicroThread(MicroThread::PRIMORDIAL);
    if (NULL == _primo)
    {
        MTLOG_ERROR("new _primo thread failed");
        this->Destroy();
        return false;
    }
    _primo->SetState(MicroThread::RUNNING);
    SetActiveThread(_primo);

    _last_clock = GetSystemMS();
    TAILQ_INIT(&_iolist);
    TAILQ_INIT(&_pend_list);

    //SetHookFlag();

    return true;
    
}

void MtFrame::Destroy(void)
{
    if (NULL == _instance )
    {
        return;
    }

    if (_primo) {
        delete _primo;
        _primo = NULL;
    }

    if (_daemon) {
        FreeThread(_daemon);
        _daemon = NULL;
    }
    
    TAILQ_INIT(&_iolist);
    
    MicroThread* thread = dynamic_cast<MicroThread*>(_sleeplist.HeapPop());
    while (thread)
    {
        FreeThread(thread);
        thread = dynamic_cast<MicroThread*>(_sleeplist.HeapPop());
    }
    
    while (!_runlist.empty())
    {
        thread = _runlist.front();
        _runlist.pop();
        FreeThread(thread);
    }

    MicroThread* tmp;
    TAILQ_FOREACH_SAFE(thread, &_pend_list, _entry, tmp)
    {
        TAILQ_REMOVE(&_pend_list, thread, _entry);
        FreeThread(thread);
    }  

    if (_timer != NULL)
    {
        delete _timer;
        _timer = NULL;
    }

    _instance->DestroyPool();
    _instance->TermKqueue();
    delete _instance;
    _instance = NULL;
}

char* MtFrame::Version()
{
    return IMT_VERSION;
}

MicroThread* MtFrame::CreateThread(ThreadStart entry, void *args, bool runable)
{
    MtFrame* mtframe = MtFrame::Instance();
    MicroThread* thread = mtframe->AllocThread(); 
    if (NULL == thread)
    {
        MTLOG_ERROR("create thread failed");
        return NULL;
    }
    thread->SetSartFunc(entry, args);

    if (runable) {
        mtframe->InsertRunable(thread);
    }

    return thread;
}

int MtFrame::Loop(void* args)
{
    MtFrame* mtframe = MtFrame::Instance();
    MicroThread* daemon = mtframe->DaemonThread(); 

    mtframe->KqueueDispatch();        
    mtframe->SetLastClock(mtframe->GetSystemMS());
    mtframe->WakeupTimeout(); 
    mtframe->CheckExpired();
    daemon->SwitchContext();

    return 0;
}

void MtFrame::DaemonRun(void* args)
{
    /*
    MtFrame* mtframe = MtFrame::Instance();
    MicroThread* daemon = mtframe->DaemonThread(); 

    while (true) {
        mtframe->KqueueDispatch();        
        mtframe->SetLastClock(mtframe->GetSystemMS());
        mtframe->WakeupTimeout(); 
        mtframe->CheckExpired();
        daemon->SwitchContext();
    }
    */
    ff_run(MtFrame::Loop, NULL);
}

MicroThread *MtFrame::GetRootThread()
{
    if (NULL == _curr_thread)
    {
        return NULL;
    }

    MicroThread::ThreadType type = _curr_thread->GetType();
    MicroThread *thread = _curr_thread;
    MicroThread *parent = thread;

    while (MicroThread::SUB_THREAD == type)
    {
        thread = thread->GetParent();
        if (!thread)
        {
            break;
        }

        type   = thread->GetType();
        parent = thread;
    }

    return parent;
}

void MtFrame::ThreadSchdule()
{
    MicroThread* thread = NULL;    
    MtFrame* mtframe = MtFrame::Instance();
    
    if (mtframe->_runlist.empty())
    {
        thread = mtframe->DaemonThread();
    }
    else
    {
        thread = mtframe->_runlist.front();
        mtframe->RemoveRunable(thread);
    }

    this->SetActiveThread(thread);
    thread->SetState(MicroThread::RUNNING);
    thread->RestoreContext();
}

void MtFrame::CheckExpired()
{
    static utime64_t check_time = 0;
    
    if (_timer != NULL)
    {
        _timer->check_expired();
    }

   utime64_t now = GetLastClock();

    if ((now - check_time) > 1000)
    {
        CNetMgr::Instance()->RecycleObjs(now);
        check_time = now;
    }
}

void MtFrame::WakeupTimeout()
{
    utime64_t now = GetLastClock();
    MicroThread* thread = dynamic_cast<MicroThread*>(_sleeplist.HeapTop());
    while (thread && (thread->GetWakeupTime() <= now))
    {
        if (thread->HasFlag(MicroThread::IO_LIST))
        {
            RemoveIoWait(thread);
        }
        else
        {
            RemoveSleep(thread);
        }
        
        InsertRunable(thread);
        
        thread = dynamic_cast<MicroThread*>(_sleeplist.HeapTop());
    }    
}

int MtFrame::KqueueGetTimeout()
{
    utime64_t now = GetLastClock();
    MicroThread* thread = dynamic_cast<MicroThread*>(_sleeplist.HeapTop());
    if (!thread)
    {
        return 10; //default 10ms epollwait
    }
    else if (thread->GetWakeupTime() < now)
    {
        return 0;
    }
    else
    {
        return (int)(thread->GetWakeupTime() - now);
    }
}

inline void MtFrame::InsertSleep(MicroThread* thread)
{
    ASSERT(!thread->HasFlag(MicroThread::SLEEP_LIST));

    thread->SetFlag(MicroThread::SLEEP_LIST);
    thread->SetState(MicroThread::SLEEPING);
    int rc = _sleeplist.HeapPush(thread);
    if (rc < 0)
    {
        MT_ATTR_API(320848, 1); // heap error
        MTLOG_ERROR("Insert heap failed , rc %d", rc);
    }
}

inline void MtFrame::RemoveSleep(MicroThread* thread)
{
    ASSERT(thread->HasFlag(MicroThread::SLEEP_LIST));
    thread->UnsetFlag(MicroThread::SLEEP_LIST);

    int rc = _sleeplist.HeapDelete(thread);
    if (rc < 0)
    {
        MT_ATTR_API(320849, 1); // heap error
        MTLOG_ERROR("remove heap failed , rc %d", rc);
    }
}

inline void MtFrame::InsertIoWait(MicroThread* thread)
{
    ASSERT(!thread->HasFlag(MicroThread::IO_LIST));
    thread->SetFlag(MicroThread::IO_LIST);
    TAILQ_INSERT_TAIL(&_iolist, thread, _entry);
    InsertSleep(thread);
}

void MtFrame::RemoveIoWait(MicroThread* thread)
{
    ASSERT(thread->HasFlag(MicroThread::IO_LIST));
    thread->UnsetFlag(MicroThread::IO_LIST);
    TAILQ_REMOVE(&_iolist, thread, _entry);

    RemoveSleep(thread);
}

void MtFrame::InsertRunable(MicroThread* thread)
{
    ASSERT(!thread->HasFlag(MicroThread::RUN_LIST));
    thread->SetFlag(MicroThread::RUN_LIST);

    thread->SetState(MicroThread::RUNABLE);
    _runlist.push(thread);
    _waitnum++;
}

inline void MtFrame::RemoveRunable(MicroThread* thread)
{
    ASSERT(thread->HasFlag(MicroThread::RUN_LIST));
    ASSERT(thread == _runlist.front());
    thread->UnsetFlag(MicroThread::RUN_LIST);

    _runlist.pop();
    _waitnum--;
}

void MtFrame::InsertPend(MicroThread* thread)
{
    ASSERT(!thread->HasFlag(MicroThread::PEND_LIST));
    thread->SetFlag(MicroThread::PEND_LIST);
    TAILQ_INSERT_TAIL(&_pend_list, thread, _entry);
    thread->SetState(MicroThread::PENDING);    
}

void MtFrame::RemovePend(MicroThread* thread)
{
    ASSERT(thread->HasFlag(MicroThread::PEND_LIST));
    thread->UnsetFlag(MicroThread::PEND_LIST);
    TAILQ_REMOVE(&_pend_list, thread, _entry);
}

void MtFrame::WaitNotify(utime64_t timeout)
{
    MicroThread* thread = GetActiveThread();
    
    thread->SetWakeupTime(timeout + this->GetLastClock());
    this->InsertIoWait(thread); 
    thread->SwitchContext();
}

void MtFrame::NotifyThread(MicroThread* thread)
{
    if(thread == NULL){
        return;
    }
    MicroThread* cur_thread = GetActiveThread();
    if (thread->HasFlag(MicroThread::IO_LIST))
    {
        this->RemoveIoWait(thread);
        if(cur_thread == this->DaemonThread()){
            // 这里不直接切的话,还是不及时,会导致目标线程等待到超时
            if(cur_thread->SaveContext() == 0){
                this->SetActiveThread(thread);
                thread->SetState(MicroThread::RUNNING);
                thread->RestoreContext();
            }
        }else{
            this->InsertRunable(thread);
        }
    }
}

void MtFrame::SwapDaemonThread()
{
    MicroThread* thread = GetActiveThread();
    MicroThread* daemon_thread = this->DaemonThread();
    if(thread != daemon_thread){
        if(thread->SaveContext() == 0){
            this->InsertRunable(thread);
            this->SetActiveThread(daemon_thread);
            daemon_thread->SetState(MicroThread::RUNNING);
            daemon_thread->RestoreContext();
        }
    }
}

bool MtFrame::KqueueSchedule(KqObjList* fdlist, KqueuerObj* fd, int timeout)
{
    MicroThread* thread = GetActiveThread();
    if (NULL == thread)
    {
        MTLOG_ERROR("active thread null, epoll schedule failed");
        return false;
    }

    thread->ClearAllFd();
    if (fdlist) 
    {
        thread->AddFdList(fdlist);
    }
    if (fd) 
    {
        thread->AddFd(fd);
    }

    thread->SetWakeupTime(timeout + this->GetLastClock());
    if (!this->KqueueAdd(thread->GetFdSet()))
    {
        MTLOG_ERROR("epoll add failed, errno: %d", errno);
        return false;
    }
    this->InsertIoWait(thread); 
    thread->SwitchContext();

    int rcvnum = 0;
    KqObjList& rcvfds = thread->GetFdSet();
    KqueuerObj* fdata = NULL;
    TAILQ_FOREACH(fdata, &rcvfds, _entry)
    {
        if (fdata->GetRcvEvents() != 0)
        {
            rcvnum++;
        }        
    }
    this->KqueueDel(rcvfds);

    if (rcvnum == 0)
    {
        errno = ETIME;
        return false;
    }

    return true;   
}

int MtFrame::recvfrom(int fd, void *buf, int len, int flags, struct sockaddr *from, socklen_t *fromlen, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;

    if(fd<0 || !buf || len<1)
    {
        errno = EINVAL;
        MTLOG_ERROR("recvfrom failed, errno: %d (%m)", errno);
        return -10;
    }
    
    if (timeout <= -1)
    {
        timeout = 0x7fffffff;
    }

    while (true) 
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return -1;
        }        
        
        KqueuerObj epfd;
        epfd.SetOsfd(fd);
        epfd.EnableInput();
        epfd.SetOwnerThread(thread);
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout))
        {
            MTLOG_DEBUG("epoll schedule failed, errno: %d", errno);
            return -2;
        }

        mt_hook_syscall(recvfrom);
        int n = ff_hook_recvfrom(fd, buf, len, flags, from, fromlen);
        if (n < 0)
        {
            if (errno == EINTR) {
                continue;
            }
            
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) 
            {
                MTLOG_ERROR("recvfrom failed, errno: %d", errno);
                return -3;
            }
        }
        else
        {
            return n;
        }        
    }

}

int MtFrame::sendto(int fd, const void *msg, int len, int flags, const struct sockaddr *to, int tolen, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;

    if(fd<0 || !msg || len<1)
    {
        errno = EINVAL;
        MTLOG_ERROR("sendto failed, errno: %d (%m)", errno);
        return -10;
    }
    
    int n = 0; 
    mt_hook_syscall(sendto);
    while ((n = ff_hook_sendto(fd, msg, len, flags, to, tolen)) < 0)
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return -1;
        }
        
        if (errno == EINTR) {
            continue;
        }

        if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            MTLOG_ERROR("sendto failed, errno: %d", errno);
            return -2;
        }

        KqueuerObj epfd;
        epfd.SetOsfd(fd);
        epfd.EnableOutput();
        epfd.SetOwnerThread(thread);
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout)) {
            return -3;
        }
    }

    return n;
}

int MtFrame::connect(int fd, const struct sockaddr *addr, int addrlen, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;

    if(fd<0 || !addr || addrlen<1)
    {
        errno = EINVAL;
        MTLOG_ERROR("connect failed, errno: %d (%m)", errno);
        return -10;
    }
    
    int n = 0; 
    mt_hook_syscall(connect);
    while ((n = ff_hook_connect(fd, addr, addrlen)) < 0)
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return -1;
        }

        if (errno == EISCONN)
        {
            return 0;
        }
        
        if (errno == EINTR) {
            continue;
        }

        if (errno != EINPROGRESS) {
            MTLOG_ERROR("connect failed, errno: %d", errno);
            return -2;
        }

        KqueuerObj epfd;
        epfd.SetOsfd(fd);
        epfd.EnableOutput();
        epfd.SetOwnerThread(thread);
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout)) {
            return -3;
        }
    }

    return n;
}

int MtFrame::accept(int fd, struct sockaddr *addr, socklen_t *addrlen, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;

    if(fd<0)
    {
        errno = EINVAL;
        MTLOG_ERROR("accept failed, errno: %d (%m)", errno);
        return -10;
    }
    
    int acceptfd = 0; 
    mt_hook_syscall(accept);
    while ((acceptfd = ff_hook_accept(fd, addr, addrlen)) < 0)
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return -1;
        }
        
        if (errno == EINTR) {
            continue;
        }

        if (!((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
            MTLOG_ERROR("accept failed, errno: %d", errno);
            return -2;
        }

        KqueuerObj epfd;
        epfd.SetOsfd(fd);
        epfd.EnableInput();
        epfd.SetOwnerThread(thread);
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout)) {
            return -3;
        }
    }

    return acceptfd;
}

ssize_t MtFrame::read(int fd, void *buf, size_t nbyte, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;

    if(fd<0 || !buf || nbyte<1)
    {
        errno = EINVAL;
        MTLOG_ERROR("read failed, errno: %d (%m)", errno);
        return -10;
    }
    
    ssize_t n = 0;
    mt_hook_syscall(read);
    while ((n = ff_hook_read(fd, buf, nbyte)) < 0)
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return -1;
        }
        
        if (errno == EINTR) {
            continue;
        }

        if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            MTLOG_ERROR("read failed, errno: %d", errno);
            return -2;
        }
        
        KqueuerObj epfd;
        epfd.SetOsfd(fd);
        epfd.EnableInput();
        epfd.SetOwnerThread(thread);
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout)) {
            return -3;
        }
    }
    
    return n;
}

ssize_t MtFrame::write(int fd, const void *buf, size_t nbyte, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;

    if(fd<0 || !buf || nbyte<1)
    {
        errno = EINVAL;
        MTLOG_ERROR("write failed, errno: %d (%m)", errno);
        return -10;
    }
    
    ssize_t n = 0;
    size_t send_len = 0;
    while (send_len < nbyte)
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return -1;
        }

        mt_hook_syscall(write);
        n = ff_hook_write(fd, (char*)buf + send_len, nbyte - send_len);
        if (n < 0)
        {
            if (errno == EINTR) {
                continue;
            }
            
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                MTLOG_ERROR("write failed, errno: %d", errno);
                return -2;
            }
        }
        else
        {
            send_len += n;
            if (send_len >= nbyte) {
                return nbyte;
            }
        }

        KqueuerObj epfd;
        epfd.SetOsfd(fd);
        epfd.EnableOutput();
        epfd.SetOwnerThread(thread);
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout)) {
            return -3;
        }
    }

    return nbyte;
}

int MtFrame::recv(int fd, void *buf, int len, int flags, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;

    if(fd<0 || !buf || len<1)
    {
        errno = EINVAL;
        MTLOG_ERROR("recv failed, errno: %d (%m)", errno);
        return -10;
    }
    
    if (timeout <= -1)
    {
        timeout = 0x7fffffff;
    }

    while (true) 
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return -1;
        }        
        
        KqueuerObj epfd;
        epfd.SetOsfd(fd);
        epfd.EnableInput();
        epfd.SetOwnerThread(thread);
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout))
        {
            MTLOG_DEBUG("epoll schedule failed, errno: %d", errno);
            return -2;
        }

        mt_hook_syscall(recv);
        int n = ff_hook_recv(fd, buf, len, flags);
        if (n < 0)
        {
            if (errno == EINTR) {
                continue;
            }
            
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) 
            {
                MTLOG_ERROR("recv failed, errno: %d", errno);
                return -3;
            }
        }
        else
        {
            return n;
        }        
    }

}

ssize_t MtFrame::send(int fd, const void *buf, size_t nbyte, int flags, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;

    if(fd<0 || !buf || nbyte<1)
    {
        errno = EINVAL;
        MTLOG_ERROR("send failed, errno: %d (%m)", errno);
        return -10;
    }
    
    ssize_t n = 0;
    size_t send_len = 0;
    while (send_len < nbyte)
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return -1;
        }
        
        mt_hook_syscall(send);
        n = ff_hook_send(fd, (char*)buf + send_len, nbyte - send_len, flags);
        if (n < 0)
        {
            if (errno == EINTR) {
                continue;
            }
            
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                MTLOG_ERROR("write failed, errno: %d", errno);
                return -2;
            }
        }
        else
        {
            send_len += n;
            if (send_len >= nbyte) {
                return nbyte;
            }
        }
        
        KqueuerObj epfd;
        epfd.SetOsfd(fd);
        epfd.EnableOutput();
        epfd.SetOwnerThread(thread);
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout)) {
            return -3;
        }
    }

    return nbyte;
}

void MtFrame::sleep(int ms)
{
    MtFrame* frame = MtFrame::Instance();
    MicroThread* thread = frame->GetActiveThread();
    if (thread != NULL)
    {
        thread->sleep(ms);
    }
}

int MtFrame::WaitEvents(int fd, int events, int timeout)
{
    MtFrame* mtframe = MtFrame::Instance();
    utime64_t start = mtframe->GetLastClock();
    MicroThread* thread = mtframe->GetActiveThread();
    utime64_t now = 0;
    
    if (timeout <= -1)
    {
        timeout = 0x7fffffff;
    }

    while (true) 
    {
        now = mtframe->GetLastClock();
        if ((int)(now - start) > timeout)
        {
            errno = ETIME;            
            return 0;
        }        
        
        KqueuerObj epfd;
        epfd.SetOsfd(fd);        
        if (events & KQ_EVENT_READ)
        {
            epfd.EnableInput();
        }
        if (events & KQ_EVENT_WRITE)
        {
            epfd.EnableOutput();
        } 
        epfd.SetOwnerThread(thread);
        
        if (!mtframe->KqueueSchedule(NULL, &epfd, timeout))
        {
            MTLOG_TRACE("epoll schedule failed, errno: %d", errno);
            return 0;
        }

        return epfd.GetRcvEvents();
    }
}
