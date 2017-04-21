
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
 *  @filename epoll_proxy.h
 *  @info     epoll for micro thread manage
 */

#ifndef _EPOLL_PROXY___
#define _EPOLL_PROXY___

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/epoll.h>
#include <assert.h>

#include <set>
#include <vector>
using std::set;
using std::vector;

#define  epoll_assert(statement)
//#define  epoll_assert(statement)   assert(statement)


namespace NS_MICRO_THREAD {


/******************************************************************************/
/*  操作系统头文件适配定义                                                    */
/******************************************************************************/

/**
 * @brief add more detail for linux <sys/queue.h>, freebsd and University of California 
 * @info  queue.h version 8.3 (suse)  diff version 8.5 (tlinux)
 */
#ifndef TAILQ_CONCAT

#define TAILQ_EMPTY(head)   ((head)->tqh_first == NULL)
#define TAILQ_FIRST(head)   ((head)->tqh_first)
#define TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define TAILQ_LAST(head, headname) \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))

#define TAILQ_FOREACH(var, head, field)                                     \
        for ((var) = TAILQ_FIRST((head));                                   \
             (var);                                                         \
             (var) = TAILQ_NEXT((var), field))

#define TAILQ_CONCAT(head1, head2, field)                                   \
do {                                                                        \
    if (!TAILQ_EMPTY(head2)) {                                              \
        *(head1)->tqh_last = (head2)->tqh_first;                            \
        (head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;             \
        (head1)->tqh_last = (head2)->tqh_last;                              \
        TAILQ_INIT((head2));                                                \
    }                                                                       \
} while (0)

#endif    

#ifndef TAILQ_FOREACH_SAFE      // tlinux no this define    
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                          \
        for ((var) = TAILQ_FIRST((head));                                   \
             (var) && ((tvar) = TAILQ_NEXT((var), field), 1);               \
             (var) = (tvar))  
#endif



/******************************************************************************/
/*  Epoll proxy 定义与实现部分                                                */
/******************************************************************************/

class EpollProxy;
class MicroThread;

/**
 *  @brief epoll通知对象基类定义
 */
class EpollerObj
{
protected:
    int _fd;                ///< 系统FD 或 socket
    int _events;            ///< 监听的事件类型
    int _revents;           ///< 收到的事件类型
    int _type;              ///< 工厂类别定义
    MicroThread* _thread;   ///< 关联线程指针对象

public:

    TAILQ_ENTRY(EpollerObj) _entry;       ///< 关联微线程的管理入口
    
    /**
     *  @brief 构造与析构函数
     */
    explicit EpollerObj(int fd = -1) {
        _fd      = fd;
        _events  = 0;
        _revents = 0;
        _type    = 0;
        _thread  = NULL;
    };
    virtual ~EpollerObj(){};

    /**
     *  @brief 可读事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
     *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
     */
    virtual int InputNotify();
    
    /**
     *  @brief 可写事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
     *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
     */
    virtual int OutputNotify();
    
    /**
     *  @brief 异常通知接口
     *  @return 忽略返回值, 跳过其它事件处理
     */
    virtual int HangupNotify();

    /**
     *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
     *  @param args fd引用对象的指针
     *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
     */
    virtual int EpollCtlAdd(void* args);

    /**
     *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
     *  @param args fd引用对象的指针
     *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
     */
    virtual int EpollCtlDel(void* args);

    /**
     *  @brief fd打开可读事件侦听
     */
    void EnableInput() {    _events |= EPOLLIN; };

    /**
     *  @brief fd打开可写事件侦听
     */
    void EnableOutput() {     _events |= EPOLLOUT; };

    /**
     *  @brief fd关闭可读事件侦听
     */
    void DisableInput() {   _events &= ~EPOLLIN; };

    /**
     *  @brief fd关闭可写事件侦听
     */
    void DisableOutput() {    _events &= ~EPOLLOUT; };

    /**
     *  @brief 系统socket设置读取封装
     */
    int GetOsfd() { return _fd; };
    void SetOsfd(int fd) {   _fd = fd; };

    /**
     *  @brief 监听事件与收到事件的访问方法
     */
    int GetEvents() { return _events; };
    void SetRcvEvents(int revents) { _revents = revents; };
    int GetRcvEvents() { return _revents; };

    /**
     *  @brief 工厂管理方法, 获取真实类型
     */
    int GetNtfyType() {    return _type; };
    virtual void Reset() {
        _fd      = -1;
        _events  = 0;
        _revents = 0;
        _type    = 0;
        _thread  = NULL;
    };
        
    /**
     *  @brief 设置与获取所属的微线程句柄接口
     *  @param thread 关联的线程指针
     */
    void SetOwnerThread(MicroThread* thread) {      _thread = thread; };
    MicroThread* GetOwnerThread() {        return _thread; };
    
};

typedef TAILQ_HEAD(__EpFdList, EpollerObj) EpObjList;  ///< 高效的双链管理 
typedef struct epoll_event EpEvent;                 ///< 重定义一下epoll event


/**
 *  @brief EPOLL支持同一FD多个线程侦听, 建立一个引用计数数组, 元素定义
 *  @info  引用计数弊大于利, 没有实际意义, 字段保留, 功能移除掉 20150623
 */
class FdRef
{
private:
    int _wr_ref;             ///< 监听写的引用计数
    int _rd_ref;             ///< 监听读的引用计数
    int _events;             ///< 当前正在侦听的事件列表
    int _revents;            ///< 当前该fd收到的事件信息, 仅在epoll_wait后处理中有效
    EpollerObj* _epobj;      ///< 单独注册调度器对象，一个fd关联一个对象

public:

    /**
     *  @brief 构造与析构函数
     */
    FdRef() {
        _wr_ref  = 0;
        _rd_ref  = 0;
        _events  = 0;
        _revents = 0;
        _epobj   = NULL;
    };
    ~FdRef(){};

    /**
     *  @brief 监听事件获取与设置接口
     */
    void SetListenEvents(int events) {
        _events = events;
    };
    int GetListenEvents() {
        return _events;
    };

    /**
     *  @brief 监听对象获取与设置接口
     */
    void SetNotifyObj(EpollerObj* ntfy) {
        _epobj = ntfy;
    };
    EpollerObj* GetNotifyObj() {
        return _epobj;
    };

    /**
     *  @brief 监听引用计数的更新
     */
    void AttachEvents(int event) {
        if (event & EPOLLIN) {
            _rd_ref++;
        }
        if (event & EPOLLOUT){
            _wr_ref++;
        }
    };
    void DetachEvents(int event) {
        if (event & EPOLLIN) {
            if (_rd_ref > 0) {
                _rd_ref--;
            } else {
                _rd_ref = 0;
            }
        }
        if (event & EPOLLOUT){
            if (_wr_ref > 0) {
                _wr_ref--;
            } else {
                _wr_ref = 0;
            }
        }
    };

    /**
     * @brief 获取引用计数
     */
    int ReadRefCnt() { return _rd_ref; };
    int WriteRefCnt() { return _wr_ref; };
    
};


/**
 *  @brief EPOLL代理, 封装epoll操作与epoll全局数据
 */
class EpollProxy
{
public:
    static const int DEFAULT_MAX_FD_NUM = 100000;   ///< 默认最大监控的fd
    
private:  
    int                 _epfd;                      ///< epoll 主句柄
    int                 _maxfd;                     ///< 最大的文件句柄数    
    EpEvent*            _evtlist;                   ///< epoll返回给用户的事件列表指针
    FdRef*              _eprefs;                    ///< 用户监听的事件本地管理数组
    
public:  

    /**
     *  @brief 构造与析构函数
     */
    EpollProxy();
    virtual ~EpollProxy(){};

    /**
     *  @brief epoll初始化与终止处理, 申请动态内存等
     *  @param max_num 最大可管理的fd数目
     */
    int InitEpoll(int max_num);
    void TermEpoll(void);

    /**
     *  @brief epoll_wait 获取最大等待时间接口
     *  @return 目前需要等待的时间, 单位MS
     */
    virtual int EpollGetTimeout(void) {     return 0;};

    /**
     *  @brief epoll 触发调度接口
     *  @param fdlist 多路并发请求, 所有发送的socket集合
     *  @param fd    单个socket, 触发等待
     *  @param timeout 超时时间设置, 毫秒
     *  @return true 成功, false 失败
     */
    virtual bool EpollSchedule(EpObjList* fdlist, EpollerObj* fd, int timeout) { return false;};
    
    /**
     *  @brief 将一个微线程侦听的所有socket送入epoll管理
     *  @param fdset 微线程侦听的socket集合
     *  @return true 成功, false 失败
     */
    bool EpollAdd(EpObjList& fdset);

    /**
     *  @brief 将一个微线程侦听的所有socket移除epoll管理
     *  @param fdset 微线程侦听的socket集合
     *  @return true 成功, false 失败
     */
    bool EpollDel(EpObjList& fdset);

    /**
     *  @brief epoll_wait 以及分发处理过程
     */
    void EpollDispath(void);

    /**
     *  @brief 单独一个fd注册, 关联侦听事件
     *  @param fd 文件句柄与事件信息
     *  @param obj epoll回调对象
     */
    bool EpollAddObj(EpollerObj* obj);

    /**
     *  @brief 取消一个fd注册, 关联侦听事件
     *  @param fd 文件句柄与事件信息
     *  @param obj epoll回调对象
     */
    bool EpollDelObj(EpollerObj* obj);

    /**
     * @brief 封装epoll ctl的处理与当前监听事件的记录, 内部接口
     * @param fd 操作的文件句柄
     * @param new_events 需要新增的监听事件
     */
    bool EpollCtrlAdd(int fd, int new_events);

    /**
     * @brief 封装epoll ctl的处理与当前监听事件的记录, 内部接口
     * @param fd 操作的文件句柄
     * @param new_events 需要新删除的监听事件
     */
    bool EpollCtrlDel(int fd, int new_events);    
    bool EpollCtrlDelRef(int fd, int new_events, bool use_ref);
    
    /**
     *  @brief 根据fd获取本地引用的结构, 按fd生成策略, 目前简单管理
     *  @param fd 文件描述符
     *  @return 本地文件引用结构, NULL 表示失败
     */
    FdRef* FdRefGet(int fd) {
        return ((fd >= _maxfd) || (fd < 0)) ? (FdRef*)NULL : &_eprefs[fd];        
    };

    
    /**
     * @brief 单独的注册接口, 用于注册或取消注册通知对象
     * @param fd 操作的文件句柄
     * @param obj 待注册或取消注册的对象
     */
    void EpollNtfyReg(int fd, EpollerObj* obj) {
        FdRef* ref = FdRefGet(fd);
        if (ref) {
            ref->SetNotifyObj(obj);
        }
    };

protected: 

    /**
     *  @brief 更新每个socket的最新接收事件信息
     *  @param evtfdnum 收到事件的fd集合数目
     */
    void EpollRcvEventList(int evtfdnum);

};
}//NAMESPCE

#endif


