
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
 *  @filename kqueue.h
 *  @info     kqueue for micro thread manage
 */

#ifndef _KQUEUE_PROXY___
#define _KQUEUE_PROXY___

#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>

#include "ff_api.h"

#include <set>
#include <vector>
using std::set;
using std::vector;

#define kqueue_assert(statement)
//#define kqueue_assert(statement) assert(statement)

namespace NS_MICRO_THREAD {

#define KQ_EVENT_NONE 0
#define KQ_EVENT_READ 1
#define KQ_EVENT_WRITE 2

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
/*  Kqueue proxy definition and implementation                                */
/******************************************************************************/

class KqueueProxy;
class MicroThread;

class KqueuerObj
{
    protected:
        int _fd;
        int _events;
        int _revents;
        int _type;
        MicroThread* _thread;

    public:

        TAILQ_ENTRY(KqueuerObj) _entry;

        explicit KqueuerObj(int fd = -1) {
            _fd       = fd;
            _events   = 0;
            _revents  = 0;
            _type     = 0;
            _thread   = NULL;
        };
        virtual ~KqueuerObj(){};

        virtual int InputNotify();
        virtual int OutputNotify();
        virtual int HangupNotify();
        virtual int KqueueCtlAdd(void* args);
        virtual int KqueueCtlDel(void* args);

        void EnableInput() {    _events |= KQ_EVENT_READ; };

        void EnableOutput() {     _events |= KQ_EVENT_WRITE; };

        void DisableInput() {   _events &= ~KQ_EVENT_READ; };

        void DisableOutput() {    _events &= ~KQ_EVENT_WRITE; };

        int GetOsfd() { return _fd; };
        void SetOsfd(int fd) {   _fd = fd; };

        int GetEvents() { return _events; };
        void SetRcvEvents(int revents) { _revents = revents; };
        int GetRcvEvents() { return _revents; };

        int GetNtfyType() {    return _type; };
        virtual void Reset() {
            _fd      = -1;
            _events  = 0;
            _revents = 0;
            _type    = 0;
            _thread  = NULL;
        };
            
        void SetOwnerThread(MicroThread* thread) {      _thread = thread; };
        MicroThread* GetOwnerThread() {        return _thread; };
    
};

typedef TAILQ_HEAD(__KqFdList, KqueuerObj) KqObjList;
typedef struct kevent KqEvent;


class KqFdRef
{
private:
    int _wr_ref;
    int _rd_ref;
    int _events;
    int _revents;
    KqueuerObj* _kqobj;

public:

    KqFdRef() {
        _wr_ref  = 0;
        _rd_ref  = 0;
        _events  = 0;
        _revents = 0;
        _kqobj   = NULL;
    };
    ~KqFdRef(){};

    void SetListenEvents(int events) {
        _events = events;
    };
    int GetListenEvents() {
        return _events;
    };

    void SetNotifyObj(KqueuerObj* ntfy) {
        _kqobj = ntfy;
    };
    KqueuerObj* GetNotifyObj() {
        return _kqobj;
    };

    void AttachEvents(int event) {
        if (event & KQ_EVENT_READ) {
            _rd_ref++;
        }
        if (event & KQ_EVENT_WRITE){
            _wr_ref++;
        }
    };
    void DetachEvents(int event) {
        if (event & KQ_EVENT_READ) {
            if (_rd_ref > 0) {
                _rd_ref--;
            } else {
                _rd_ref = 0;
            }
        }
        if (event & KQ_EVENT_WRITE){
            if (_wr_ref > 0) {
                _wr_ref--;
            } else {
                _wr_ref = 0;
            }
        }
    };


    int ReadRefCnt() { return _rd_ref; };
    int WriteRefCnt() { return _wr_ref; };
    
};


class KqueueProxy
{
    public:
        static const int DEFAULT_MAX_FD_NUM = 100000;

    private:
        int                       _kqfd;
        int                       _maxfd;
        KqEvent*                  _evtlist;
        KqFdRef*                  _kqrefs;

    public:
        KqueueProxy();
        virtual ~KqueueProxy(){};

        int InitKqueue(int max_num);
        void TermKqueue(void);

        virtual int KqueueGetTimeout(void) { return 0; };
        virtual bool KqueueSchedule(KqObjList* fdlist, KqueuerObj* fd, int timeout) { return false; };
        
        bool KqueueAdd(KqObjList& fdset);
        bool KqueueDel(KqObjList& fdset);
        void KqueueDispatch(void);
        bool KqueueAddObj(KqueuerObj* obj);
        bool KqueueDelObj(KqueuerObj* obj);
        bool KqueueCtrlAdd(int fd, int new_events);
        bool KqueueCtrlDel(int fd, int new_events);
        bool KqueueCtrlDelRef(int fd, int new_events, bool use_ref);

        KqFdRef* KqFdRefGet(int fd) {
            return ((fd >= _maxfd) || (fd < 0)) ? (KqFdRef*)NULL : &_kqrefs[fd];
        }

        void KqueueNtfyReg(int fd, KqueuerObj* obj) {
            KqFdRef* ref = KqFdRefGet(fd);
            if (ref) {
                ref->SetNotifyObj(obj);
            }
        };

    protected:
        void KqueueRcvEventList(int evtfdnum);
};

}


#endif
