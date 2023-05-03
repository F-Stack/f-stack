
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
 *  @filename kqueue_proxy.cpp
 *  @info     kqueue for micro thread manage
 */

#include "kqueue_proxy.h"
#include "micro_thread.h"
#include "ff_hook.h"

using namespace NS_MICRO_THREAD;

KqueueProxy::KqueueProxy()
{
    _maxfd = KqueueProxy::DEFAULT_MAX_FD_NUM;
    _kqfd = -1;
    _evtlist = NULL;
    _kqrefs = NULL;
}

int KqueueProxy::InitKqueue(int max_num)
{
    int rc = 0;
    if (max_num > _maxfd)
    {
        _maxfd = max_num;
    }

    _kqfd = ff_kqueue();
    if (_kqfd < 0)
    {
        rc = -1;
        goto EXIT_LABEL;
    }

    ff_fcntl(_kqfd, F_SETFD, FD_CLOEXEC);

    _kqrefs = new KqFdRef[_maxfd];
    if (_kqrefs == NULL)
    {
        rc = -2;
        goto EXIT_LABEL;
    }

    _evtlist = (KqEvent*)calloc(_maxfd, sizeof(KqEvent));
    if (_evtlist == NULL)
    {
        rc = -3;
        goto EXIT_LABEL;
    }

    struct rlimit rlim;
    memset(&rlim, 0, sizeof(rlim));
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0)
    {
        if ((int)rlim.rlim_max < _maxfd)
        {
            rlim.rlim_cur = rlim.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rlim);
            rlim.rlim_cur = _maxfd;
            rlim.rlim_max = _maxfd;
            setrlimit(RLIMIT_NOFILE, &rlim);
        } 
    }

EXIT_LABEL:

    if (rc < 0)
    {
        TermKqueue();
    }

    return rc;
}

void KqueueProxy::TermKqueue()
{
    if (_kqfd > 0)
    {
        close(_kqfd);
        _kqfd = -1;
    }
    
    if (_evtlist != NULL)
    {
        free(_evtlist);
        _evtlist = NULL;
    }
    
    if (_kqrefs != NULL)
    {
        delete []_kqrefs;
        _kqrefs = NULL;
    }
}

bool KqueueProxy::KqueueAdd(KqObjList& obj_list)
{
    bool ret = true;
    KqueuerObj *kqobj = NULL;
    KqueuerObj *kqobj_error = NULL;
    TAILQ_FOREACH(kqobj, &obj_list, _entry)
    {
        if (!KqueueAddObj(kqobj))
        {
            MTLOG_ERROR("kqobj add failed, fd: %d", kqobj->GetOsfd());
            kqueue_assert(0);
            kqobj_error = kqobj;
            ret = false;
            goto EXIT_LABEL;
        }
    }

EXIT_LABEL:

    if (!ret)
    {
        TAILQ_FOREACH(kqobj, &obj_list, _entry)
        {
            if (kqobj == kqobj_error)
            {
                break;
            }
            KqueueDelObj(kqobj);
        }
    }

    return ret;
}

bool KqueueProxy::KqueueDel(KqObjList& obj_list)
{
    bool ret = true;
    
    KqueuerObj *kqobj = NULL;
    TAILQ_FOREACH(kqobj, &obj_list, _entry)
    {
        if (!KqueueDelObj(kqobj))  // failed also need continue, be sure ref count ok
        {
            MTLOG_ERROR("epobj del failed, fd: %d", kqobj->GetOsfd());
            kqueue_assert(0);
            ret = false;
        }
    }

    return ret;
}

bool KqueueProxy::KqueueCtrlAdd(int fd, int events)
{
    KqFdRef* item = KqFdRefGet(fd);
    if (item == NULL)
    {
        MT_ATTR_API(320851, 1); // fd error, wtf?
        MTLOG_ERROR("kqfd ref not find, failed, fd: %d", fd);
        kqueue_assert(0);
        return false;
    }

    item->AttachEvents(events);

    int old_events = item->GetListenEvents();
    int new_events = old_events | events;
    if (old_events == new_events)
    {
        return true;
    }
    
    KqEvent ke;
    int ret;
    if (old_events & KQ_EVENT_WRITE) {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        ret = ff_kevent(_kqfd, &ke, 1, NULL, 0, NULL);
        if (ret == -1) {
            // TODO, error check
            item->DetachEvents(events);
            kqueue_assert(0);
            return false;
        }
    }
    if (old_events & KQ_EVENT_READ) {
        EV_SET(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        ret = ff_kevent(_kqfd, &ke, 1, NULL, 0, NULL);
        if (ret == -1) {
            // TODO, error check
            item->DetachEvents(events);
            kqueue_assert(0);
            return false;
        }
    }
    if (events & KQ_EVENT_WRITE) {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        ret = ff_kevent(_kqfd, &ke, 1, NULL, 0, NULL);
        if (ret == -1) {
            // TODO, error check
            item->DetachEvents(events);
            kqueue_assert(0);
            return false;
        }
    }
    if (events & KQ_EVENT_READ) {
        EV_SET(&ke, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        ret = ff_kevent(_kqfd, &ke, 1, NULL, 0, NULL);
        if (ret == -1) {
            // TODO, error check
            item->DetachEvents(events);
            kqueue_assert(0);
            return false;
        }
    }

    item->SetListenEvents(new_events);

    return true;
}


bool KqueueProxy::KqueueCtrlDel(int fd, int events)
{
    return KqueueCtrlDelRef(fd, events, false);
}

bool KqueueProxy::KqueueCtrlDelRef(int fd, int events, bool use_ref)
{
    KqFdRef* item = KqFdRefGet(fd);
    if (item == NULL)
    {
        MT_ATTR_API(320851, 1); // fd error
        MTLOG_ERROR("kqfd ref not find, failed, fd: %d", fd);
        kqueue_assert(0);
        return false;

    }

    item->DetachEvents(events);
    int old_events = item->GetListenEvents();
    int new_events = old_events &~ events;

    if (use_ref) {
        new_events = old_events;
        if (item->ReadRefCnt() == 0) {
            new_events = new_events & ~KQ_EVENT_READ;
        }
        if (item->WriteRefCnt() == 0) {
            new_events = new_events & ~KQ_EVENT_WRITE;
        }
    }

    if (old_events == new_events)
    {
        return true;
    }
    KqEvent ke;
    int ret;
    if (old_events & KQ_EVENT_WRITE) {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        ret = ff_kevent(_kqfd, &ke, 1, NULL, 0, NULL);
        if (ret == -1) {
            kqueue_assert(0);
            return false;
        }
    }
    if (old_events & KQ_EVENT_READ) {
        EV_SET(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        ret = ff_kevent(_kqfd, &ke, 1, NULL, 0, NULL);
        if (ret == -1) {
            kqueue_assert(0);
            return false;
        }
    }

    if (new_events & KQ_EVENT_WRITE) {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        ret = ff_kevent(_kqfd, &ke, 1, NULL, 0, NULL);
        if (ret == -1) {
            kqueue_assert(0);
            return false;
        }
    }
    if (new_events & KQ_EVENT_READ) {
        EV_SET(&ke, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        ret = ff_kevent(_kqfd, &ke, 1, NULL, 0, NULL);
        if (ret == -1) {
            kqueue_assert(0);
            return false;
        }
    }

    item->SetListenEvents(new_events);

    return true;
}

bool KqueueProxy::KqueueAddObj(KqueuerObj* obj)
{
    if (obj == NULL)
    {
        MTLOG_ERROR("kqobj input invalid, %p", obj);
        return false;
    }

    KqFdRef* item = KqFdRefGet(obj->GetOsfd());
    if (item == NULL)
    {
        MT_ATTR_API(320851, 1); // fd error
        MTLOG_ERROR("kqfd ref not find, failed, fd: %d", obj->GetOsfd());
        kqueue_assert(0);
        return false;
    }

    int ret = obj->KqueueCtlAdd(item);
    if (ret < 0) {
        MTLOG_ERROR("kqueue ctrl callback failed, fd: %d, obj: %p", obj->GetOsfd(), obj);
        kqueue_assert(0);
        return false;
    }

    return true;
}

bool KqueueProxy::KqueueDelObj(KqueuerObj* obj)
{
    if (obj == NULL)
    {
        MTLOG_ERROR("kqobj input invalid, %p", obj);
        return false;
    }
    KqFdRef* item = KqFdRefGet(obj->GetOsfd());
    if (item == NULL)
    {
        MT_ATTR_API(320851, 1); // fd error
        MTLOG_ERROR("kqfd ref not find, failed, fd: %d", obj->GetOsfd());
        kqueue_assert(0);
        return false;
    }

    int ret = obj->KqueueCtlDel(item);
    if (ret < 0) {
        MTLOG_ERROR("kqueue ctrl callback failed, fd: %d, obj: %p", obj->GetOsfd(), obj);
        kqueue_assert(0);
        return false;
    }

    return true;
}

void KqueueProxy::KqueueRcvEventList(int evtfdnum)
{
    int ret = 0;
    int osfd = 0;
    int revents = 0;
    int tmp_evts = 0;
    KqFdRef* item = NULL;
    KqueuerObj* obj = NULL;

    for (int i = 0; i < evtfdnum; i++)
    {
        osfd = _evtlist[i].ident;

        item = KqFdRefGet(osfd);
        if (item == NULL)
        {
            MT_ATTR_API(320851, 1); // fd error
            MTLOG_ERROR("kqfd ref not find, failed, fd: %d", osfd);
            kqueue_assert(0);
            continue;
        }
        tmp_evts = _evtlist[i].filter;
        if (tmp_evts == EVFILT_READ) {
            revents |= KQ_EVENT_READ;
        }
        if (tmp_evts == EVFILT_WRITE) {
            revents |= KQ_EVENT_WRITE;
        }
        obj = item->GetNotifyObj();
        if (obj == NULL)
        {
            MTLOG_ERROR("fd notify obj null, failed, fd: %d", osfd);
            KqueueCtrlDel(osfd, (revents & (KQ_EVENT_READ | KQ_EVENT_WRITE)));
            continue;
        }
        obj->SetRcvEvents(revents);

        if (tmp_evts == EV_ERROR)
        {
            obj->HangupNotify();
            continue;
        }

        if (revents & KQ_EVENT_READ)
        {
            ret = obj->InputNotify();
            if (ret != 0)
            {
                continue;
            }
        }

        if (revents & KQ_EVENT_WRITE)
        {
            ret = obj->OutputNotify();
            if (ret != 0)
            {
                continue;
            }
        }
    }
}

void KqueueProxy::KqueueDispatch()
{
    int nfd;
    int wait_time = KqueueGetTimeout();
    if (wait_time) {
        struct timespec ts;
        ts.tv_sec = wait_time / 1000;
        ts.tv_nsec = 0;
        nfd = ff_kevent(_kqfd, NULL, 0, _evtlist, _maxfd, &ts);
    } else {
        nfd = ff_kevent(_kqfd, NULL, 0, _evtlist, _maxfd, NULL);
    }
    if (nfd <= 0)
    {
        return;
    }

    KqueueRcvEventList(nfd);
}

int KqueuerObj::InputNotify()
{
    MicroThread* thread = this->GetOwnerThread();
    if (thread == NULL)
    {
        kqueue_assert(0);
        MTLOG_ERROR("kqueue fd obj, no thread ptr, wrong");
        return -1;
    }

    if (thread->HasFlag(MicroThread::IO_LIST))
    {
        MtFrame* frame = MtFrame::Instance();
        frame->RemoveIoWait(thread);
        frame->InsertRunable(thread);
    }

    return 0;
}

int KqueuerObj::OutputNotify()
{
    MicroThread* thread = this->GetOwnerThread();
    if (NULL == thread) 
    {
        kqueue_assert(0);
        MTLOG_ERROR("kqueue fd obj, no thread ptr, wrong");
        return -1;
    }

    // Multiple events arrive at the same time
    if (thread->HasFlag(MicroThread::IO_LIST))
    {
        MtFrame* frame = MtFrame::Instance();
        frame->RemoveIoWait(thread);
        frame->InsertRunable(thread);
    }

    return 0;    
}

int KqueuerObj::HangupNotify()
{
    MtFrame* frame = MtFrame::Instance();
    frame->KqueueCtrlDel(this->GetOsfd(), this->GetEvents());
    return 0;
}

int KqueuerObj::KqueueCtlAdd(void* args)
{
    MtFrame* frame = MtFrame::Instance();
    KqFdRef* fd_ref = (KqFdRef*)args;
    kqueue_assert(fd_ref != NULL);

    int osfd = this->GetOsfd();
    int new_events = this->GetEvents();

    // Notify object needs updating
    KqueuerObj* old_obj = fd_ref->GetNotifyObj();
    if ((old_obj != NULL) && (old_obj != this))
    {
        MTLOG_ERROR("kqfd ref conflict, fd: %d, old: %p, now: %p", osfd, old_obj, this);
        return -1;
    }
    fd_ref->SetNotifyObj(this);

    if (!frame->KqueueCtrlAdd(osfd, new_events))
    {
        MTLOG_ERROR("kqfd ref add failed, log");
        fd_ref->SetNotifyObj(old_obj);
        return -2;
    }

    return 0;
}

int KqueuerObj::KqueueCtlDel(void* args)
{
    MtFrame* frame = MtFrame::Instance();
    KqFdRef* fd_ref = (KqFdRef*)args;
    kqueue_assert(fd_ref != NULL);

    int osfd = this->GetOsfd();
    int events = this->GetEvents();
    
    KqueuerObj* old_obj = fd_ref->GetNotifyObj();
    if (old_obj != this)
    {
        MTLOG_ERROR("kqfd ref conflict, fd: %d, old: %p, now: %p", osfd, old_obj, this);
        return -1;
    }
    fd_ref->SetNotifyObj(NULL);

    if (!frame->KqueueCtrlDelRef(osfd, events, false))
    {
        MTLOG_ERROR("kqfd ref del failed, log");
        fd_ref->SetNotifyObj(old_obj);
        return -2;
    }

    return 0;
    
}

