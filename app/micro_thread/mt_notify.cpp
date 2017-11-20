
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
 *  @file mt_notify.cpp
 *  @time 20130924
 **/
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "micro_thread.h"
#include "mt_session.h"
#include "mt_msg.h"
#include "mt_notify.h"
#include "mt_connection.h"
#include "mt_sys_hook.h"
#include "ff_hook.h"

using namespace std;
using namespace NS_MICRO_THREAD;

void ISessionNtfy::InsertWriteWait(SessionProxy* proxy) 
{
    if (!proxy->_flag) {
        TAILQ_INSERT_TAIL(&_write_list, proxy, _write_entry);
        proxy->_flag = 1;
    }    
}

void ISessionNtfy::RemoveWriteWait(SessionProxy* proxy) 
{
    if (proxy->_flag) {
        TAILQ_REMOVE(&_write_list, proxy, _write_entry);
        proxy->_flag = 0;
    }    
}

void UdpSessionNtfy::NotifyWriteWait()
{
    MtFrame* frame = MtFrame::Instance();
    SessionProxy* proxy = NULL;
    MicroThread* thread = NULL;
    TAILQ_FOREACH(proxy, &_write_list, _write_entry)
    {
        proxy->SetRcvEvents(KQ_EVENT_WRITE);
        
        thread = proxy->GetOwnerThread();
        if (thread && thread->HasFlag(MicroThread::IO_LIST))
        {
            frame->RemoveIoWait(thread);
            frame->InsertRunable(thread);
        }
    }
}

int UdpSessionNtfy::CreateSocket()
{
    int osfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (osfd < 0)
    {
        MTLOG_ERROR("socket create failed, errno %d(%s)", errno, strerror(errno));
        return -1;
    }

    int flags = 1;
    if (ioctl(osfd, FIONBIO, &flags) < 0)
    {
        MTLOG_ERROR("socket unblock failed, errno %d(%s)", errno, strerror(errno));
        close(osfd);
        osfd = -1;
        return -2;
    }

    if (_local_addr.sin_port != 0)
    {
        int ret = bind(osfd, (struct sockaddr *)&_local_addr, sizeof(_local_addr));
        if (ret < 0)
        {
            MTLOG_ERROR("socket bind(%s:%d) failed, errno %d(%s)",  inet_ntoa(_local_addr.sin_addr), 
                    ntohs(_local_addr.sin_port), errno, strerror(errno));
            close(osfd);
            osfd = -1;
            return -3;
        }
    }

    this->SetOsfd(osfd);
    this->EnableInput();
    MtFrame* frame = MtFrame::Instance();
    frame->KqueueNtfyReg(osfd, this);
    frame->KqueueCtrlAdd(osfd, KQ_EVENT_READ);
    
    return osfd;
}

void UdpSessionNtfy::CloseSocket()
{
    int osfd = this->GetOsfd();
    if (osfd > 0)
    {
        MtFrame* frame = MtFrame::Instance();
        frame->KqueueCtrlDel(osfd, KQ_EVENT_READ);
        frame->KqueueNtfyReg(osfd, NULL);
        this->DisableInput();
        this->SetOsfd(-1);
        close(osfd);
    }
}

int UdpSessionNtfy::InputNotify()
{
    while (1)
    {
        int ret = 0;
        int have_rcv_len = 0;

        if (!_msg_buff) {
            _msg_buff = MsgBuffPool::Instance()->GetMsgBuf(this->GetMsgBuffSize());
            if (NULL == _msg_buff) {
                MTLOG_ERROR("Get memory failed, size %d, wait next time", this->GetMsgBuffSize());
                return 0;
            }
            _msg_buff->SetBuffType(BUFF_RECV);
        }
        char* buff = (char*)_msg_buff->GetMsgBuff();

        int osfd = this->GetOsfd();
        struct sockaddr_in  from;
        socklen_t fromlen = sizeof(from); 
        mt_hook_syscall(recvfrom);
        ret = ff_hook_recvfrom(osfd, buff, _msg_buff->GetMaxLen(),
                       0, (struct sockaddr*)&from, &fromlen);
        if (ret < 0)
        {
            if ((errno == EINTR) || (errno == EAGAIN) || (errno == EINPROGRESS))
            {
                return 0;
            }
            else
            {
                MTLOG_ERROR("recv error, fd %d", osfd);
                return 0;
            }
        }
        else if (ret == 0)
        {
            MTLOG_DEBUG("remote close connection, fd %d", osfd);
            return 0;
        }
        else
        {
            have_rcv_len = ret;
            _msg_buff->SetHaveRcvLen(have_rcv_len);
            _msg_buff->SetMsgLen(have_rcv_len);
        }

        int sessionid = 0;
        ret = this->GetSessionId(buff, have_rcv_len, sessionid);
        if (ret <= 0)
        {
            MTLOG_ERROR("recv get session failed, len %d, fd %d, drop it", 
                       have_rcv_len, osfd);
            MsgBuffPool::Instance()->FreeMsgBuf(_msg_buff);
            _msg_buff = NULL;
            return 0;
        }

        ISession* session = SessionMgr::Instance()->FindSession(sessionid);
        if (NULL == session) 
        {
            MT_ATTR_API(350403, 1);
            MTLOG_DEBUG("session %d, not find, maybe timeout, drop pkg", sessionid);
            MsgBuffPool::Instance()->FreeMsgBuf(_msg_buff);
            _msg_buff = NULL;
            return 0;
        }

        IMtConnection* conn = session->GetSessionConn();
        MicroThread* thread = session->GetOwnerThread();
        if (!thread || !conn || !conn->GetNtfyObj()) 
        {
            MTLOG_ERROR("sesson obj %p, no thread ptr %p, no conn %p wrong",
                    session, thread, conn);
            MsgBuffPool::Instance()->FreeMsgBuf(_msg_buff);
            _msg_buff = NULL;
            return 0;
        }
        MtMsgBuf* msg = conn->GetMtMsgBuff();
        if (msg) {
            MsgBuffPool::Instance()->FreeMsgBuf(msg);
        }
        conn->SetMtMsgBuff(_msg_buff);
        _msg_buff = NULL;

        conn->GetNtfyObj()->SetRcvEvents(KQ_EVENT_READ);
        if (thread->HasFlag(MicroThread::IO_LIST))
        {
            MtFrame* frame = MtFrame::Instance();
            frame->RemoveIoWait(thread);
            frame->InsertRunable(thread);
        }
    }

    return 0;
}

int UdpSessionNtfy::OutputNotify()
{
    NotifyWriteWait();
    return 0;
}

int UdpSessionNtfy::HangupNotify()
{
    MtFrame* frame = MtFrame::Instance();
    frame->KqueueCtrlDel(this->GetOsfd(), this->GetEvents());

    MTLOG_ERROR("sesson obj %p, recv error event. fd %d", this, this->GetOsfd());

    CloseSocket();

    CreateSocket();

    return 0;
}

int UdpSessionNtfy::KqueueCtlAdd(void* args)
{
    MtFrame* frame = MtFrame::Instance();
    KqFdRef* fd_ref = (KqFdRef*)args;
    //ASSERT(fd_ref != NULL);

    int osfd = this->GetOsfd();

    KqueuerObj* old_obj = fd_ref->GetNotifyObj();
    if ((old_obj != NULL) && (old_obj != this))
    {
        MTLOG_ERROR("epfd ref conflict, fd: %d, old: %p, now: %p", osfd, old_obj, this);
        return -1;
    }

    if (!frame->KqueueCtrlAdd(osfd, KQ_EVENT_WRITE))
    {
        MTLOG_ERROR("epfd ref add failed, log");
        return -2;
    }
    this->EnableOutput();
    
    return 0;
}

int UdpSessionNtfy::KqueueCtlDel(void* args)
{
    MtFrame* frame = MtFrame::Instance();
    KqFdRef* fd_ref = (KqFdRef*)args;
    //ASSERT(fd_ref != NULL);

    int osfd = this->GetOsfd();

    KqueuerObj* old_obj = fd_ref->GetNotifyObj();
    if (old_obj != this)
    {
        MTLOG_ERROR("epfd ref conflict, fd: %d, old: %p, now: %p", osfd, old_obj, this);
        return -1;
    }

    if (!frame->KqueueCtrlDel(osfd, KQ_EVENT_WRITE))
    {
        MTLOG_ERROR("epfd ref del failed, log");
        return -2;
    }
    this->DisableOutput();

    return 0;

}

int TcpKeepNtfy::InputNotify()
{
    KeepaliveClose();
    return -1;
}

int TcpKeepNtfy::OutputNotify()
{
    KeepaliveClose();
    return -1;
}

int TcpKeepNtfy::HangupNotify()
{
    KeepaliveClose();
    return -1;
}

void TcpKeepNtfy::KeepaliveClose()
{
    if (_keep_conn) {
        MTLOG_DEBUG("remote close, fd %d, close connection", _fd);
        ConnectionMgr::Instance()->CloseIdleTcpKeep(_keep_conn);
    } else {
        MTLOG_ERROR("_keep_conn ptr null, error");
    }
}

NtfyObjMgr* NtfyObjMgr::_instance = NULL;
NtfyObjMgr* NtfyObjMgr::Instance (void)
{
    if (NULL == _instance)
    {
        _instance = new NtfyObjMgr;
    }

    return _instance;
}

void NtfyObjMgr::Destroy()
{
    if( _instance != NULL )
    {
        delete _instance;
        _instance = NULL;
    }
}

NtfyObjMgr::NtfyObjMgr()
{
}

NtfyObjMgr::~NtfyObjMgr()
{
}

int NtfyObjMgr::RegisterSession(int session_name, ISessionNtfy* session)
{
    if (session_name <= 0 || NULL == session) {
        MTLOG_ERROR("session %d, register %p failed", session_name, session);
        return -1;
    }

    SessionMap::iterator it = _session_map.find(session_name);
    if (it != _session_map.end())
    {
        MTLOG_ERROR("session %d, register %p already", session_name, session);
        return -2;
    }

    _session_map.insert(SessionMap::value_type(session_name, session));

    return 0;
}

ISessionNtfy* NtfyObjMgr::GetNameSession(int session_name)
{
    SessionMap::iterator it = _session_map.find(session_name);
    if (it != _session_map.end())
    {
        return it->second;
    } 
    else
    {
        return NULL;
    }
}

KqueuerObj* NtfyObjMgr::GetNtfyObj(int type, int session_name)
{
    KqueuerObj* obj = NULL;
    SessionProxy* proxy = NULL;    

    switch (type)
    {
        case NTFY_OBJ_THREAD:
            obj = _fd_ntfy_pool.AllocPtr();
            break;

        case NTFY_OBJ_SESSION:
            proxy = _udp_proxy_pool.AllocPtr();
            obj = proxy;
            break;

        case NTFY_OBJ_KEEPALIVE:    // no need get this now
            break;

        default:
            break;
    }

    if (proxy) {
        ISessionNtfy* ntfy = this->GetNameSession(session_name);
        if (!ntfy) {
            MTLOG_ERROR("ntfy get session name(%d) failed", session_name);
            this->FreeNtfyObj(proxy);
            obj = NULL;
        } else {
            proxy->SetRealNtfyObj(ntfy);
        }
    }    

    return obj;

}

void NtfyObjMgr::FreeNtfyObj(KqueuerObj* obj)
{
    SessionProxy* proxy = NULL;    
    if (!obj) {
        return;
    }

    int type = obj->GetNtfyType();
    obj->Reset();
    
    switch (type)
    {
        case NTFY_OBJ_THREAD:
            return _fd_ntfy_pool.FreePtr(obj);
            break;

        case NTFY_OBJ_SESSION:
            proxy = dynamic_cast<SessionProxy*>(obj);
            return _udp_proxy_pool.FreePtr(proxy);
            break;

        case NTFY_OBJ_KEEPALIVE:
            break;

        default:
            break;
    }

    delete obj;
    return;
}
