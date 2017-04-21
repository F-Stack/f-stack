
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
 *  @info 微线程调度注册对象管理实现
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


/**
 * @brief 通知代理进入等待状态, 挂入等待队列中
 * @param proxy 代理的session模型
 */
void ISessionNtfy::InsertWriteWait(SessionProxy* proxy) 
{
    if (!proxy->_flag) {
        TAILQ_INSERT_TAIL(&_write_list, proxy, _write_entry);
        proxy->_flag = 1;
    }    
}

/**
 * @brief 通知代理移除等待状态
 * @param proxy 代理的session模型
 */
void ISessionNtfy::RemoveWriteWait(SessionProxy* proxy) 
{
    if (proxy->_flag) {
        TAILQ_REMOVE(&_write_list, proxy, _write_entry);
        proxy->_flag = 0;
    }    
}

/**
 * @brief 观察者模式, 通知写等待线程
 * @info UDP可以通知每个线程执行写操作, TCP需要排队写
 */
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

/**
 *  @brief 创建socket, 监听可读事件
 *  @return fd的句柄, <0 失败
 */
int UdpSessionNtfy::CreateSocket()
{
    // 1. UDP短连接, 每次新创SOCKET
    int osfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (osfd < 0)
    {
        MTLOG_ERROR("socket create failed, errno %d(%s)", errno, strerror(errno));
        return -1;
    }
    
    // 2. 非阻塞设置
    int flags = 1;
    if (ioctl(osfd, FIONBIO, &flags) < 0)
    {
        MTLOG_ERROR("socket unblock failed, errno %d(%s)", errno, strerror(errno));
        close(osfd);
        osfd = -1;
        return -2;
    }

    // 可选bind执行, 设置本地port后执行
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

    // 3. 更新管理信息, 默认udp session 侦听 epollin
    this->SetOsfd(osfd);
    this->EnableInput();
    MtFrame* frame = MtFrame::Instance();
    frame->KqueueNtfyReg(osfd, this);
    frame->KqueueCtrlAdd(osfd, KQ_EVENT_READ);
    
    return osfd;
}


/**
 *  @brief 关闭socket, 停止监听可读事件
 */
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


/**
 *  @brief 可读事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
 *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
 */
int UdpSessionNtfy::InputNotify()
{
    while (1)
    {
        int ret = 0;
        int have_rcv_len = 0;

        // 1. 获取收包缓冲区, 优先选择未处理完的链接buff
        if (!_msg_buff) {
            _msg_buff = MsgBuffPool::Instance()->GetMsgBuf(this->GetMsgBuffSize());
            if (NULL == _msg_buff) {
                MTLOG_ERROR("Get memory failed, size %d, wait next time", this->GetMsgBuffSize());
                return 0;
            }
            _msg_buff->SetBuffType(BUFF_RECV);
        }
        char* buff = (char*)_msg_buff->GetMsgBuff();

        // 2. 获取socket, 收包处理
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
                return 0;  // 系统错误, UDP 暂不关闭
            }
        }
        else if (ret == 0)
        {
            MTLOG_DEBUG("remote close connection, fd %d", osfd);
            return 0;  // 对端关闭, UDP 暂不关闭
        }
        else
        {
            have_rcv_len = ret;
            _msg_buff->SetHaveRcvLen(have_rcv_len);
            _msg_buff->SetMsgLen(have_rcv_len);
        }

        // 3. 检查消息的完整性, 提取sessionid
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

        // 4. 映射查询thread句柄, 连接handle句柄, 设置读事件来临, 挂接msgbuff
        ISession* session = SessionMgr::Instance()->FindSession(sessionid);
        if (NULL == session) 
        {
            MT_ATTR_API(350403, 1); // session 到达已超时
            MTLOG_DEBUG("session %d, not find, maybe timeout, drop pkg", sessionid);
            MsgBuffPool::Instance()->FreeMsgBuf(_msg_buff);
            _msg_buff = NULL;
            return 0;
        }

        // 5. 挂接recvbuff, 唤醒线程
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

/**
 *  @brief 可写事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
 *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
 */
int UdpSessionNtfy::OutputNotify()
{
    NotifyWriteWait();
    return 0;
}

/**
 *  @brief 异常通知接口, 关闭fd侦听, thread等待处理超时
 *  @return 忽略返回值, 跳过其它事件处理
 */
int UdpSessionNtfy::HangupNotify()
{
    // 1. 清理epoll ctl监听事件
    MtFrame* frame = MtFrame::Instance();
    frame->KqueueCtrlDel(this->GetOsfd(), this->GetEvents());

    MTLOG_ERROR("sesson obj %p, recv error event. fd %d", this, this->GetOsfd());
    
    // 2. 重新打开socket
    CloseSocket();

    // 3. 重加入epoll listen
    CreateSocket();

    return 0;
}

/**
 *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
 *  @param args fd引用对象的指针
 *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
 *  @info  默认是监听可读事件的, 这里只处理可写事件的监听删除
 */
int UdpSessionNtfy::KqueueCtlAdd(void* args)
{
    MtFrame* frame = MtFrame::Instance();
    KqFdRef* fd_ref = (KqFdRef*)args;
    //ASSERT(fd_ref != NULL);

    int osfd = this->GetOsfd();

    // 通知对象需要更新, FD通知对象理论上不会复用, 这里做冲突检查, 异常log记录
    KqueuerObj* old_obj = fd_ref->GetNotifyObj();
    if ((old_obj != NULL) && (old_obj != this))
    {
        MTLOG_ERROR("epfd ref conflict, fd: %d, old: %p, now: %p", osfd, old_obj, this);
        return -1;
    }

    // 调用框架的epoll ctl接口, 屏蔽epoll ctrl细节
    if (!frame->KqueueCtrlAdd(osfd, KQ_EVENT_WRITE))
    {
        MTLOG_ERROR("epfd ref add failed, log");
        return -2;
    }
    this->EnableOutput();
    
    return 0;
}

/**
 *  @brief 调整epoll侦听事件的回调接口, 长连接始终EPOLLIN, 偶尔EPOLLOUT
 *  @param args fd引用对象的指针
 *  @return 0 成功, < 0 失败, 要求事务回滚到操作前状态
 */
int UdpSessionNtfy::KqueueCtlDel(void* args)
{
    MtFrame* frame = MtFrame::Instance();
    KqFdRef* fd_ref = (KqFdRef*)args;
    //ASSERT(fd_ref != NULL);

    int osfd = this->GetOsfd();
    
    // 通知对象需要更新, FD通知对象理论上不会复用, 这里做冲突检查, 异常log记录
    KqueuerObj* old_obj = fd_ref->GetNotifyObj();
    if (old_obj != this)
    {
        MTLOG_ERROR("epfd ref conflict, fd: %d, old: %p, now: %p", osfd, old_obj, this);
        return -1;
    }

    // 调用框架的epoll ctl接口, 屏蔽epoll ctrl细节
    if (!frame->KqueueCtrlDel(osfd, KQ_EVENT_WRITE))
    {
        MTLOG_ERROR("epfd ref del failed, log");
        return -2;
    }
    this->DisableOutput();

    return 0;

}


/**
 *  @brief 可读事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
 *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
 */
int TcpKeepNtfy::InputNotify()
{
    KeepaliveClose();
    return -1;
}
    
/**
 *  @brief 可写事件通知接口, 考虑通知处理可能会破坏环境, 可用返回值区分
 *  @return 0 该fd可继续处理其它事件; !=0 该fd需跳出回调处理
 */
int TcpKeepNtfy::OutputNotify()
{
    KeepaliveClose();
    return -1;
}
    
/**
 *  @brief 异常通知接口
 *  @return 忽略返回值, 跳过其它事件处理
 */
int TcpKeepNtfy::HangupNotify()
{
    KeepaliveClose();
    return -1;
}

    
/**
 *  @brief 触发实际连接关闭操作
 */
void TcpKeepNtfy::KeepaliveClose()
{
    if (_keep_conn) {
        MTLOG_DEBUG("remote close, fd %d, close connection", _fd);
        ConnectionMgr::Instance()->CloseIdleTcpKeep(_keep_conn);
    } else {
        MTLOG_ERROR("_keep_conn ptr null, error");
    }
}
    

/**
 * @brief session全局管理句柄
 * @return 全局句柄指针
 */
NtfyObjMgr* NtfyObjMgr::_instance = NULL;
NtfyObjMgr* NtfyObjMgr::Instance (void)
{
    if (NULL == _instance)
    {
        _instance = new NtfyObjMgr;
    }

    return _instance;
}

/**
 * @brief session管理全局的销毁接口
 */
void NtfyObjMgr::Destroy()
{
    if( _instance != NULL )
    {
        delete _instance;
        _instance = NULL;
    }
}

/**
 * @brief 消息buff的构造函数
 */
NtfyObjMgr::NtfyObjMgr()
{
}

/**
 * @brief 析构函数, 不持有资源, 并不负责清理
 */
NtfyObjMgr::~NtfyObjMgr()
{
}

/**
 * @brief 注册长连接session信息
 * @param session_name 长连接的标识, 每个连接处理一类session封装格式
 * @param session 长连接对象指针, 定义连接属性
 * @return 0 成功, < 0 失败
 */
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

/**
 * @brief 获取注册长连接session信息
 * @param session_name 长连接的标识, 每个连接处理一类session封装格式
 * @return 长连接指针, 失败为NULL
 */
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

/**
 * @brief 获取通用通知对象, 如线程通知对象与session通知代理对象
 * @param type 类型, 线程通知类型，UDP/TCP SESSION通知等
 * @param session_name proxy模型,一并获取session对象
 * @return 通知对象的指针, 失败为NULL
 */
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

    // 获取底层的长连接对象, 关联代理与实际的通知对象
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

/**
 * @brief 释放通知对象指针
 * @param obj 通知对象
 */
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



