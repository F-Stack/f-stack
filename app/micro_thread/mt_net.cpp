
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
 *  @file mt_mbuf_pool.cpp
 *  @time 20130924
 **/

#include <errno.h>
#include <netinet/tcp.h>
#include "micro_thread.h"
#include "mt_sys_hook.h"
#include "ff_hook.h"
#include "mt_net.h"


using namespace std;
using namespace NS_MICRO_THREAD;

CNetHelper::CNetHelper()
{
    handler = (void*)CNetMgr::Instance()->AllocNetItem();
}

CNetHelper::~CNetHelper()
{
    CNetHandler* net_handler = (CNetHandler*)handler;
    if (handler != NULL) 
    {
        net_handler->Reset();
        CNetMgr::Instance()->FreeNetItem(net_handler);
        handler = NULL;
    }
}

int32_t CNetHelper::SendRecv(void* data, uint32_t len, uint32_t timeout)
{
    if (handler != NULL) {
        CNetHandler* net_handler = (CNetHandler*)handler;
        return net_handler->SendRecv(data, len, timeout);
    } else {
        return RC_INVALID_HANDLER;
    }
}

void* CNetHelper::GetRspBuff()
{
    if (handler != NULL) {
        CNetHandler* net_handler = (CNetHandler*)handler;
        return net_handler->GetRspBuff();
    } else {
        return NULL;
    }
}

uint32_t CNetHelper::GetRspLen()
{
    if (handler != NULL) {
        CNetHandler* net_handler = (CNetHandler*)handler;
        return net_handler->GetRspLen();
    } else {
        return 0;
    }
}

char* CNetHelper::GetErrMsg(int32_t result)
{
    static const char* errmsg = "unknown error type";

    switch (result)
    {
        case RC_SUCCESS:
            errmsg = "success";
            break;

        case RC_ERR_SOCKET:
            errmsg = "create socket failed";
            break;
        
        case RC_SEND_FAIL:
            errmsg = "send pakeage timeout or failed";
            break;
            
        case RC_RECV_FAIL:
            errmsg = "recv response timeout or failed";
            break;
            
        case RC_CONNECT_FAIL:
            errmsg = "connect timeout or failed";
            break;

        case RC_CHECK_PKG_FAIL:
            errmsg = "user package check failed";
            break;

        case RC_NO_MORE_BUFF:
            errmsg = "user response buffer too small";
            break;

        case RC_REMOTE_CLOSED:
            errmsg = "remote close connection";
            break;
    
        case RC_INVALID_PARAM:
            errmsg = "params invalid";
            break;

        case RC_INVALID_HANDLER:
            errmsg = "net handler invalid";
            break;

        case RC_MEM_ERROR:
            errmsg = "no more memory, alloc failed";
            break;
            
        case RC_CONFLICT_SID:
            errmsg = "session id with the dest address conflict";
            break;

        case RC_KQUEUE_ERROR:
            errmsg = "epoll system error";
            break;
            
        default:
            break;
    }

    return (char*)errmsg;
}

void CNetHelper::SetProtoType(MT_PROTO_TYPE type)
{
    if (handler != NULL) {
        CNetHandler* net_handler = (CNetHandler*)handler;
        return net_handler->SetProtoType(type);
    } 
}

void CNetHelper::SetDestAddress(struct sockaddr_in* dst)
{
    if (handler != NULL) {
        CNetHandler* net_handler = (CNetHandler*)handler;
        return net_handler->SetDestAddress(dst);
    } 
}

void CNetHelper::SetSessionId(uint64_t sid)
{
    if (handler != NULL) {
        CNetHandler* net_handler = (CNetHandler*)handler;
        return net_handler->SetSessionId(sid);
    }
}

void CNetHelper::SetSessionCallback(CHECK_SESSION_CALLBACK function)
{
    if (handler != NULL) {
        CNetHandler* net_handler = (CNetHandler*)handler;
        return net_handler->SetSessionCallback(function);
    }
}

void CNetHandler::Reset()
{
    this->Unlink();
    this->UnRegistSession();

    if (_rsp_buff != NULL) {
        delete_sk_buffer(_rsp_buff);
        _rsp_buff               = NULL;
    }

    _thread                     = NULL;    
    _proto_type                 = NET_PROTO_TCP;
    _conn_type                  = TYPE_CONN_SESSION;
    _dest_ipv4.sin_addr.s_addr  = 0;
    _dest_ipv4.sin_port         = 0;
    _session_id                 = 0;
    _callback                   = NULL;
    _err_no                     = 0;
    _state_flags                = 0;
    _conn_ptr                   = NULL;
    _send_pos                   = 0;
    _req_len                    = 0;
    _req_data                   = NULL;
  
}

CNetHandler::CNetHandler()
{
    _state_flags = 0;
    _rsp_buff = NULL;
    
    this->Reset();
}

CNetHandler::~CNetHandler()
{
    this->Reset();
}

int32_t CNetHandler::CheckParams()
{
    if ((NULL == _req_data) || (_req_len == 0))
    {
        MTLOG_ERROR("param invalid, data[%p], len[%u]", _req_data, _req_len);
        return RC_INVALID_PARAM;
    }

    if ((_dest_ipv4.sin_addr.s_addr == 0) || (_dest_ipv4.sin_port == 0))
    {
        MTLOG_ERROR("param invalid, ip[%u], port[%u]", _dest_ipv4.sin_addr.s_addr,
             _dest_ipv4.sin_port);
        return RC_INVALID_PARAM;
    }

    if (_conn_type == TYPE_CONN_SESSION)
    {
        if ((_callback == NULL) || (_session_id == 0))
        {
            MTLOG_ERROR("param invalid, callback[%p], session_id[%llu]", _callback, _session_id);
            return RC_INVALID_PARAM;
        }

        if (!this->RegistSession())
        {
            MTLOG_ERROR("param invalid, session_id[%llu] regist failed", _session_id);
            return RC_CONFLICT_SID;
        }
    }

    return 0;
}

int32_t CNetHandler::GetConnLink()
{
    CDestLinks key;
    key.SetKeyInfo(_dest_ipv4.sin_addr.s_addr, _dest_ipv4.sin_port, _proto_type, _conn_type);
    
    CDestLinks* dest_link = CNetMgr::Instance()->FindCreateDest(&key);
    if (NULL == dest_link)
    {
        MTLOG_ERROR("get dest link handle failed");
        return RC_MEM_ERROR;
    }
    
    CSockLink* sock_link = dest_link->GetSockLink();
    if (NULL == sock_link)
    {
        MTLOG_ERROR("get sock link handle failed");
        return RC_MEM_ERROR;
    }
    
    this->Link(sock_link);

    return 0;
}

int32_t CNetHandler::WaitConnect(uint64_t timeout)
{
    CSockLink* conn = (CSockLink*)this->_conn_ptr;
    if (NULL == conn)
    {
        MTLOG_ERROR("get sock link handle failed");
        return RC_MEM_ERROR;
    }
    
    int32_t fd = conn->CreateSock();
    if (fd < 0)
    {
        MTLOG_ERROR("create sock failed, ret %d[%m]", fd);
        return RC_ERR_SOCKET;
    }

    if (conn->Connect())
    {
        MTLOG_DEBUG("sock conncet ok");
        return RC_SUCCESS;
    }

    this->SwitchToConn();

    MtFrame* mtframe = MtFrame::Instance();
    mtframe->WaitNotify(timeout);

    this->SwitchToIdle();

    if (_err_no != 0)
    {
        MTLOG_ERROR("connect get out errno %d", _err_no);
        return _err_no;
    }

    if (conn->Connected())
    {
        MTLOG_DEBUG("connect ok");
        return 0;
    }
    else
    {
        MTLOG_TRACE("connect not ok, maybe timeout");
        return RC_CONNECT_FAIL;
    }
}

int32_t CNetHandler::WaitSend(uint64_t timeout)
{
    CSockLink* conn = (CSockLink*)this->_conn_ptr;
    if (NULL == conn)
    {
        MTLOG_ERROR("get sock link handle failed");
        return RC_MEM_ERROR;
    }
    
    int32_t ret = conn->SendData(_req_data, _req_len);
    if (ret < 0)
    {
        MTLOG_ERROR("sock send failed, ret %d[%m]", ret);
        return RC_SEND_FAIL;
    }
    this->SkipSendPos(ret);
    
    if (_req_len == 0)
    {
        MTLOG_DEBUG("sock send ok");
        return RC_SUCCESS;
    }

    this->SwitchToSend();

    MtFrame* mtframe = MtFrame::Instance();
    mtframe->WaitNotify(timeout);

    this->SwitchToIdle();

    if (_err_no != 0)
    {
        MTLOG_ERROR("send get out errno %d", _err_no);
        return _err_no;
    }

    if (_req_len == 0)
    {
        MTLOG_DEBUG("send req ok, len %u", _send_pos);
        return 0;
    }
    else
    {
        MTLOG_TRACE("send req not ok, left len %u", _req_len);
        return RC_SEND_FAIL;
    }
}

int32_t CNetHandler::WaitRecv(uint64_t timeout)
{
    CSockLink* conn = (CSockLink*)this->_conn_ptr;
    if (NULL == conn)
    {
        MTLOG_ERROR("get sock link handle failed");
        return RC_MEM_ERROR;
    }

    if (_conn_type == TYPE_CONN_SENDONLY)
    {
        MTLOG_DEBUG("only send, without recv");
        return 0;
    }

    this->SwitchToRecv();

    MtFrame* mtframe = MtFrame::Instance();
    mtframe->WaitNotify(timeout);

    this->SwitchToIdle();

    if ((_rsp_buff != NULL) && (_rsp_buff->data_len > 0))
    {
        MTLOG_DEBUG("recv get rsp, len %d", _rsp_buff->data_len);
        return 0;
    }
    else
    {
        MTLOG_TRACE("recv get out errno %d", _err_no);
        return RC_RECV_FAIL;
    }
}

int32_t CNetHandler::SendRecv(void* data, uint32_t len, uint32_t timeout)
{
    utime64_t start_ms = MtFrame::Instance()->GetLastClock();
    utime64_t cost_time = 0;
    uint64_t time_left = timeout;
    this->_req_data = data;
    this->_req_len  = len;

    int32_t ret = this->CheckParams();
    if (ret < 0)
    {
        MTLOG_ERROR("check params failed, ret[%d]", ret);
        goto EXIT_LABEL;
    }

    ret = this->GetConnLink();
    if (ret < 0)
    {
        MTLOG_ERROR("get sock conn failed, ret: %d", ret);
        goto EXIT_LABEL;
    }

    ret = this->WaitConnect(time_left);
    if (ret < 0)
    {
        MTLOG_ERROR("sock connect failed, ret: %d", ret);
        goto EXIT_LABEL;
    }

    cost_time = MtFrame::Instance()->GetLastClock() - start_ms;
    time_left = (timeout > (uint32_t)cost_time) ? (timeout - (uint32_t)cost_time) : 0;
    ret = this->WaitSend(time_left);
    if (ret < 0)
    {
        MTLOG_ERROR("sock send failed, ret: %d", ret);
        goto EXIT_LABEL;
    }

    cost_time = MtFrame::Instance()->GetLastClock() - start_ms;
    time_left = (timeout > (uint32_t)cost_time) ? (timeout - (uint32_t)cost_time) : 0;
    ret = this->WaitRecv(time_left);
    if (ret < 0)
    {
        MTLOG_ERROR("sock recv failed, ret: %d", ret);
        goto EXIT_LABEL;
    }

    ret = 0;

EXIT_LABEL:

    this->Unlink();

    this->UnRegistSession();

    return ret;
}

uint32_t CNetHandler::SkipSendPos(uint32_t len)
{
    uint32_t skip_len = (len >= _req_len) ? _req_len : len;
    _req_len -= skip_len;
    _send_pos += skip_len;
    _req_data = (char*)_req_data + skip_len;

    return skip_len;
}

void CNetHandler::Link(CSockLink* conn)
{
    this->_conn_ptr = conn;
    this->SwitchToIdle();
}

void CNetHandler::Unlink()
{
    if (this->_state_flags != 0)
    {
        this->DetachConn();
    }
    this->_conn_ptr = NULL;
}

void CNetHandler::SwitchToConn()
{
    CSockLink* conn = (CSockLink*)this->_conn_ptr;
    if (NULL == conn)
    {
        MTLOG_ERROR("net handler invalid");
        return; 
    }

    this->DetachConn();

    this->_state_flags |= STATE_IN_CONNECT;
    conn->AppendToList(CSockLink::LINK_CONN_LIST, this);
}

void CNetHandler::SwitchToSend()
{
    CSockLink* conn = (CSockLink*)this->_conn_ptr;
    if (NULL == conn)
    {
        MTLOG_ERROR("net handler invalid");
        return; 
    }

    this->DetachConn();

    this->_state_flags |= STATE_IN_SEND;
    conn->AppendToList(CSockLink::LINK_SEND_LIST, this);
}

void CNetHandler::SwitchToRecv()
{
    CSockLink* conn = (CSockLink*)this->_conn_ptr;
    if (NULL == conn)
    {
        MTLOG_ERROR("net handler invalid");
        return; 
    }

    this->DetachConn();

    this->_state_flags |= STATE_IN_RECV;
    conn->AppendToList(CSockLink::LINK_RECV_LIST, this);
}

void CNetHandler::SwitchToIdle()
{
    CSockLink* conn = (CSockLink*)this->_conn_ptr;
    if (NULL == conn)
    {
        MTLOG_ERROR("net handler invalid");
        return; 
    }

    this->DetachConn();

    this->_state_flags |= STATE_IN_IDLE;
    conn->AppendToList(CSockLink::LINK_IDLE_LIST, this);
}

void CNetHandler::DetachConn()
{
    CSockLink* conn = (CSockLink*)this->_conn_ptr;
    if (NULL == conn)
    {
        MTLOG_DEBUG("net handler not set");
        return; 
    }

    if (_state_flags == 0)
    {
        return;
    }

    if (_state_flags & STATE_IN_CONNECT)
    {
        conn->RemoveFromList(CSockLink::LINK_CONN_LIST, this);
        _state_flags &= ~STATE_IN_CONNECT;
    }
    
    if (_state_flags & STATE_IN_SEND)
    {
        conn->RemoveFromList(CSockLink::LINK_SEND_LIST, this);
        _state_flags &= ~STATE_IN_SEND;
    }

    if (_state_flags & STATE_IN_RECV)
    {
        conn->RemoveFromList(CSockLink::LINK_RECV_LIST, this);
        _state_flags &= ~STATE_IN_RECV;
    }

    if (_state_flags & STATE_IN_IDLE)
    {
        conn->RemoveFromList(CSockLink::LINK_IDLE_LIST, this);
        _state_flags &= ~STATE_IN_IDLE;
    }
}

uint32_t CNetHandler::HashValue()
{
    uint32_t ip = _dest_ipv4.sin_addr.s_addr;
    ip ^= (_dest_ipv4.sin_port << 16) | (_proto_type << 8) | (_conn_type << 8);
    
    uint32_t hash = (_session_id >> 32) & 0xffffffff;
    hash ^= _session_id  & 0xffffffff;
    hash ^= ip;

    return hash;
}

int32_t CNetHandler::HashCmp(HashKey* rhs) 
{
    CNetHandler* data = (CNetHandler*)(rhs);
    if (!data) { 
        return -1;
    }
    if (this->_session_id != data->_session_id)
    {
        return (this->_session_id > data->_session_id) ? 1 : -1;
    }
    
    if (this->_dest_ipv4.sin_addr.s_addr != data->_dest_ipv4.sin_addr.s_addr) {
        return (this->_dest_ipv4.sin_addr.s_addr > data->_dest_ipv4.sin_addr.s_addr) ? 1 : -1;   
    }
    if (this->_dest_ipv4.sin_port != data->_dest_ipv4.sin_port) {
        return (this->_dest_ipv4.sin_port > data->_dest_ipv4.sin_port) ? 1 : -1;
    }
    if (this->_proto_type != data->_proto_type) {
        return (this->_proto_type > data->_proto_type) ? 1 : -1;
    }
    if (this->_conn_type != data->_conn_type) {
        return (this->_conn_type > data->_conn_type) ? 1 : -1;
    }
    
    return 0;
}; 

bool CNetHandler::RegistSession()
{
    if (CNetMgr::Instance()->FindNetItem(this) != NULL)
    {
        return false;
    }
    
    MtFrame* mtframe = MtFrame::Instance();
    this->_thread = mtframe->GetActiveThread();
    
    CNetMgr::Instance()->InsertNetItem(this);
    this->_state_flags |= STATE_IN_SESSION;
    return true;    
}

void CNetHandler::UnRegistSession()
{
    if (this->_state_flags & STATE_IN_SESSION)
    {
        CNetMgr::Instance()->RemoveNetItem(this);
        this->_state_flags &= ~STATE_IN_SESSION;
    }
}

TNetItemList* CSockLink::GetItemList(int32_t type)
{
    TNetItemList* list = NULL;
    switch (type)
    {
        case LINK_IDLE_LIST:
            list = &this->_idle_list;
            break;
            
        case LINK_CONN_LIST:
            list = &this->_wait_connect;
            break;

        case LINK_SEND_LIST:
            list = &this->_wait_send;
            break;

        case LINK_RECV_LIST:
            list = &this->_wait_recv;
            break;

        default:
            break;
    }

    return list;
}

void CSockLink::AppendToList(int32_t type, CNetHandler* item)
{
    TNetItemList* list = this->GetItemList(type);
    if (NULL == list)
    {
        MTLOG_ERROR("unknown list type: %d", type);
        return;
    }
    
    TAILQ_INSERT_TAIL(list, item, _link_entry);
}

void CSockLink::RemoveFromList(int32_t type, CNetHandler* item)
{
    TNetItemList* list = this->GetItemList(type);
    if (NULL == list)
    {
        MTLOG_ERROR("unknown list type: %d", type);
        return;
    }
    
    TAILQ_REMOVE(list, item, _link_entry);
}

void CSockLink::NotifyThread(CNetHandler* item, int32_t result)
{
    static MtFrame* frame = NULL;
    if (frame == NULL) {
        frame = MtFrame::Instance();
    }

    if (result != RC_SUCCESS)
    {
        item->SetErrNo(result);
    }

    MicroThread* thread = item->GetThread();
    if ((thread != NULL) && (thread->HasFlag(MicroThread::IO_LIST)))
    {
        frame->RemoveIoWait(thread);
        frame->InsertRunable(thread);
    }  
}

void CSockLink::NotifyAll(int32_t result)
{
    CNetHandler* item = NULL;
    CNetHandler* tmp = NULL;

    TAILQ_FOREACH_SAFE(item, &_wait_connect, _link_entry, tmp)
    {
        NotifyThread(item, result);
        item->Unlink();
    }

    TAILQ_FOREACH_SAFE(item, &_wait_send, _link_entry, tmp)
    {
        NotifyThread(item, result);
        item->Unlink();
    }

    TAILQ_FOREACH_SAFE(item, &_wait_recv, _link_entry, tmp)
    {
        NotifyThread(item, result);
        item->Unlink();
    }

    TAILQ_FOREACH_SAFE(item, &_idle_list, _link_entry, tmp)
    {
        NotifyThread(item, result);
        item->Unlink();
    }
}

void CSockLink::Reset()
{
    this->Close();
    this->NotifyAll(_errno);

    rw_cache_destroy(&_recv_cache);
    if (_rsp_buff != NULL)
    {
        delete_sk_buffer(_rsp_buff);
        _rsp_buff = NULL;
    }

    TAILQ_INIT(&_wait_connect);
    TAILQ_INIT(&_wait_send);
    TAILQ_INIT(&_wait_recv);
    TAILQ_INIT(&_idle_list);
    
    _proto_type     = NET_PROTO_TCP;
    _errno          = 0;
    _state          = 0;
    _last_access    = mt_time_ms();
    _parents        = NULL;

    this->KqueuerObj::Reset();   
}

CSockLink::CSockLink()
{
    rw_cache_init(&_recv_cache, NULL);
    _rsp_buff       = NULL;

    TAILQ_INIT(&_wait_connect);
    TAILQ_INIT(&_wait_send);
    TAILQ_INIT(&_wait_recv);
    TAILQ_INIT(&_idle_list);

    _proto_type     = NET_PROTO_TCP;
    _errno          = 0;
    _state          = 0;
    _last_access    = mt_time_ms();
    _parents        = NULL;
}

CSockLink::~CSockLink()
{
    this->Reset();    
}

void CSockLink::SetProtoType(MT_PROTO_TYPE type)
{
    _proto_type = type;
    _recv_cache.pool = CNetMgr::Instance()->GetSkBuffMng(type);
}

void CSockLink::Close()
{
    if (_fd < 0)
    {
        return;
    }

    MtFrame::Instance()->KqueueDelObj(this);

    close(_fd);
    _fd = -1;
}

void CSockLink::Destroy()
{
    CDestLinks* dstlink = (CDestLinks*)_parents;
    if (NULL == dstlink)
    {
        MTLOG_ERROR("socket link without parents ptr, maybe wrong");
        delete this;
    }
    else
    {
        MTLOG_DEBUG("socket link just free");
        dstlink->FreeSockLink(this);
    }
}

int32_t CSockLink::CreateSock()
{
    if (_fd > 0)
    {
        return _fd;
    }

    if (NET_PROTO_TCP == _proto_type)
    {
        _fd = socket(AF_INET, SOCK_STREAM, 0);
    }
    else
    {
        _fd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    if (_fd < 0)
    {
        MTLOG_ERROR("create socket failed, ret %d[%m]", _fd);
        return -1;
    }

    int flags = 1;
    if (ioctl(_fd, FIONBIO, &flags) < 0)
    {
        MTLOG_ERROR("socket unblock failed, %m");
        close(_fd);
        _fd = -1;
        return -2;
    }

    if (NET_PROTO_TCP == _proto_type)
    {
        setsockopt(_fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
        this->EnableOutput();
    }

    this->EnableInput();
    if (!MtFrame::Instance()->KqueueAddObj(this))
    {
        MTLOG_ERROR("socket epoll mng failed, %m");
        close(_fd);
        _fd = -1;
        return -3;
    }

    return _fd;
}

struct sockaddr_in* CSockLink::GetDestAddr(struct sockaddr_in* addr)
{
    CDestLinks* dstlink = (CDestLinks*)_parents;
    if ((NULL == _parents) || (NULL == addr)) {
        return NULL;
    }

    uint32_t ip = 0;
    uint16_t port = 0;
    dstlink->GetDestIP(ip, port);
    
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
    addr->sin_port = port;

    return addr;
}

bool CSockLink::Connect()
{
    this->_last_access = mt_time_ms();

    if (_proto_type == NET_PROTO_UDP)
    {
        _state |= LINK_CONNECTED;
    }

    if (_state & LINK_CONNECTED)
    {
        return true;
    }

    if (_state & LINK_CONNECTING)
    {
        return false;
    }

    struct sockaddr_in addr = {0};
    
    mt_hook_syscall(connect);
    int32_t ret = ff_hook_connect(_fd, (struct sockaddr*)this->GetDestAddr(&addr), sizeof(struct sockaddr_in));
    if (ret < 0)
    {
        int32_t err = errno;
        if (err == EISCONN)
        {
            _state |= LINK_CONNECTED;
            return true;
        }
        else
        {
            _state |= LINK_CONNECTING;
            if ((err == EINPROGRESS) || (err == EALREADY) || (err == EINTR))
            {
                MTLOG_DEBUG("Open connect not ok, maybe first try, sock %d, errno %d", _fd, err);
                return false;
            }
            else
            {
                MTLOG_ERROR("Open connect not ok, sock %d, errno %d", _fd, err);
                return false;
            }
        }
    }
    else
    {
        _state |= LINK_CONNECTED;
        return true;
    }
}

int32_t CSockLink::SendCacheUdp(void* data, uint32_t len)
{
    mt_hook_syscall(sendto);
    void* buff = NULL;
    uint32_t buff_len = 0;

    CNetHandler* item = NULL;
    CNetHandler* tmp = NULL;
    struct sockaddr_in dst = {0};

    TAILQ_FOREACH_SAFE(item, &_wait_send, _link_entry, tmp)
    {
        item->GetSendData(buff, buff_len);
        if ((NULL == buff) || (buff_len == 0))
        {
            MTLOG_ERROR("get buff ptr invalid, log it");
            NotifyThread(item, 0);
            item->SwitchToIdle();
            continue;
        }
        
        int32_t ret = ff_hook_sendto(_fd, buff, buff_len, 0, 
                    (struct sockaddr*)this->GetDestAddr(&dst), sizeof(struct sockaddr_in));
        if (ret == -1)
        {
            if ((errno == EINTR) || (errno == EAGAIN) || (errno == EINPROGRESS))
            {
                return 0;
            }
            else
            {
                MTLOG_ERROR("socket send failed, fd %d, errno %d(%s)", _fd, 
                          errno, strerror(errno));
                return -2;
            }
        }
    
        NotifyThread(item, 0);
        item->SwitchToIdle();
    }

    if ((data == NULL) || (len == 0))
    {
        return 0;
    }

    int32_t ret = ff_hook_sendto(_fd, data, len, 0, 
                    (struct sockaddr*)this->GetDestAddr(&dst), sizeof(struct sockaddr_in));
    if (ret == -1)
    {
        if ((errno == EINTR) || (errno == EAGAIN) || (errno == EINPROGRESS))
        {
            return 0;
        }
        else
        {
            MTLOG_ERROR("socket send failed, fd %d, errno %d(%s)", _fd, 
                   errno, strerror(errno));
            return -2;
        }
    }
    else
    {
        return ret;
    }
}

int32_t CSockLink::SendCacheTcp(void* data, uint32_t len)
{
    void* buff = NULL;
    uint32_t buff_len = 0;
    struct iovec iov[64];
    int32_t count = 0;
    CNetHandler* item = NULL;
    CNetHandler* tmp = NULL;

    TAILQ_FOREACH_SAFE(item, &_wait_send, _link_entry, tmp)
    {
        item->GetSendData(buff, buff_len); 
        iov[count].iov_base = buff;
        iov[count].iov_len  = (int32_t)buff_len;
        count++;
        if (count >= 64)
        {
            break;
        }
    }
    if ((count < 64) && (data != NULL))
    {
        iov[count].iov_base = data;
        iov[count].iov_len  = (int32_t)len;
        count++;
    }
    
    ssize_t bytes = writev(_fd, iov, count);
    if (bytes < 0)
    {
        if ((errno == EAGAIN) || (errno == EINTR))
        {
            return 0;
        }
        else
        {
            MTLOG_ERROR("socket writev failed, fd %d, errno %d(%s)", _fd, 
                   errno, strerror(errno));
            return -1;
        }
    }

    uint32_t send_left = (uint32_t)bytes;
    TAILQ_FOREACH_SAFE(item, &_wait_send, _link_entry, tmp)
    {
        send_left -= item->SkipSendPos(send_left);
        item->GetSendData(buff, buff_len); 
        if (buff_len == 0)
        {
            NotifyThread(item, 0);
            item->SwitchToIdle();
        }

        if (send_left == 0)
        {
            break;
        }
    }

    return send_left;
}

int32_t CSockLink::SendData(void* data, uint32_t len)
{
    int32_t ret = 0;
    bool rc = false;

    this->_last_access = mt_time_ms();

    if (_proto_type == NET_PROTO_UDP)
    {
        ret = SendCacheUdp(data, len);
    }
    else
    {
        ret = SendCacheTcp(data, len);
    }

    if (ret < (int32_t)len)
    {
        this->EnableOutput();
        rc = MtFrame::Instance()->KqueueCtrlAdd(_fd, KQ_EVENT_READ); 
    }
    else
    {
        this->DisableOutput();
        rc = MtFrame::Instance()->KqueueCtrlDel(_fd, KQ_EVENT_WRITE); 
    }

    if (!rc)
    {
        MTLOG_ERROR("socket epoll mng failed[%m], wait timeout");
    }

    return ret;
}

int32_t CSockLink::RecvDispath()
{
    if (_proto_type == NET_PROTO_UDP)
    {
        return this->DispathUdp();
    }
    else
    {
        return this->DispathTcp();
    }
}

void CSockLink::ExtendRecvRsp()
{
    if (NULL == _rsp_buff)
    {
        _rsp_buff = new_sk_buffer(512);
        if (NULL == _rsp_buff) 
        {
            MTLOG_ERROR("no more memory, error");
            return;
        }
    }
    
    _rsp_buff->data_len +=  read_cache_begin(&_recv_cache, _rsp_buff->data_len, 
        _rsp_buff->data + _rsp_buff->data_len , _rsp_buff->size - _rsp_buff->data_len);
}

CHECK_SESSION_CALLBACK CSockLink::GetSessionCallback()
{
    CHECK_SESSION_CALLBACK check_session = NULL;

    CNetHandler* item = TAILQ_FIRST(&_wait_recv);
    if (NULL == item)
    {
        MTLOG_DEBUG("recv data with no wait item, err");
        goto EXIT_LABEL;
    }
    
    check_session = item->GetSessionCallback();
    if (NULL == check_session)
    {
        MTLOG_ERROR("recv data with no session callback, err");
        goto EXIT_LABEL;
    }

EXIT_LABEL:

    CDestLinks* dstlink = (CDestLinks*)_parents;
    if (NULL == dstlink)
    {
        return check_session;
    }

    if (check_session != NULL)
    {
        dstlink->SetDefaultCallback(check_session);
    }
    else
    {
        check_session = dstlink->GetDefaultCallback();
    }

    return check_session;
}

int32_t CSockLink::DispathTcp()
{
    CHECK_SESSION_CALLBACK check_session = this->GetSessionCallback();
    if (NULL == check_session)
    {
        MTLOG_ERROR("recv data with no session callback, err");
        return -1;
    }

    uint32_t need_len = 0;
    uint64_t sid = 0;
    int32_t ret = 0;
    while (_recv_cache.len > 0)
    {
        this->ExtendRecvRsp();
        if (NULL == _rsp_buff)
        {
            MTLOG_ERROR("alloc memory, error");
            _errno = RC_MEM_ERROR;
            return -3;
        }

        need_len = 0;
        ret = check_session(_rsp_buff->data, _rsp_buff->data_len, &sid, &need_len);
        
        if (ret < 0)
        {
            MTLOG_ERROR("user check resp failed, ret %d", ret);
            _errno = RC_CHECK_PKG_FAIL;
            return -1;
        }

        if (ret == 0)
        {
            if ((need_len == 0) && (_rsp_buff->data_len == _rsp_buff->size))
            {
                MTLOG_DEBUG("recv default buff full[%u], but user no set need length", _rsp_buff->size);
                need_len = _rsp_buff->size * 2;
            }

            if ((need_len <= _rsp_buff->size) || (need_len > 100*1024*1024))
            {
                MTLOG_DEBUG("maybe need wait more data: %u", need_len);
                return 0;
            }

            _rsp_buff = reserve_sk_buffer(_rsp_buff, need_len);
            if (NULL == _rsp_buff)
            {
                MTLOG_ERROR("no more memory, error");
                _errno = RC_MEM_ERROR;
                return -3;
            }

            if (_rsp_buff->data_len >= _recv_cache.len)
            {
                MTLOG_DEBUG("maybe need wait more data, now %u", _recv_cache.len);
                return 0;
            }

            continue;
        }

        if (ret > (int32_t)_recv_cache.len)
        {
            MTLOG_DEBUG("maybe pkg not all ok, wait more");
            return 0;
        }

        CNetHandler* session = this->FindSession(sid);
        if (NULL == session)
        {
            MTLOG_DEBUG("session id %llu, find failed, maybe timeout", sid);
            cache_skip_data(&_recv_cache, ret);
            delete_sk_buffer(_rsp_buff);
            _rsp_buff = NULL;
        }
        else
        {
            MTLOG_DEBUG("session id %llu, find ok, wakeup it", sid);
            cache_skip_data(&_recv_cache, ret);
            this->NotifyThread(session, 0);
            session->SwitchToIdle();
            _rsp_buff->data_len = ret;
            session->SetRespBuff(_rsp_buff);
            _rsp_buff = NULL;
        }
    }

    return 0;

}

int32_t CSockLink::DispathUdp()
{
    CHECK_SESSION_CALLBACK check_session = NULL;
    CNetHandler* item = TAILQ_FIRST(&_wait_recv);
    if (NULL == item)
    {
        MTLOG_DEBUG("recv data with no wait item, maybe wrong pkg recv");
    }
    else
    {
        check_session = item->GetSessionCallback();
        if (NULL == check_session)
        {
            MTLOG_TRACE("recv data with no session callback, err");
        }
    }

    uint64_t sid = 0;
    uint32_t need_len = 0;
    int32_t ret = 0;
    TSkBuffer* block = NULL;
    while ((block = TAILQ_FIRST(&_recv_cache.list)) != NULL)
    {
        if (check_session == NULL)
        {
            MTLOG_DEBUG("no recv wait, skip first block");
            cache_skip_data(&_recv_cache, block->data_len);
            continue;
        }

        need_len = 0;
        ret = check_session(block->data, block->data_len, &sid, &need_len);
        if ((ret <= 0) || (ret > (int32_t)block->data_len))
        {
            MTLOG_DEBUG("maybe wrong pkg come, skip it");
            cache_skip_data(&_recv_cache, block->data_len);
            continue;
        }

        CNetHandler* session = this->FindSession(sid);
        if (NULL == session)
        {
            MTLOG_DEBUG("session id %llu, find failed, maybe timeout", sid);
            cache_skip_data(&_recv_cache, block->data_len);
        }
        else
        {
            MTLOG_DEBUG("session id %llu, find ok, wakeup it", sid);
            this->NotifyThread(session, 0);
            session->SwitchToIdle();
            cache_skip_first_buffer(&_recv_cache);
            session->SetRespBuff(block);
        }
    }

    return 0;
}

CNetHandler* CSockLink::FindSession(uint64_t sid)
{
    CNetHandler key;
    CDestLinks* dstlink = (CDestLinks*)_parents;
    if (NULL == dstlink)
    {
        MTLOG_ERROR("session dest link invalid, maybe error");
        return NULL;
    }
    struct sockaddr_in addr;
    key.SetDestAddress(this->GetDestAddr(&addr));
    key.SetConnType(dstlink->GetConnType());
    key.SetProtoType(dstlink->GetProtoType());
    key.SetSessionId(sid);

    return CNetMgr::Instance()->FindNetItem(&key);
}

int CSockLink::InputNotify()
{
    int32_t ret = 0;
    
    this->_last_access = mt_time_ms();

    if (_proto_type == NET_PROTO_UDP)
    {
        ret = cache_udp_recv(&_recv_cache, _fd, NULL);
    }
    else
    {
        ret = cache_tcp_recv(&_recv_cache, _fd);
    }

    if (ret < 0)
    {
        if (ret == -SK_ERR_NEED_CLOSE)
        {
            MTLOG_DEBUG("recv on link failed, remote close");
            _errno = RC_REMOTE_CLOSED;
        }
        else
        {
            MTLOG_ERROR("recv on link failed, close it, ret %d[%m]", ret);
            _errno = RC_RECV_FAIL;
        }
    
        this->Destroy();
        return -1;
    }

    ret = this->RecvDispath();
    if (ret < 0)
    {
        MTLOG_DEBUG("recv dispath failed, close it, ret %d[%m]", ret);
        this->Destroy();
        return -2;
    }

    return 0;
    
}

int CSockLink::OutputNotify()
{
    int32_t ret = 0;
    
    this->_last_access = mt_time_ms();

    if (_state & LINK_CONNECTING)
    {
        _state &= ~LINK_CONNECTING;
        _state |= LINK_CONNECTED;
        
        CNetHandler* item = NULL;
        CNetHandler* tmp = NULL;
        TAILQ_FOREACH_SAFE(item, &_wait_connect, _link_entry, tmp)
        {
            NotifyThread(item, 0);
            item->SwitchToIdle();
        }
    }

    if (_proto_type == NET_PROTO_UDP)
    {
        ret = SendCacheUdp(NULL, 0);
    }
    else
    {
        ret = SendCacheTcp(NULL, 0);
    }

    if (ret < 0)
    {
        MTLOG_ERROR("Send on link failed, close it, ret %d[%m]", ret);
        _errno = RC_SEND_FAIL;
        this->Destroy();
        return ret;
    }

    if (TAILQ_EMPTY(&_wait_send))
    {
        this->DisableOutput();
        if (!MtFrame::Instance()->KqueueCtrlDel(_fd, KQ_EVENT_WRITE))
        {
            MTLOG_ERROR("socket epoll mng failed[%m], wait timeout");
        }
    }

    return 0;
}

int CSockLink::HangupNotify()
{
    MTLOG_ERROR("socket epoll error, fd %d", _fd);
    
    this->_errno = RC_KQUEUE_ERROR;
    this->Destroy();
    return -1;
}

CDestLinks::CDestLinks()
{
    _timeout        = 5*60*1000;
    _addr_ipv4      = 0;
    _net_port       = 0;
    _proto_type     = NET_PROTO_UNDEF;
    _conn_type      = TYPE_CONN_SESSION;
    
    _max_links      = 3; // 默认3个
    _curr_link      = 0;
    _dflt_callback  = NULL;

    TAILQ_INIT(&_sock_list);
}

void CDestLinks::Reset()
{
    CSockLink* item = NULL;
    CSockLink* temp = NULL;
    TAILQ_FOREACH_SAFE(item, &_sock_list, _link_entry, temp)
    {
        item->Destroy();
    }
    TAILQ_INIT(&_sock_list);

    CTimerMng* timer = MtFrame::Instance()->GetTimerMng();
    if (NULL != timer) 
    {
        timer->stop_timer(this);
    }

    _timeout        = 5*60*1000;
    _addr_ipv4      = 0;
    _net_port       = 0;
    _proto_type     = NET_PROTO_UNDEF;
    _conn_type      = TYPE_CONN_SESSION;
    
    _max_links      = 3;
    _curr_link      = 0;
}

CDestLinks::~CDestLinks()
{
    this->Reset();
}

void CDestLinks::StartTimer()
{
    CTimerMng* timer = MtFrame::Instance()->GetTimerMng();
    if ((NULL == timer) || !timer->start_timer(this, 60*1000))
    {
        MTLOG_ERROR("obj %p attach timer failed, error", this);
    }
}

void CDestLinks::FreeSockLink(CSockLink* sock)
{
    if ((sock == NULL) || (sock->GetParentsPtr() != (void*)this))
    {
        MTLOG_ERROR("invalid socklink %p, error", sock);
        return;
    }

    TAILQ_REMOVE(&_sock_list, sock, _link_entry);
    if (this->_curr_link > 0) {
        this->_curr_link--;
    }

    sock->Reset();
    CNetMgr::Instance()->FreeSockLink(sock);
}

CSockLink* CDestLinks::GetSockLink()
{
    CSockLink* link = NULL;
    if (_curr_link < _max_links)
    {
        link = CNetMgr::Instance()->AllocSockLink();
        if (NULL == link)
        {
            MTLOG_ERROR("alloc sock link failed, error");
            return NULL;
        }
        link->SetParentsPtr(this);
        link->SetProtoType(_proto_type);
        TAILQ_INSERT_TAIL(&_sock_list, link, _link_entry);
        _curr_link++;
    }
    else
    {
        link = TAILQ_FIRST(&_sock_list);
        TAILQ_REMOVE(&_sock_list, link, _link_entry);
        TAILQ_INSERT_TAIL(&_sock_list, link, _link_entry);
    }

    return link;
}

void CDestLinks::timer_notify()
{
    uint64_t now = mt_time_ms();
    CSockLink* item = NULL;
    CSockLink* temp = NULL;
    TAILQ_FOREACH_SAFE(item, &_sock_list, _link_entry, temp)
    {
        if ((item->GetLastAccess() + this->_timeout) < now)
        {
            MTLOG_DEBUG("link timeout, last[%llu], now [%llu]", item->GetLastAccess(), now);
            item->Destroy();
        }
    }

    item = TAILQ_FIRST(&_sock_list);
    if (NULL == item)
    {
        MTLOG_DEBUG("dest links timeout, now [%llu]", now);
        CNetMgr::Instance()->DeleteDestLink(this);
        return;
    }

    this->StartTimer();
    
    return;
}

CNetMgr* CNetMgr::_instance = NULL;
CNetMgr* CNetMgr::Instance (void)
{
    if (NULL == _instance)
    {
        _instance = new CNetMgr();
    }

    return _instance;
}

void CNetMgr::Destroy()
{
    if( _instance != NULL )
    {
        delete _instance;
        _instance = NULL;
    }
}

CNetHandler* CNetMgr::FindNetItem(CNetHandler* key)
{
    if (NULL == this->_session_hash)
    {
        return NULL;
    }

    return (CNetHandler*)_session_hash->HashFind(key);
}

void CNetMgr::InsertNetItem(CNetHandler* item)
{
    if (NULL == this->_session_hash)
    {
        return;
    }

    int32_t ret = _session_hash->HashInsert(item);
    if (ret < 0)
    {
        MTLOG_ERROR("session insert failed, ret %d", ret);
    }
    
    return;
}

void CNetMgr::RemoveNetItem(CNetHandler* item)
{
    CNetHandler* handler =  this->FindNetItem(item);
    if (NULL == handler)
    {
        return;
    }

    _session_hash->HashRemove(handler);
}

CDestLinks* CNetMgr::FindDestLink(CDestLinks* key)
{
    if (NULL == this->_ip_hash)
    {
        return NULL;
    }

    return (CDestLinks*)_ip_hash->HashFind(key);
}

void CNetMgr::InsertDestLink(CDestLinks* item)
{
    if (NULL == this->_ip_hash)
    {
        return;
    }

    int32_t ret = _ip_hash->HashInsert(item);
    if (ret < 0)
    {
        MTLOG_ERROR("ip dest insert failed, ret %d", ret);
    }
    
    return;
}

void CNetMgr::RemoveDestLink(CDestLinks* item)
{
    CDestLinks* handler =  this->FindDestLink(item);
    if (NULL == handler)
    {
        return;
    }

    _ip_hash->HashRemove(handler);
}

CDestLinks* CNetMgr::FindCreateDest(CDestLinks* key)
{
    CDestLinks* dest = this->FindDestLink(key);
    if (dest != NULL)
    {
        MTLOG_DEBUG("dest links reuse ok");
        return dest;
    }

    dest = this->AllocDestLink();
    if (NULL == dest)
    {
        MTLOG_ERROR("dest links alloc failed, log it");
        return NULL;
    }

    dest->CopyKeyInfo(key);
    dest->StartTimer();
    this->InsertDestLink(dest);
    
    return dest;
}

void CNetMgr::DeleteDestLink(CDestLinks* dst)
{
    this->RemoveDestLink(dst);
    dst->Reset();
    this->FreeDestLink(dst);   
}

CNetMgr::CNetMgr()
{
    sk_buffer_mng_init(&_tcp_pool, 60, 4096);
    sk_buffer_mng_init(&_udp_pool, 60, SK_DFLT_BUFF_SIZE);

    _ip_hash = new HashList(100000);
    _session_hash = new HashList(100000);
}

CNetMgr::~CNetMgr()
{
    if (_ip_hash != NULL) 
    {
        HashKey* hash_item = _ip_hash->HashGetFirst();
        while (hash_item)
        {
            delete hash_item;
            hash_item = _ip_hash->HashGetFirst();
        }
    
        delete _ip_hash;
        _ip_hash = NULL;
    }

    if (_session_hash != NULL) 
    {
        HashKey* hash_item = _session_hash->HashGetFirst();
        while (hash_item)
        {
            delete hash_item;
            hash_item = _session_hash->HashGetFirst();
        }
        
        delete _session_hash;
        _session_hash = NULL;
    }

    sk_buffer_mng_destroy(&_tcp_pool);
    sk_buffer_mng_destroy(&_udp_pool);
}

void CNetMgr::RecycleObjs(uint64_t now)
{
    uint32_t now_s = (uint32_t)(now / 1000);
    
    recycle_sk_buffer(&_udp_pool, now_s);
    recycle_sk_buffer(&_tcp_pool, now_s);
    
    _net_item_pool.RecycleItem(now);
    _sock_link_pool.RecycleItem(now);
    _dest_ip_pool.RecycleItem(now);
}
