
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
 *  @file mt_concurrent.c
 *  @time 20130924
 **/

#include "micro_thread.h"
#include "mt_msg.h"
#include "mt_notify.h"
#include "mt_connection.h"
#include "mt_concurrent.h"

using namespace std;
using namespace NS_MICRO_THREAD;

int NS_MICRO_THREAD::mt_multi_netfd_poll(IMtActList& req_list, int how, int timeout)
{
    KqObjList fdlist;
    TAILQ_INIT(&fdlist);

    KqueuerObj* obj = NULL;
    IMtAction* action = NULL;    
    for (IMtActList::iterator it = req_list.begin(); it != req_list.end(); ++it)
    {
        action = *it;
        if (action) {
            obj = action->GetNtfyObj();
        }
        if (!action || !obj)
        {
            action->SetErrno(ERR_FRAME_ERROR);
            MTLOG_ERROR("input action %p, or ntify null, error", action);
            return -1;
        }
        
        obj->SetRcvEvents(0);
        if (how & KQ_EVENT_READ)
        {
            obj->EnableInput();
        }
        else
        {
            obj->DisableInput();
        }
        
        if (how & KQ_EVENT_WRITE)
        {
            obj->EnableOutput();
        } 
        else
        {
            obj->DisableOutput();
        }
        
        TAILQ_INSERT_TAIL(&fdlist, obj, _entry);

    }

    MtFrame* mtframe = MtFrame::Instance();
    if (!mtframe || !mtframe->KqueueSchedule(&fdlist, NULL, (int)timeout))
    {
        if (errno != ETIME)
        {
            action->SetErrno(ERR_KQUEUE_FAIL);
            MTLOG_ERROR("Mtframe %p, epoll schedule failed, errno %d", mtframe, errno);
            return -2;
        }
        
        return -3;
    }   

    return 0;
}

int NS_MICRO_THREAD::mt_multi_newsock(IMtActList& req_list)
{
    int sock = -1, has_ok = 0;
    IMtAction* action = NULL; 
    IMtConnection* net_handler = NULL;

    for (IMtActList::iterator it = req_list.begin(); it != req_list.end(); ++it)
    {
        action = *it;
        if (NULL == action)
        {
            action->SetErrno(ERR_PARAM_ERROR);
            MTLOG_ERROR("Invalid param, conn %p null!!", action);
            return -1;
        }

        if (action->GetErrno() != ERR_NONE) {
            continue;
        }           
        
        net_handler = action->GetIConnection();
        if (NULL == net_handler)
        {
            action->SetErrno(ERR_FRAME_ERROR);
            MTLOG_ERROR("Invalid param, conn %p null!!", net_handler);
            return -2;
        }

        sock = net_handler->CreateSocket();
        if (sock < 0)
        {
            action->SetErrno(ERR_SOCKET_FAIL);
            MTLOG_ERROR("Get sock data failed, ret %d, errno %d!!", sock, errno);
            return -3;
        }
        has_ok = 1;

        if (action->GetProtoType() == MT_UDP)
        {  
            action->SetMsgFlag(MULTI_FLAG_OPEN);
        }
        else
        {
            action->SetMsgFlag(MULTI_FLAG_INIT);
        }        
    }

    if (has_ok)
    {
        return 0;
    }
    else
    {
        return -4;
    }
}

int NS_MICRO_THREAD::mt_multi_open(IMtActList& req_list, int timeout)
{
    utime64_t start_ms = MtFrame::Instance()->GetLastClock();
    utime64_t end_ms = start_ms + timeout;
    utime64_t curr_ms = 0;

    int ret = 0, has_open = 0;
    IMtAction* action = NULL;   
    IMtConnection* net_handler = NULL;
    IMtActList::iterator it;  
    
    while (1)
    {
        IMtActList wait_list;
        for (it = req_list.begin(); it != req_list.end(); ++it)
        {
            action = *it;
            if (action->GetErrno() != ERR_NONE) {
                continue;
            }           
            
            if (action->GetMsgFlag() == MULTI_FLAG_OPEN) {
                has_open = 1;
                continue;                
            }

            net_handler = action->GetIConnection();
            if (NULL == net_handler)
            {
                action->SetErrno(ERR_FRAME_ERROR);
                MTLOG_ERROR("Invalid param, conn %p null!!", net_handler);
                return -1;
            }
            
            ret = net_handler->OpenCnnect();
            if (ret < 0)
            {
                wait_list.push_back(action);
            }
            else
            {
                action->SetMsgFlag(MULTI_FLAG_OPEN);
            }
        }
        
        curr_ms = MtFrame::Instance()->GetLastClock(); 
        if (curr_ms > end_ms)
        {
            MTLOG_DEBUG("Open connect timeout, errno %d", errno);
            for (IMtActList::iterator it = wait_list.begin(); it != wait_list.end(); ++it)
            {
                (*it)->SetErrno(ERR_CONNECT_FAIL);                
            }

            if (!has_open)
            {
                return 0;
            }
            else
            {
                return -2;                
            }
        }

        if (!wait_list.empty())
        {
            mt_multi_netfd_poll(wait_list, KQ_EVENT_WRITE, end_ms - curr_ms);
        }
        else
        {
            return 0;
        }        
    }
        
}

int NS_MICRO_THREAD::mt_multi_sendto(IMtActList& req_list, int timeout)
{
    utime64_t start_ms = MtFrame::Instance()->GetLastClock();
    utime64_t end_ms = start_ms + timeout;
    utime64_t curr_ms = 0;

    int ret = 0, has_send = 0;
    IMtAction* action = NULL;    
    IMtConnection* net_handler = NULL;

    while (1)
    {
        IMtActList wait_list;
        for (IMtActList::iterator it = req_list.begin(); it != req_list.end(); ++it)
        {
            action = *it;            
            if (action->GetErrno() != ERR_NONE) {
                continue;
            } 
            
            if (action->GetMsgFlag() == MULTI_FLAG_SEND) {
                has_send = 1;
                continue;
            }             

            net_handler = action->GetIConnection();
            if (NULL == net_handler)
            {
                action->SetErrno(ERR_FRAME_ERROR);
                MTLOG_ERROR("Invalid param, conn %p null!!", net_handler);
                return -2;
            }

            ret = net_handler->SendData();
            if (ret == -1)
            {
                action->SetErrno(ERR_SEND_FAIL);
                MTLOG_ERROR("MultiItem msg send error, %d", errno);
                continue;
            }
            else if (ret == 0)
            {
                wait_list.push_back(action);
                continue;
            }
            else
            {
                action->SetMsgFlag(MULTI_FLAG_SEND);
            }
        }

        curr_ms = MtFrame::Instance()->GetLastClock(); 
        if (curr_ms > end_ms)
        {
            MTLOG_DEBUG("send data timeout");
            for (IMtActList::iterator it = wait_list.begin(); it != wait_list.end(); ++it)
            {
                (*it)->SetErrno(ERR_SEND_FAIL);                
            } 

            if (has_send) 
            {
                return 0;
            }
            else
            {
                return -5;
            }
        }
        
        if (!wait_list.empty())
        {
            mt_multi_netfd_poll(wait_list, KQ_EVENT_WRITE, end_ms - curr_ms);
        }
        else
        {
            return 0;
        }        
    }

    return 0;
}

int NS_MICRO_THREAD::mt_multi_recvfrom(IMtActList& req_list, int timeout)
{
    utime64_t start_ms = MtFrame::Instance()->GetLastClock();
    utime64_t end_ms = start_ms + timeout;
    utime64_t curr_ms = 0;

    int ret = 0;
    IMtAction* action = NULL;
    IMtConnection* net_handler = NULL;

    while (1)
    {
        IMtActList wait_list;
        for (IMtActList::iterator it = req_list.begin(); it != req_list.end(); ++it)
        {
            action = *it;
            if (action->GetErrno() != ERR_NONE) {
                continue;
            }  
            
            if (MULTI_FLAG_FIN == action->GetMsgFlag())
            {
                continue;
            }
           
            net_handler = action->GetIConnection();
            if (NULL == net_handler)
            {
                action->SetErrno(ERR_FRAME_ERROR);
                MTLOG_ERROR("Invalid param, conn %p null!!", net_handler);
                return -2;
            }

            ret = net_handler->RecvData();
            if (ret < 0)
            {
                action->SetErrno(ERR_RECV_FAIL);
                MTLOG_ERROR("MultiItem msg recv failed: %p", net_handler);
                continue;
            }
            else if (ret == 0)
            {
                wait_list.push_back(action);
                continue;
            }
            else
            {
                action->SetMsgFlag(MULTI_FLAG_FIN);
                action->SetCost(MtFrame::Instance()->GetLastClock() - start_ms);
            }
        }

        curr_ms = MtFrame::Instance()->GetLastClock(); 
        if (curr_ms > end_ms)
        {
            MTLOG_DEBUG("Recv data timeout, curr %llu, start: %llu", curr_ms, start_ms);            
            for (IMtActList::iterator it = wait_list.begin(); it != wait_list.end(); ++it)
            {
                (*it)->SetErrno(ERR_RECV_TIMEOUT);                
            }
            return -5;
        }
        
        if (!wait_list.empty())
        {
            mt_multi_netfd_poll(wait_list, KQ_EVENT_READ, end_ms - curr_ms);
        }
        else
        {
            return 0;
        }        
    }
}

int NS_MICRO_THREAD::mt_multi_sendrcv_ex(IMtActList& req_list, int timeout)
{
    utime64_t start_ms = MtFrame::Instance()->GetLastClock();
    utime64_t curr_ms = 0;
    
    int rc = mt_multi_newsock(req_list);
    if (rc < 0)
    {
        MT_ATTR_API(320842, 1);
        MTLOG_ERROR("mt_multi_sendrcv new sock failed, ret: %d", rc);
        return -1;
    }

    rc = mt_multi_open(req_list, timeout);
    if (rc < 0)
    {
        MT_ATTR_API(320843, 1);
        MTLOG_ERROR("mt_multi_sendrcv open failed, ret: %d", rc);
        return -2;
    }
    
    curr_ms = MtFrame::Instance()->GetLastClock();
    rc = mt_multi_sendto(req_list, timeout - (curr_ms - start_ms));
    if (rc < 0)
    {
        MT_ATTR_API(320844, 1); 
        MTLOG_ERROR("mt_multi_sendrcv send failed, ret: %d", rc);
        return -3;
    }

    curr_ms = MtFrame::Instance()->GetLastClock();
    rc = mt_multi_recvfrom(req_list, timeout - (curr_ms - start_ms));
    if (rc < 0)
    {
        MT_ATTR_API(320845, 1);
        MTLOG_ERROR("mt_multi_sendrcv recv failed, ret: %d", rc);
        return -4;
    }

    return 0; 
}

int NS_MICRO_THREAD::mt_msg_sendrcv(IMtActList& req_list, int timeout)
{
    int iRet = 0;

    for (IMtActList::iterator it = req_list.begin(); it != req_list.end(); ++it)
    {
        IMtAction* pAction = *it;
        if (!pAction || pAction->InitConnEnv() < 0)
        {
            MTLOG_ERROR("invalid action(%p) or int failed, error", pAction);
            return -1;
        } 
        
        iRet = pAction->DoEncode();
        if (iRet < 0)
        {
            pAction->SetErrno(ERR_ENCODE_ERROR);
            MTLOG_ERROR("pack action pkg failed, act %p, ret %d", pAction, iRet);
            continue;
        }
        
    }

    mt_multi_sendrcv_ex(req_list, timeout);

    for (IMtActList::iterator it = req_list.begin(); it != req_list.end(); ++it)
    {
        IMtAction* pAction = *it;
        
        if (pAction->GetMsgFlag() != MULTI_FLAG_FIN)
        {
            pAction->DoError();
            MTLOG_DEBUG("send recv failed: %d", pAction->GetErrno());
            continue;
        }

        iRet = pAction->DoProcess();
        if (iRet < 0)
        {
            MTLOG_DEBUG("action process failed: %d", iRet);
            continue;
        } 
    }

    for (IMtActList::iterator it = req_list.begin(); it != req_list.end(); ++it)
    {
        IMtAction* pAction = *it;
        pAction->Reset();
    }

    return 0;
}
