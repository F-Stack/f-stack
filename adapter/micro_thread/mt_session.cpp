
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
 *  @file mt_session.cpp
 *  @time 20130924
 **/

#include "micro_thread.h"
#include "mt_session.h"

using namespace std;
using namespace NS_MICRO_THREAD;

ISession::~ISession()
{
    if (_session_flg) {
        SessionMgr* sessionmgr = SessionMgr::Instance();
        sessionmgr->RemoveSession(_session_id);
        _session_flg = (int)SESSION_IDLE;
    }
}

SessionMgr* SessionMgr::_instance = NULL;
SessionMgr* SessionMgr::Instance (void)
{
    if (NULL == _instance)
    {
        _instance = new SessionMgr;
    }

    return _instance;
}

void SessionMgr::Destroy()
{
    if( _instance != NULL )
    {
        delete _instance;
        _instance = NULL;
    }
}

SessionMgr::SessionMgr()
{
    _curr_session = 0;
    _hash_map = new HashList(100000);
}

SessionMgr::~SessionMgr()
{
    if (_hash_map) {
        delete _hash_map;
        _hash_map = NULL;
    }
}

int SessionMgr::InsertSession(ISession* session)
{
    if (!_hash_map || !session) {
        MTLOG_ERROR("Mngr not init(%p), or session null(%p)", _hash_map, session);
        return -100;
    }

    int flag = session->GetSessionFlag();
    if (flag & SESSION_INUSE) {
        MTLOG_ERROR("Session already in hash, bugs, %p, %d", session, flag);
        return -200;
    }    
    
    session->SetSessionFlag((int)SESSION_INUSE);
    return _hash_map->HashInsert(session);
}

ISession* SessionMgr::FindSession(int session_id)
{
    if (!_hash_map) {
        MTLOG_ERROR("Mngr not init(%p)", _hash_map);
        return NULL;
    }

    ISession key;
    key.SetSessionId(session_id);    
    return dynamic_cast<ISession*>(_hash_map->HashFind(&key));
}

void SessionMgr::RemoveSession(int session_id)
{
    if (!_hash_map) {
        MTLOG_ERROR("Mngr not init(%p)", _hash_map);
        return;
    }

    ISession key;
    key.SetSessionId(session_id);    
    return _hash_map->HashRemove(&key);
}
