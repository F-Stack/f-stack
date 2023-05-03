
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
 *  @file mt_session.h
 *  @time 20130924
 **/

#ifndef __MT_SESSION_H__
#define __MT_SESSION_H__

#include "hash_list.h"

namespace NS_MICRO_THREAD {

class MicroThread;
class IMtConnection;

enum SESSION_FLAG
{
    SESSION_IDLE    = 0,
    SESSION_INUSE   = 1,
};

class ISession : public HashKey
{
public:

    ISession() : _session_id(0), _session_flg(0), _thread(NULL), _connection(NULL) {};
    virtual ~ISession();

public:

    void SetSessionId(int id) {
        _session_id = id;    
    };
    int GetSessionId() {
        return _session_id;
    };

    MicroThread* GetOwnerThread(){
        return _thread;
    };
    void SetOwnerThread(MicroThread* thread) {
        _thread = thread;
    };

    IMtConnection* GetSessionConn(){
        return _connection;
    };
    void SetSessionConn(IMtConnection* conn) {
        _connection = conn;
    };

    void SetSessionFlag(int flag) {
        _session_flg = flag;    
    };
    int GetSessionFlag() {
        return _session_flg;
    };

    virtual uint32_t HashValue(){
        return _session_id;
    }; 

    virtual int HashCmp(HashKey* rhs){
        return this->_session_id - (int)rhs->HashValue();
    };         

protected:

    int  _session_id;
    int  _session_flg;
    MicroThread* _thread;
    IMtConnection* _connection;
};

class SessionMgr
{
public:

    static SessionMgr* Instance (void);

    static void Destroy();

    int GetSessionId(void) {
        _curr_session++;
        if (!_curr_session) {
            _curr_session++;
        }
        return _curr_session;
    };

    int InsertSession(ISession* session);

    ISession* FindSession(int session_id);

    void RemoveSession(int session_id);

    ~SessionMgr();
    
private:

    SessionMgr();

    static SessionMgr * _instance;
    int       _curr_session;
    HashList* _hash_map;
};

}

#endif
