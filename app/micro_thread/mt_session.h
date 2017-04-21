
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
 *  @info 微线程的事件会话管理部分, 每个后端连接关联一session信息
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
    SESSION_IDLE    = 0,    ///< SESSION 未加入hash管理
    SESSION_INUSE   = 1,    ///< SESSION 进入管理状态
};

/**
 * @brief 并发请求session接口定义, 根据session可映射出thread,action等
 */
class ISession : public HashKey
{
public:

    /**
     * @brief 构造与析构函数
     */
    ISession() : _session_id(0), _session_flg(0), _thread(NULL), _connection(NULL) {};
    virtual ~ISession();

public:

    /**
     * @brief 会话ID的设置与获取
     */
    void SetSessionId(int id) {
        _session_id = id;    
    };
    int GetSessionId() {
        return _session_id;
    };

    /**
     * @brief 关联线程的设置与获取
     */
    MicroThread* GetOwnerThread(){
        return _thread;
    };
    void SetOwnerThread(MicroThread* thread) {
        _thread = thread;
    };

    /**
     * @brief 关联连接的设置与获取
     */
    IMtConnection* GetSessionConn(){
        return _connection;
    };
    void SetSessionConn(IMtConnection* conn) {
        _connection = conn;
    };

    /**
     * @brief 会话flag的设置与获取
     */
    void SetSessionFlag(int flag) {
        _session_flg = flag;    
    };
    int GetSessionFlag() {
        return _session_flg;
    };

    /**
     *  @brief 节点元素的hash算法, 获取key的hash值
     *  @return 节点元素的hash值
     */
    virtual uint32_t HashValue(){
        return _session_id;
    }; 

    /**
     *  @brief 节点元素的cmp方法, 同一桶ID下, 按key比较
     *  @return 节点元素的hash值
     */
    virtual int HashCmp(HashKey* rhs){
        return this->_session_id - (int)rhs->HashValue();
    };         

protected:

    int  _session_id;               // 会话id信息
    int  _session_flg;              // 记录session状态 0 -不在hash中, 1 -hash管理中
    MicroThread* _thread;           // 会话所属的session  
    IMtConnection* _connection;     // 会话关联的连接
};

/**
 * @brief 全局的session管理结构
 */
class SessionMgr
{
public:

    /**
     * @brief 会话上下文的全局管理句柄接口
     * @return 全局句柄指针
     */
    static SessionMgr* Instance (void);

    /**
     * @brief 全局的删除接口
     */
    static void Destroy();

    /**
     * @brief 获取sessionid
     * @return 全局句柄指针
     */
    int GetSessionId(void) {
        _curr_session++;
        if (!_curr_session) {
            _curr_session++;
        }
        return _curr_session;
    };

    /**
     * @brief Session数据存储
     */
    int InsertSession(ISession* session);

    /**
     * @brief 查询session数据
     */
    ISession* FindSession(int session_id);

    /**
     * @brief 删除session数据
     */
    void RemoveSession(int session_id);

    /**
     * @brief 析构函数
     */
    ~SessionMgr();
    
private:

    /**
     * @brief 消息buff的构造函数
     */
    SessionMgr();

    static SessionMgr * _instance;          ///<  单例类句柄
    int       _curr_session;                ///<  session种子
    HashList* _hash_map;                    ///<  按sessionid hash存储
};

}

#endif


