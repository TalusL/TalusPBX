//
// Created by liangzhuohua on 2023/7/17.
//

#ifndef TALUSPBX_AGENTMGR_H
#define TALUSPBX_AGENTMGR_H
#include "UserAgentSession.h"

using namespace std;
class AgentMgr {
public:
    static AgentMgr& Instance(){
        static AgentMgr agentMgr;
        return agentMgr;
    }
    void Start();
    void Stop();
    /**
     * 增加注册成功的Agent
     * @param userId 用户Id
     * @param session 会话引用
     */
    void AddRegisterAgent(const string& userId,const shared_ptr<UserAgentSession>& session){
        lock_guard<mutex> lck(m_agentSessionMtx);
        if(m_regSessions.find(userId) != m_regSessions.end()){
            auto agent = m_regSessions[userId].lock();
            if(agent){
                agent->shutdown(SockException(Err_shutdown,(StrPrinter<<"userId:"<<userId
                    <<" connection change from:"<<agent->get_peer_ip()<<":"<<agent->get_peer_port()
                    <<" to:"<<session->get_peer_ip()<<":"<<session->get_peer_port())));
            }
        }
        m_regSessions[userId] = session;
    }
    /**
     * RemoveAgent
     * @param userId userid
     */
    void RemoveAgent(const string& userId){
        lock_guard<mutex> lck(m_agentSessionMtx);
        m_regSessions.erase(userId);
        InfoL<<userId<<" removed!";
    }
    /**
     * 遍历
     * @param cb callback
     */
    void EachAgentSession(const function<bool(const string& userId,const shared_ptr<UserAgentSession>&)>& cb){
        lock_guard<mutex> lck(m_agentSessionMtx);
        for (const auto &item: m_regSessions){
            auto uid = item.first;
            auto session = item.second.lock();
            auto cont = true;
            if(cont&&session){
                cont = cb(uid,session);
            }
        }
    }
private:
    mutex m_agentSessionMtx;
    map<string,weak_ptr<UserAgentSession>> m_regSessions;
    AgentMgr() = default;
    ~AgentMgr() = default;
};


#endif //TALUSPBX_AGENTMGR_H
