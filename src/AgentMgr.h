//
// Created by liangzhuohua on 2023/7/17.
//

#ifndef TALUSPBX_AGENTMGR_H
#define TALUSPBX_AGENTMGR_H


class AgentMgr {
public:
    static AgentMgr& Instance(){
        static AgentMgr agentMgr;
        return agentMgr;
    }
    void Start();
    void Stop();
private:
    AgentMgr() = default;
    ~AgentMgr() = default;
};


#endif //TALUSPBX_AGENTMGR_H
