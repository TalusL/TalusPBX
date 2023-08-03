//
// Created by liangzhuohua on 2023/7/21.
//

#ifndef TALUSPBX_MESSAGEROUTER_H
#define TALUSPBX_MESSAGEROUTER_H


#include "osipparser2/osip_message.h"
#include "AgentMgr.h"

class MessageRouter {
public:
    static MessageRouter& Instance(){
        static MessageRouter messageRouter;
        return messageRouter;
    }

    void RouteMessage(osip_transaction_t* t,osip_message_t * msg,const shared_ptr<SipSession>& session){
        AgentMgr::Instance().EachAgentSession([this, msg,t,session](const string& uid,const shared_ptr<SipSession>& targetSession){
            if(session.get() != targetSession.get() && ( msg->from->url->username == uid || msg->to->url->username == uid )){

                char *buf{};
                size_t len{};
                osip_message_to_str(msg,&buf,&len);
                DebugL<<"routing:"<<session->get_peer_ip()<<":"<<session->get_peer_port()<<" -> "<<targetSession->get_peer_ip()<<":"<<targetSession->get_peer_port()<<" \r\n"<<buf;
                osip_free(buf);

                targetSession->SendMsg(msg);
                return false;
            }
            return true;
        });
    }

private:
    MessageRouter() = default;
};


#endif //TALUSPBX_MESSAGEROUTER_H
