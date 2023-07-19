//
// Created by liangzhuohua on 2023/7/17.
//

#include "AgentMgr.h"
#include <Util/NoticeCenter.h>
#include "SipSession.h"
#include "Common/Parser.h"

using namespace toolkit;
using namespace mediakit;

#define PASS "12345678"

void AgentMgr::Start() {
    // 监听收到SIP消息广播
    NoticeCenter::Instance().addListener(this,ON_SIP_MSG_EVT,[](ON_SIP_MSG_EVT_ARGS){
        switch (type) {
            case OSIP_NIST_REGISTER_RECEIVED:{
                //收到注册消息
                if(!sender.CheckAuth(t,PASS)){
                    return;
                }
                //注册成功
                sender.Response(t,200);
                break;
            }
            case OSIP_IST_INVITE_RECEIVED:{
                //收到INVITE
                break;
            }
            case OSIP_IST_ACK_RECEIVED:{
                //收到INVITE ACK
                break;
            }
            case OSIP_ICT_STATUS_2XX_RECEIVED:{
                //收到INVITE 200
                break;
            }
            default:{
                // 收到SIP消息
            }
        }
    });
}

void AgentMgr::Stop() {
    // 取消监听收到SIP消息广播
    NoticeCenter::Instance().delListener(this,ON_SIP_MSG_EVT);
}
