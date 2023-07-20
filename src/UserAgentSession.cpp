//
// Created by liangzhuohua on 2023/7/20.
//

#include "UserAgentSession.h"
#include "Util/MD5.h"

#define PASS "12345678"

void UserAgentSession::onSipMsgEvent(int type, osip_transaction_t *t, osip_message_t *message) {
    switch (type) {
        case OSIP_NIST_REGISTER_RECEIVED:{
            //收到注册消息
            if(!CheckAuth(t,PASS)){
                StrCaseMap header;
                header["WWW-Authenticate"] =
                        StrPrinter << "Digest realm=\"" << "TalusPBX" << "\","
                                   << "qop=\"auth,auth-int\","
                                   << "nonce=\"" << toolkit::makeRandStr(32) << "\","
                                   << "opaque=\"" << getIdentifier() << "\"";
                Response(t, 401, header);
            }
            //注册成功
            Response(t,200);
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
}

void UserAgentSession::onSipTransactionEvent(int type, osip_transaction_t *transaction) {
}

void UserAgentSession::onSipTransportError(int type, osip_transaction_t *t, int error) {
}


bool UserAgentSession::CheckAuth(osip_transaction_t *t, const std::string &pass) {
    osip_authorization_t *authenticationInfo{};
    osip_message_get_authorization(t->orig_request, 0, &authenticationInfo);
    if (!authenticationInfo) {
        return false;
    }
    std::string username = authenticationInfo->username;
    replace(username, "\"", "");
    std::string realm = authenticationInfo->realm;
    replace(realm, "\"", "");
    std::string method = t->orig_request->sip_method;
    replace(method, "\"", "");
    std::string uri = authenticationInfo->uri;
    replace(uri, "\"", "");
    std::string nonce = authenticationInfo->nonce;
    replace(nonce, "\"", "");
    std::string cnonce = authenticationInfo->cnonce;
    replace(cnonce, "\"", "");
    std::string response = authenticationInfo->response;
    replace(response, "\"", "");
    std::string nonce_count = authenticationInfo->nonce_count;
    replace(nonce_count, "\"", "");
    std::string qop = authenticationInfo->message_qop;
    replace(nonce_count, "\"", "");
    osip_authorization_free(authenticationInfo);

    auto r = toolkit::MD5(
            toolkit::MD5(username + ":" + realm + ":" + pass).hexdigest()
            + ":" + (qop.empty() ? (nonce) : (nonce + ":" + nonce_count + ":" + cnonce + ":" + qop)) + ":" +
            toolkit::MD5(method + ":" + uri).hexdigest()
    ).hexdigest();
    return (response == r);
}