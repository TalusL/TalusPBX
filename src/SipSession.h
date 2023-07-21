//
// Created by Talus on 2023/7/16.
//

#ifndef TALUSPBX_SIPSESSION_H
#define TALUSPBX_SIPSESSION_H

#include <sys/time.h>
#include "osip2/osip.h"
#include "osip2/osip_dialog.h"
#include "Network/Session.h"
#include "Common/Parser.h"

// sip event
#define ON_SIP_MSG_EVT "ON_SIP_EVT"
#define ON_SIP_MSG_EVT_ARGS SipSession& sender,int type, osip_transaction_t * t, osip_message_t * message
// sip transaction
#define ON_SIP_TRANSACTION_EVT "ON_SIP_TRANSACTION_EVT"
#define ON_SIP_TRANSACTION_EVT_ARGS  SipSession& sender,int type, osip_transaction_t * transaction
// sip transport error
#define ON_SIP_TRANSPORT_ERROR "ON_SIP_TRANSPORT_ERROR"
#define ON_SIP_TRANSPORT_ERROR_ARGS  SipSession& sender,int type, osip_transaction_t * t, int error


using namespace toolkit;
using namespace mediakit;

class SipSession :public toolkit::Session{
public:
    explicit SipSession(const toolkit::Socket::Ptr &sock);
    ~SipSession() override = default;
    static std::shared_ptr<SipSession> GetSipInstance(void * p);
    static int BuildDefaultResp(osip_message_t **dest, osip_dialog_t *dialog, int status, osip_message_t *request);
    static int Response(osip_transaction_t * t,int status,const mediakit::StrCaseMap& header = {},
                 const std::string& contentType = "",const std::string& body = "");
    static int BuildRequest(osip_message_t **message, const char *method, const char *to, const char *from, const char *route);
protected:
    void onRecv(const toolkit::Buffer::Ptr &buf) override;

    void onError(const toolkit::SockException &err) override;

    void onManager() override;

    virtual void onSipMsgEvent(int type, osip_transaction_t * t, osip_message_t * message){};

    virtual void onSipTransactionEvent(int type, osip_transaction_t * transaction){};

    virtual void onSipTransportError(int type, osip_transaction_t * t, int error){};


    std::shared_ptr<osip> m_sipCtx;
};


#endif //TALUSPBX_SIPSESSION_H
