//
// Created by Talus on 2023/7/16.
//

#ifndef TALUSPBX_SIPSESSION_H
#define TALUSPBX_SIPSESSION_H

#include <sys/time.h>
#include "osip2/osip.h"
#include "osip2/osip_dialog.h"
#include "Network/Session.h"

// sip event
#define ON_SIP_MSG_EVT "ON_SIP_EVT"
#define ON_SIP_MSG_EVT_ARGS int type, osip_transaction_t * t, osip_message_t * message
// sip transaction
#define ON_SIP_TRANSACTION_EVT "ON_SIP_TRANSACTION_EVT"
#define ON_SIP_TRANSACTION_EVT_ARGS int type, osip_transaction_t * transaction
// sip transport error
#define ON_SIP_TRANSPORT_ERROR "ON_SIP_TRANSPORT_ERROR"
#define ON_SIP_TRANSPORT_ERROR_ARGS int type, osip_transaction_t * t, int error

class SipSession :public toolkit::Session{
public:
    explicit SipSession(const toolkit::Socket::Ptr &sock);
    ~SipSession() override = default;
protected:
    void onRecv(const toolkit::Buffer::Ptr &buf) override;

    void onError(const toolkit::SockException &err) override;

    void onManager() override;

    static int buildDefaultResp(osip_message_t **dest, osip_dialog_t *dialog, int status, osip_message_t *request);
private:
    std::shared_ptr<osip> m_sipCtx;
};


#endif //TALUSPBX_SIPSESSION_H
