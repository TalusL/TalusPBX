//
// Created by liangzhuohua on 2023/7/20.
//

#ifndef TALUSPBX_USERAGENTSESSION_H
#define TALUSPBX_USERAGENTSESSION_H

#include "SipSession.h"
#include <Util/TimeTicker.h>

using namespace toolkit;
class UserAgentSession: public SipSession{
public:
    explicit UserAgentSession(const toolkit::Socket::Ptr &sock): SipSession(sock){};
    ~UserAgentSession() override = default;
protected:
    void onSipMsgEvent(int type, osip_transaction_t *t, osip_message_t *message) override;

    void onSipTransactionEvent(int type, osip_transaction_t *transaction) override;

    void onSipTransportError(int type, osip_transaction_t *t, int error) override;

    static bool CheckAuth(osip_transaction_t *t, const std::string &pass);

    void onManager() override;

private:
    Ticker m_ticker;
    std::string m_userName;
    std::string m_agentContract;
};


#endif //TALUSPBX_USERAGENTSESSION_H
