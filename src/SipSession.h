//
// Created by Talus on 2023/7/16.
//

#ifndef TALUSPBX_SIPSESSION_H
#define TALUSPBX_SIPSESSION_H

#include <sys/time.h>
#include "osip2/osip.h"
#include "osip2/osip_dialog.h"
#include "Network/Session.h"

class SipSession :public toolkit::Session{
public:
    SipSession(const toolkit::Socket::Ptr &sock);
    ~SipSession() = default;
    void onRecv(const toolkit::Buffer::Ptr &buf) override;

    void onError(const toolkit::SockException &err) override;

    void onManager() override;

    static int buildDefaultResp(osip_message_t **dest, osip_dialog_t *dialog, int status, osip_message_t *request);
private:
    std::shared_ptr<osip> m_sipCtx;
};


#endif //TALUSPBX_SIPSESSION_H
