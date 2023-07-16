//
// Created by Talus on 2023/7/16.
//

#include "SipSession.h"

static std::mutex g_instanceMapMtx;
static std::map<void* ,std::weak_ptr<SipSession>> g_instanceMap;

static std::shared_ptr<SipSession> getInstance(void * p){
    std::lock_guard<std::mutex> lck(g_instanceMapMtx);
    if(g_instanceMap.find(p) != g_instanceMap.end()){
        return g_instanceMap[p].lock();
    }
    return {};
}

int SipSession::buildDefaultResp(osip_message_t **dest, osip_dialog_t *dialog, int status, osip_message_t *request) {
    osip_generic_param_t *tag;
    osip_message_t *response;
    int i;

    *dest = nullptr;

    if (request == nullptr)
        return OSIP_BADPARAMETER;

    i = osip_message_init(&response);

    if (i != 0)
        return i;

    /* initialise osip_message_t structure */
    /* yet done... */

    response->sip_version = (char *) osip_malloc(8 * sizeof(char));

    if (response->sip_version == nullptr) {
        osip_message_free(response);
        return OSIP_NOMEM;
    }

    sprintf(response->sip_version, "SIP/2.0");
    osip_message_set_status_code(response, status);

    /* handle some internal reason definitions. */
    if (MSG_IS_NOTIFY(request) && status == 481) {
        response->reason_phrase = osip_strdup("Subscription Does Not Exist");

    } else if (MSG_IS_SUBSCRIBE(request) && status == 202) {
        response->reason_phrase = osip_strdup("Accepted subscription");

    } else {
        response->reason_phrase = osip_strdup(osip_message_get_reason(status));

        if (response->reason_phrase == nullptr) {
            if (response->status_code == 101)
                response->reason_phrase = osip_strdup("Dialog Establishement");

            else
                response->reason_phrase = osip_strdup("Unknown code");
        }

        response->req_uri = nullptr;
        response->sip_method = nullptr;
    }


    if (response->reason_phrase == nullptr) {
        osip_message_free(response);
        return OSIP_NOMEM;
    }

    i = osip_to_clone(request->to, &(response->to));

    if (i != 0) {
        osip_message_free(response);
        return i;
    }

    i = osip_to_get_tag(response->to, &tag);

    if (i != 0) { /* we only add a tag if it does not already contains one! */
        if ((dialog != nullptr) && (dialog->local_tag != nullptr))
            /* it should contain the local TAG we created */
        {
            osip_to_set_tag(response->to, osip_strdup(dialog->local_tag));

        } else {
            if (status != 100){
                auto tagStr = strdup(toolkit::makeRandStr(32, true).c_str());
                osip_to_set_tag(response->to, tagStr);
            }
        }
    }

    i = osip_from_clone(request->from, &(response->from));

    if (i != 0) {
        osip_message_free(response);
        return i;
    }

    {
        osip_list_iterator_t it;
        auto *via = (osip_via_t *) osip_list_get_first(&request->vias, &it);

        while (via != nullptr) {
            osip_via_t *via2;

            i = osip_via_clone(via, &via2);

            if (i != 0) {
                osip_message_free(response);
                return i;
            }

            osip_list_add(&response->vias, via2, -1);
            via = (osip_via_t *) osip_list_get_next(&it);
        }
    }

    i = osip_call_id_clone(request->call_id, &(response->call_id));

    if (i != 0) {
        osip_message_free(response);
        return i;
    }

    i = osip_cseq_clone(request->cseq, &(response->cseq));

    if (i != 0) {
        osip_message_free(response);
        return i;
    }


    if (MSG_IS_SUBSCRIBE(request)) {
        osip_header_t *exp;
        osip_header_t *evt_hdr;

        osip_message_header_get_byname(request, "event", 0, &evt_hdr);

        if (evt_hdr != nullptr && evt_hdr->hvalue != nullptr)
            osip_message_set_header(response, "Event", evt_hdr->hvalue);

        else
            osip_message_set_header(response, "Event", "presence");

        i = osip_message_get_expires(request, 0, &exp);

        if (exp == nullptr) {
            osip_header_t *cp;

            i = osip_header_clone(exp, &cp);

            if (cp != nullptr)
                osip_list_add(&response->headers, cp, 0);
        }
    }
    osip_message_set_user_agent(response, "UA");

    *dest = response;
    return OSIP_SUCCESS;
}

void SipSession::onRecv(const toolkit::Buffer::Ptr &buf) {
    std::weak_ptr<SipSession> wInstance = std::dynamic_pointer_cast<SipSession>(shared_from_this());
    {
        std::lock_guard<std::mutex> lck(g_instanceMapMtx);
        if(g_instanceMap.find(this) == g_instanceMap.end()){
            g_instanceMap[this] = wInstance;
            getPoller()->doDelayTask(1,[wInstance](){
                auto sThis = wInstance.lock();
                if(sThis){
                    osip_ict_execute(sThis->m_sipCtx.get());
                    osip_ist_execute(sThis->m_sipCtx.get());
                    osip_nict_execute(sThis->m_sipCtx.get());
                    osip_nist_execute(sThis->m_sipCtx.get());
                    return true;
                }
                return false;
            });
        }
    }

    auto event = osip_parse(buf->data(),buf->size());
    if(!event){
        return;
    }
    auto ret = osip_find_transaction_and_add_event(m_sipCtx.get(),event);
    if(ret == OSIP_UNDEFINED_ERROR){
        auto transaction = osip_create_transaction(m_sipCtx.get(),event);
        osip_transaction_set_your_instance(transaction, this);
        osip_transaction_add_event(transaction,event);
    }
}

void SipSession::onError(const toolkit::SockException &err) {
    ErrorL<<err.what();
}

void SipSession::onManager() {
}

SipSession::SipSession(const toolkit::Socket::Ptr &sock) : Session(sock) {
    static auto getSipCtx = [](){
        osip * ctx{};
        osip_init(&ctx);
        return ctx;
    };
    m_sipCtx = std::shared_ptr<osip>(getSipCtx(),[](osip * ctx){
        osip_free(ctx);
    });
    auto defaultCb = [](int type, osip_transaction_t * t, osip_message_t * message){
        char *buf{};
        size_t len{};
        osip_message_to_str(message,&buf,&len);
        DebugL<<"recv:\n"<< buf;
        auto p = getInstance(osip_transaction_get_your_instance(t));
        if(!p){
            return ;
        }
        osip_message_t * resp;
        p->buildDefaultResp(&resp, nullptr,SIP_OK,message);

        auto evt = osip_new_outgoing_sipmessage(resp);
        evt->transactionid = t->transactionid;

        osip_transaction_add_event(t, evt);
        osip_free(buf);
    };
    auto transactionCb = [](int type, osip_transaction_t *){
        DebugL<<"transactionCb:"<<type;
    };
    auto transportErrorCb = [](int type, osip_transaction_t *, int error){
        DebugL<<"err:"<<type<<" code:"<<error;
    };
    // callback called when a SIP message must be sent.
    osip_set_cb_send_message(m_sipCtx.get(),[](osip_transaction_t * transaction, osip_message_t * message, char *, int,int){
        char *buf{};
        size_t len{};
        osip_message_to_str(message,&buf,&len);
        auto p = getInstance(osip_transaction_get_your_instance(transaction));
        if (p){
            DebugL<<"send:\n"<< buf;
            auto buffer = toolkit::BufferRaw::create();
            buffer->assign(buf, len);
            p->send(buffer);
        }else{
            WarnL<<"send fail,session released! msg:\n"<<buf;
            return OSIP_WRONG_STATE;
        }
        osip_free(buf);
        return OSIP_SUCCESS;
    });
    // callback called when a SIP transaction is TERMINATED.
    osip_set_kill_transaction_callback(m_sipCtx.get() , OSIP_ICT_KILL_TRANSACTION,transactionCb);
    osip_set_kill_transaction_callback(m_sipCtx.get() ,OSIP_NIST_KILL_TRANSACTION,transactionCb);
    osip_set_kill_transaction_callback(m_sipCtx.get() , OSIP_NICT_KILL_TRANSACTION,transactionCb);
    osip_set_kill_transaction_callback(m_sipCtx.get() ,OSIP_NIST_KILL_TRANSACTION,transactionCb);
    // callback called when the callback to send message have failed.
    osip_set_transport_error_callback(m_sipCtx.get() ,OSIP_ICT_TRANSPORT_ERROR,transportErrorCb);
    osip_set_transport_error_callback(m_sipCtx.get() ,OSIP_IST_TRANSPORT_ERROR,transportErrorCb);
    osip_set_transport_error_callback(m_sipCtx.get() ,OSIP_NICT_TRANSPORT_ERROR,transportErrorCb);
    osip_set_transport_error_callback(m_sipCtx.get() ,OSIP_NIST_TRANSPORT_ERROR,transportErrorCb);
    // callback called when a received answer has been accepted by the transaction.
    osip_set_message_callback(m_sipCtx.get() , OSIP_ICT_STATUS_1XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_ICT_STATUS_2XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_ICT_STATUS_3XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_ICT_STATUS_4XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_ICT_STATUS_5XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_ICT_STATUS_6XX_RECEIVED, defaultCb);
    // callback called when a received answer has been accepted by the transaction.
    osip_set_message_callback(m_sipCtx.get() , OSIP_NICT_STATUS_1XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NICT_STATUS_2XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NICT_STATUS_3XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NICT_STATUS_4XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NICT_STATUS_5XX_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NICT_STATUS_6XX_RECEIVED, defaultCb);
    // callback called when a received request has been accepted by the transaction.
    osip_set_message_callback(m_sipCtx.get() , OSIP_IST_INVITE_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_IST_ACK_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NIST_REGISTER_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NIST_BYE_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NIST_CANCEL_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NIST_INFO_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NIST_OPTIONS_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NIST_SUBSCRIBE_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NIST_NOTIFY_RECEIVED, defaultCb);
    osip_set_message_callback(m_sipCtx.get() , OSIP_NIST_UNKNOWN_REQUEST_RECEIVED, defaultCb);
}
