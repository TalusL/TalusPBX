//
// Created by Talus on 2023/7/16.
//

#include "SipSession.h"
#include "Util/NoticeCenter.h"
#include "Util/MD5.h"

static std::mutex g_instanceMapMtx;
static std::map<void* ,std::weak_ptr<SipSession>> g_instanceMap;

int request_add_via(osip_message_t *request) {
    char tmp[200];
    

    if (request == nullptr)
        return OSIP_BADPARAMETER;

    if (request->call_id == nullptr)
        return OSIP_SYNTAXERROR;


    snprintf(tmp, 200, "SIP/2.0/%s 999.999.999.999:99999;rport;branch=z9hG4bK%u", "UDP", osip_build_random_number());
    

    osip_message_set_via(request, tmp);

    return OSIP_SUCCESS;
}

int generating_request_out_of_dialog(osip_message_t **dest, const char *method, const char *to, const char *from, const char *proxy) {
    /* Section 8.1:
       A valid request contains at a minimum "To, From, Call-iD, Cseq,
       Max-Forwards and Via
     */
    int i;
    osip_message_t *request;
    int doing_register;

    *dest = nullptr;

    if (!method || !*method)
        return OSIP_BADPARAMETER;


    i = osip_message_init(&request);

    if (i != 0)
        return i;

    /* prepare the request-line */
    osip_message_set_method(request, osip_strdup(method));
    osip_message_set_version(request, osip_strdup("SIP/2.0"));
    osip_message_set_status_code(request, 0);
    osip_message_set_reason_phrase(request, nullptr);

    doing_register = 0 == strcmp("REGISTER", method);

    if (doing_register) {
        i = osip_uri_init(&(request->req_uri));

        if (i != 0) {
            osip_message_free(request);
            return i;
        }

        i = osip_uri_parse(request->req_uri, proxy);

        if (i != 0) {
            osip_message_free(request);
            return i;
        }

        i = osip_message_set_to(request, from);

        if (i != 0 || request->to == nullptr) {
            if (i >= 0)
                i = OSIP_SYNTAXERROR;

            osip_message_free(request);
            return i;
        }

        /* REMOVE ALL URL PARAMETERS from to->url headers and add them as headers */
        if (request->to != nullptr && request->to->url != nullptr) {
            osip_uri_t *url = request->to->url;

            while (osip_list_size(&url->url_headers) > 0) {
                osip_uri_header_t *u_header;

                u_header = (osip_uri_param_t *) osip_list_get(&url->url_headers, 0);

                if (u_header == nullptr)
                    break;

                if (osip_strcasecmp(u_header->gname, "from") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "to") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "call-id") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "cseq") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "via") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "contact") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "route") == 0) {
                    osip_message_set_route(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "call-info") == 0) {
                    osip_message_set_call_info(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "accept") == 0) {
                    osip_message_set_accept(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "accept-encoding") == 0) {
                    osip_message_set_accept_encoding(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "accept-language") == 0) {
                    osip_message_set_accept_language(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "alert-info") == 0) {
                    osip_message_set_alert_info(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "allow") == 0) {
                    osip_message_set_allow(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "content-type") == 0) {
                    osip_message_set_content_type(request, u_header->gvalue);

                } else
                    osip_message_set_header(request, u_header->gname, u_header->gvalue);

                osip_list_remove(&url->url_headers, 0);
                osip_uri_param_free(u_header);
            }
        }

    } else {
        /* in any cases except REGISTER: */
        i = osip_message_set_to(request, to);

        if (i != 0 || request->to == nullptr) {
            if (i >= 0)
                i = OSIP_SYNTAXERROR;

            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, nullptr, "[eXosip] callee address does not seems to be a sipurl: [%s]\n", to));
            osip_message_free(request);
            return i;
        }

        /* REMOVE ALL URL PARAMETERS from to->url headers and add them as headers */
        if (request->to != nullptr && request->to->url != nullptr) {
            osip_uri_t *url = request->to->url;

            while (osip_list_size(&url->url_headers) > 0) {
                osip_uri_header_t *u_header;

                u_header = (osip_uri_param_t *) osip_list_get(&url->url_headers, 0);

                if (u_header == nullptr)
                    break;

                if (osip_strcasecmp(u_header->gname, "from") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "to") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "call-id") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "cseq") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "via") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "contact") == 0) {
                } else if (osip_strcasecmp(u_header->gname, "route") == 0) {
                    osip_message_set_route(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "call-info") == 0) {
                    osip_message_set_call_info(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "accept") == 0) {
                    osip_message_set_accept(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "accept-encoding") == 0) {
                    osip_message_set_accept_encoding(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "accept-language") == 0) {
                    osip_message_set_accept_language(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "alert-info") == 0) {
                    osip_message_set_alert_info(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "allow") == 0) {
                    osip_message_set_allow(request, u_header->gvalue);

                } else if (osip_strcasecmp(u_header->gname, "content-type") == 0) {
                    osip_message_set_content_type(request, u_header->gvalue);

                } else
                    osip_message_set_header(request, u_header->gname, u_header->gvalue);

                osip_list_remove(&url->url_headers, 0);
                osip_uri_param_free(u_header);
            }
        }

        if (proxy != nullptr && proxy[0] != 0) { /* equal to a pre-existing route set */
            /* if the pre-existing route set contains a "lr" (compliance
               with bis-08) then the req_uri should contains the remote target
               URI */
            osip_uri_param_t *lr_param;
            osip_route_t *o_proxy;

            osip_route_init(&o_proxy);
            i = osip_route_parse(o_proxy, proxy);

            if (i != 0) {
                osip_route_free(o_proxy);
                osip_message_free(request);
                return i;
            }

            osip_uri_uparam_get_byname(o_proxy->url, "lr", &lr_param);

            if (lr_param != nullptr) { /* to is the remote target URI in this case! */
                i = osip_uri_clone(request->to->url, &(request->req_uri));

                if (i != 0) {
                    osip_route_free(o_proxy);
                    osip_message_free(request);
                    return i;
                }

                /* "[request] MUST includes a Route header field containing
                   the route set values in order." */
                osip_list_add(&request->routes, o_proxy, 0);

            } else
                /* if the first URI of route set does not contain "lr", the req_uri
                   is set to the first uri of route set */
            {
                request->req_uri = o_proxy->url;
                o_proxy->url = nullptr;
                osip_route_free(o_proxy);
                /* add the route set */
                /* "The UAC MUST add a route header field containing
                   the remainder of the route set values in order.
                   The UAC MUST then place the remote target URI into
                   the route header field as the last value
                 */
                osip_message_set_route(request, to);
            }

        } else { /* No route set (outbound proxy) is used */

            /* The UAC must put the remote target URI (to field) in the req_uri */
            i = osip_uri_clone(request->to->url, &(request->req_uri));

            if (i != 0) {
                osip_message_free(request);
                return i;
            }
        }
    }

    /* set To and From */
    i = osip_message_set_from(request, from);

    if (i != 0 || request->from == nullptr) {
        if (i >= 0)
            i = OSIP_SYNTAXERROR;

        osip_message_free(request);
        return i;
    }

    /* REMOVE ALL URL PARAMETERS from from->url headers and add them as headers */
    if (doing_register && request->from != nullptr && request->from->url != nullptr) {
        osip_uri_t *url = request->from->url;

        while (osip_list_size(&url->url_headers) > 0) {
            osip_uri_header_t *u_header;

            u_header = (osip_uri_param_t *) osip_list_get(&url->url_headers, 0);

            if (u_header == nullptr)
                break;

            osip_list_remove(&url->url_headers, 0);
            osip_uri_param_free(u_header);
        }
    }

    if (request->to != nullptr && request->to->url != nullptr) {
        osip_list_iterator_t it;
        osip_uri_param_t *u_param = (osip_uri_param_t *) osip_list_get_first(&request->to->url->url_params, &it);

        while (u_param != nullptr) {
            if (u_param->gvalue != nullptr && u_param->gname != nullptr && osip_strcasecmp(u_param->gname, "method") == 0) {
                osip_list_iterator_remove(&it);
                osip_uri_param_free(u_param);
                break;
            }

            u_param = (osip_uri_param_t *) osip_list_get_next(&it);
        }
    }

    if (request->from != nullptr && request->from->url != nullptr) {
        osip_list_iterator_t it;
        osip_uri_param_t *u_param = (osip_uri_param_t *) osip_list_get_first(&request->from->url->url_params, &it);

        while (u_param != nullptr) {
            if (u_param->gvalue != nullptr && u_param->gname != nullptr && osip_strcasecmp(u_param->gname, "method") == 0) {
                osip_list_iterator_remove(&it);
                osip_uri_param_free(u_param);
                break;
            }

            u_param = (osip_uri_param_t *) osip_list_get_next(&it);
        }
    }

    if (request->req_uri) {
        osip_list_iterator_t it;
        osip_uri_param_t *u_param = (osip_uri_param_t *) osip_list_get_first(&request->req_uri->url_params, &it);

        while (u_param != nullptr) {
            if (u_param->gvalue != nullptr && u_param->gname != nullptr && osip_strcasecmp(u_param->gname, "method") == 0) {
                osip_list_iterator_remove(&it);
                osip_uri_param_free(u_param);
                break;
            }

            u_param = (osip_uri_param_t *) osip_list_get_next(&it);
        }
    }

    /* add a tag */
    osip_from_set_tag(request->from, strdup(toolkit::makeRandStr(32, true).c_str()));

    /* set the cseq and call_id header */
    {
        osip_call_id_t *callid;
        osip_cseq_t *cseq;
        char *num;
        char *cidrand;

        /* call-id is always the same for REGISTRATIONS */
        i = osip_call_id_init(&callid);

        if (i != 0) {
            osip_message_free(request);
            return i;
        }

        cidrand = strdup(toolkit::makeRandStr(32, true).c_str());;
        osip_call_id_set_number(callid, cidrand);

        request->call_id = callid;

        i = osip_cseq_init(&cseq);

        if (i != 0) {
            osip_message_free(request);
            return i;
        }

        num = osip_strdup(doing_register ? "1" : "20");
        osip_cseq_set_number(cseq, num);
        osip_cseq_set_method(cseq, osip_strdup(method));
        request->cseq = cseq;

        if (cseq->method == nullptr || cseq->number == nullptr) {
            osip_message_free(request);
            return OSIP_NOMEM;
        }
    }

    i = request_add_via(request);

    if (i != 0) {
        osip_message_free(request);
        return i;
    }

    /* always add the Max-Forward header */
    osip_message_set_max_forwards(request, "70"); /* a UA should start a request with 70 */

    if (0 == strcmp("REGISTER", method)) {
    } else if (0 == strcmp("INFO", method)) {
    } else if (0 == strcmp("OPTIONS", method)) {
        osip_message_set_accept(request, "application/sdp");
    }

    /*  else if ... */
    *dest = request;
    return OSIP_SUCCESS;
}


int SipSession::BuildRequest( osip_message_t **message, const char *method, const char *to,
        const char *from, const char *route) {
    int i;

    *message = nullptr;

    if (method != nullptr && *method == '\0')
        return OSIP_BADPARAMETER;

    if (to != nullptr && *to == '\0')
        return OSIP_BADPARAMETER;

    if (from != nullptr && *from == '\0')
        return OSIP_BADPARAMETER;

    if (route != nullptr && *route == '\0')
        route = nullptr;

    i = generating_request_out_of_dialog(message, method, to, from, route);

    if (i != 0)
        return i;

    return OSIP_SUCCESS;
}

int SipSession::BuildDefaultResp(osip_message_t **dest, osip_dialog_t *dialog, int status, osip_message_t *request) {
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
                    return 1;
                }
                return 0;
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
        osip_free(buf);

        auto p = SipSession::GetSipInstance(osip_transaction_get_your_instance(t));
        if(!p) {
            return ;
        }
        p->onSipMsgEvent(type,t,message);
    };
    auto transactionCb = [](int type, osip_transaction_t * transaction){
        DebugL<<"transactionCb:"<<type;
        auto p = SipSession::GetSipInstance(osip_transaction_get_your_instance(transaction));
        if(!p) {
            return ;
        }
        p->onSipTransactionEvent(type,transaction);
    };
    auto transportErrorCb = [](int type, osip_transaction_t * t, int error){
        DebugL<<"err:"<<type<<" code:"<<error;
        auto p = SipSession::GetSipInstance(osip_transaction_get_your_instance(t));
        if(!p) {
            return ;
        }
        p->onSipTransportError(type,t,error);
    };
    // callback called when a SIP message must be sent.
    osip_set_cb_send_message(m_sipCtx.get(),[](osip_transaction_t * transaction, osip_message_t * message, char *, int,int){
        char *buf{};
        size_t len{};
//        osip_message_set_user_agent(message, "UA");
        osip_message_to_str(message,&buf,&len);
        auto p = GetSipInstance(osip_transaction_get_your_instance(transaction));
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

std::shared_ptr<SipSession> SipSession::GetSipInstance(void *p) {
    std::lock_guard<std::mutex> lck(g_instanceMapMtx);
    if(g_instanceMap.find(p) != g_instanceMap.end()){
        return g_instanceMap[p].lock();
    }
    return {};
}

int SipSession::Response(osip_transaction_t *t, int status, const mediakit::StrCaseMap &header,
                          const std::string &contentType, const std::string &body) {
    osip_message_t *response;
    auto ret = BuildDefaultResp(&response, nullptr,status,t->orig_request);
    if(ret!=OSIP_SUCCESS){
        return ret;
    }
    for (const auto &item: header){
        osip_message_set_header(response, strdup(item.first.c_str()), strdup(item.second.c_str()));
    }
    if(!contentType.empty()&&!body.empty()){
        osip_message_set_body_mime(response, strdup(contentType.c_str()),contentType.size());
        osip_message_set_body(response, strdup(body.c_str()),body.size());
    }

    auto evt = osip_new_outgoing_sipmessage(response);
    evt->transactionid = t->transactionid;

    osip_transaction_add_event(t, evt);

    return OSIP_SUCCESS;
}

int SipSession::SendMsg(osip_message_t * req) {
    auto event = osip_new_outgoing_sipmessage(req);
    auto transaction = osip_create_transaction(m_sipCtx.get(),event);
    osip_transaction_set_your_instance(transaction, this);
    return osip_transaction_add_event(transaction,event);;
}

