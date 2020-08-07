/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2013-2020 Ging
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <srs_app_rtc_native.hpp>

#include <unistd.h>
#include <string>

#include <srs_app_rtc_conn.hpp>
#include <srs_app_server.hpp>
#include <srs_core_autofree.hpp>
#include <srs_service_st.hpp>
#include <srs_app_config.hpp>
#include <srs_app_rtc_server.hpp>
#include <srs_app_rtc_source.hpp>
#include <srs_kernel_rtc_rtcp.hpp>
#include <srs_app_rtc_native_signaling.hpp>
#include <srs_http_stack.hpp>
#include <srs_kernel_utility.hpp>


#define SRS_TICKID_CHECK_STATE      0
#define SRS_TICKID_HEARTBEAT        1


static bool is_dtls(const uint8_t* data, size_t len)
{
    return (len >= 13 && (data[0] > 19 && data[0] < 64));
}

static bool is_rtp_or_rtcp(const uint8_t* data, size_t len)
{
    return (len >= 12 && (data[0] & 0xC0) == 0x80);
}

static bool is_rtcp(const uint8_t* data, size_t len)
{
    return (len >= 12) && (data[0] & 0x80) && (data[1] >= 200 && data[1] <= 209);
}

srs_error_t SrsRtcNativeSession::parse_signaling(char *data, int nb_data, SrsRtcNativeHeader **msg)
{
    srs_error_t err = srs_success;
    
    SrsBuffer *buf = new SrsBuffer(data, nb_data);
    SrsAutoFree(SrsBuffer, buf);

    SrsRtcpApp *app = new SrsRtcpApp();
    SrsAutoFree(SrsRtcpApp, app);

    if ((err = app->decode(buf)) != srs_success) {
        return srs_error_wrap(err, "parse_signaling");
    }
    
    uint8_t *payload = NULL;
    int nn_payload = 0;
    if ((err = app->get_payload(payload, nn_payload)) != srs_success) {
        return srs_error_wrap(err, "no payload");
    }
    if (nn_payload <= 2) {
        return srs_error_new(ERROR_RTC_NATIVE_DECODE, "no payload");
    }

    SrsRtcNativeHeader *header = NULL;
    uint8_t msg_type = get_msg_type(payload);
    if (msg_type == SrsRTCNativeMsgType_temp_resp) {
        header = new SrsRtcNativeTempResponse();
    } else if (msg_type == SrsRTCNativeMsgType_final_ack) {
        header = new SrsRtcNativeFinalAck();
    } else if (msg_type == SrsRTCNativeMsgType_request) {
        switch (app->get_subtype()) {
            case SrsRTCNativeSubTypePublish: {
                header = new SrsRtcNativePublishRequest();
            } break;
            case SrsRTCNativeSubTypeSubscribe: {
                header = new SrsRtcNativeSubscribeRequest();
            } break;
            case SrsRTCNativeSubTypePublishUpadte: {
                header = new SrsRtcNativePublishUpdateRequest();
            } break;
            case SrsRTCNativeSubTypeSubscribeUpdate: {
                header = new SrsRtcNativeSubscribeUpdateRequest();
            } break;
            case SrsRTCNativeSubTypeStop: {
                header = new SrsRtcNativeStopRequest();
            } break;
            case SrsRTCNativeSubTypeDisconnect: {
                header = new SrsRtcNativeDisconnectRequest();
            } break;
            case SrsRTCNativeSubTypeHeartbeat: {
                header = new SrsRtcNativeHeartbeatRequest();
            } break;
            case SrsRTCNativeSubTypeMediaControl: {
                header = new SrsRtcNativeMediaControlRequest();
            } break;
            case SrsRTCNativeSubTypeNotify: {
                header = new SrsRtcNativeNotifyRequest();
            } break;
            case SrsRTCNativeSubTypeSwitchMSID: {
                header = new SrsRtcNativeSwitchMsidRequest();
            } break;
            default: break;
        }
    } else if (msg_type == SrsRTCNativeMsgType_final_resp) {
        switch (app->get_subtype()) {
            case SrsRTCNativeSubTypePublish: {
                header = new SrsRtcNativePublishResponse();
            } break;
            case SrsRTCNativeSubTypeSubscribe: {
                header = new SrsRtcNativeSubscribeResponse();
            } break;
            case SrsRTCNativeSubTypePublishUpadte: {
                header = new SrsRtcNativePublishUpdateResponse();
            } break;
            case SrsRTCNativeSubTypeSubscribeUpdate: {
                header = new SrsRtcNativeSubscribeUpdateResponse();
            } break;
            case SrsRTCNativeSubTypeStop: {
                header = new SrsRtcNativeStopResponse();
            } break;
            case SrsRTCNativeSubTypeDisconnect: {
                header = new SrsRtcNativeDisconnectResponse();
            } break;
            case SrsRTCNativeSubTypeHeartbeat: {
                header = new SrsRtcNativeHeartbeatResponse();
            } break;
            case SrsRTCNativeSubTypeMediaControl: {
                header = new SrsRtcNativeMediaControlReponse();
            } break;
            case SrsRTCNativeSubTypeNotify: {
                header = new SrsRtcNativeNotifyResponse();
            } break;
            case SrsRTCNativeSubTypeSwitchMSID: {
                header = new SrsRtcNativeSwitchMsidResponse();
            } break;
            default: break;
        }
    }

    if (!header) {
        return srs_error_new(ERROR_RTC_NATIVE_DECODE, "sub_type=%u msg_type=%u not support",
                app->get_subtype(), msg_type);
    }

    header->set_subtype(app->get_subtype());
    header->set_name(app->get_name());

    SrsBuffer *buf_msg = new SrsBuffer((char*)payload, nn_payload);
    SrsAutoFree(SrsBuffer, buf_msg);
    if ((err = header->decode(buf_msg)) != srs_success) {
        srs_freep(header);
        return srs_error_wrap(err, "parse signaling");
    }

    *msg = header;

    return err;
}

srs_error_t SrsRtcNativeSession::parse_url(const std::string &url, SrsRequest **request)
{
     srs_error_t err = srs_success;
    SrsHttpUri uri;
    if ((err = uri.initialize(url)) != srs_success) {
        return srs_error_wrap(err, "convert url to request");
    }

    std::vector<std::string> path = srs_string_split(uri.get_path(), std::string("/"));

    if (path.size() != 2) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "invalid url");
    }

    SrsRequest *req = new SrsRequest();
    req->app = uri.get_host() + ":" + path[0];
    req->stream = path[1];
    SrsConfDirective* parsed_vhost = _srs_config->get_vhost(uri.get_host());
    if (parsed_vhost) {
        req->vhost = parsed_vhost->arg0();
    }
    *request = req;

    return err;
}

const int SrsRtcNativeSession::RETRY_INTERVAL[] = {
    SRS_UTIME_SECONDS,
    SRS_UTIME_SECONDS * 2,
    SRS_UTIME_SECONDS * 4,
    SRS_UTIME_SECONDS * 8,
};

int SrsRtcNativeSession::get_retry_interval(int retry_count)
{
    int interval_count = sizeof(SrsRtcNativeSession::RETRY_INTERVAL) / sizeof(int);
    int idx = retry_count;
    if (retry_count < 0 || retry_count >= interval_count) {
        idx = interval_count - 1;
    }
    
    return SrsRtcNativeSession::RETRY_INTERVAL[idx];
}

SrsRtcNativeSession::SrsRtcNativeSession(SrsRtcServer* server, SrsRtcNativeSessionRole role, bool encrypt)
        : role_(role), encrypt_(encrypt), start_us_(srs_get_system_time()), connect_msg_id_(0)
{
    cid_ = _srs_context->generate_id("sid");
    _srs_context->bind(cid_, "rtc native create session");

    state_      = SrsRtcNativeSession::STATE_INIT;
    timer_      = NULL;
    listener_   = NULL;
    udp_socket_ = NULL;
    msg_id_     = 0;
    rtc_        = server;

    conn_ = new SrsRtcConnection(SrsRtcNativeSession::rtc_, cid_);

    conn_->set_hijacker(this);
}

SrsRtcNativeSession::SrsRtcNativeSession(SrsRtcServer* server, const std::string &server_ip, int server_port, bool encrypt)
        : role_(SrsRtcNativeSession::ROLE_CLIENT), encrypt_(encrypt), start_us_(srs_get_system_time())
{
    new (this)SrsRtcNativeSession(server, SrsRtcNativeSession::ROLE_CLIENT, encrypt);
    
    server_ip_   = server_ip;
    server_port_ = server_port;
}

SrsRtcNativeSession::~SrsRtcNativeSession()
{
    this->stop();

    for (CallIterator it = publish_calls_.begin(); it != publish_calls_.end(); it++) {
        srs_freep(it->second);
    }
    publish_calls_.clear();

    for (CallIterator it = subscribe_calls_.begin(); it != subscribe_calls_.end(); it++) {
        srs_freep(it->second);
    }
    subscribe_calls_.clear();
}

srs_error_t SrsRtcNativeSession::start() {
    srs_error_t err = srs_success;

    if (timer_) {
        return err;
    }

    timer_ = new SrsHourGlass(this, SESSION_TIMER_INTERVAL);
    
    if ((err = timer_->tick(SRS_TICKID_CHECK_STATE, SESSION_TIMER_INTERVAL)) != srs_success) {
        return srs_error_wrap(err, "native session");
    }

    if (role_ == SrsRtcNativeSession::ROLE_CLIENT) {
        if ((err = timer_->tick(SRS_TICKID_HEARTBEAT, SESSION_HEARTBEAT_INTERVAL)) != srs_success) {
            return srs_error_wrap(err, "native session");
        }

        std::string ip = srs_any_address_for_listener();
        listener_ = new SrsUdpMuxListener(this, ip, 0);

        if ((err = listener_->listen()) != srs_success) {
            srs_freep(listener_);
            return srs_error_wrap(err, "listen %s:0", ip.c_str());
        }
        srs_netfd_t fd = listener_->stfd();
        udp_socket_ = new SrsUdpMuxSocket(fd);
        if ((err = udp_socket_->set_peer_addr(server_ip_, server_port_)) != srs_success) {
            srs_freep(udp_socket_);
            return srs_error_wrap(err, "parse addr %s:%u", server_ip_.c_str(), server_port_);
        }
        conn_->update_sendonly_socket(udp_socket_);
    }

    if ((err = timer_->start()) != srs_success) {
        return srs_error_wrap(err, "native session");
    }

    SrsRequest req;
    if ((err = conn_->initialize(&req, true, encrypt_, encrypt_, "")) != srs_success) {
        return srs_error_wrap(err, "native session");
    }

    if (encrypt_) {
        if ((err = conn_->start_dtls_handshake()) != srs_success) {
            return srs_error_wrap(err, "native session");
        }
        if ((err == update_state(SrsRtcNativeSession::STATE_DTLS)) != srs_success) {
            return srs_error_wrap(err, "session state");
        }
    }

    return err;
}

void SrsRtcNativeSession::stop()
{
    srs_error_t err = srs_success;
    if (state_ == SrsRtcNativeSession::STATE_CONNECTED) {
        SrsRtcNativeDisconnectRequest *request = new SrsRtcNativeDisconnectRequest();
        SrsAutoFree(SrsRtcNativeDisconnectRequest, request);
        request->set_msg_id(gen_new_msg_id());
        request->set_code(200);
        request->set_msg("NORMAL CLEARING");
        if ((err = send_signaling(request)) != srs_success) {
            srs_freep(err);
        }
    }
    if (state_ <= SrsRtcNativeSession::STATE_CONNECTED) {
        update_state(SrsRtcNativeSession::STATE_CLOSED); // safe update, no error return
    }

    srs_freep(timer_);
    
    if (conn_) {
        conn_->set_hijacker(NULL);
        rtc_->destroy(conn_);
        conn_ = NULL;
    }
    
    srs_freep(listener_);
    srs_freep(udp_socket_);
}

bool SrsRtcNativeSession::is_alive()
{
    return state_ <= SrsRtcNativeSession::STATE_CONNECTED;
}

srs_error_t SrsRtcNativeSession::publish(const std::string &url, SrsRtcNativeClientPublishCall **call)
{
    srs_error_t err = srs_success;

    SrsRequest *req = NULL;
    SrsAutoFree(SrsRequest, req);
    if ((err = SrsRtcNativeSession::parse_url(url, &req)) != srs_success) {
        return srs_error_wrap(err, "process url");
    }
    std::string stream_url = req->get_stream_url();

    CallIterator it = publish_calls_.find(stream_url);
    if (it != publish_calls_.end()) {
        return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, "%s already published", stream_url.c_str());
    }

    SrsRtcNativeClientPublishCall *c = new SrsRtcNativeClientPublishCall(this, url);
    if ((err = c->start()) != srs_success) {
        return srs_error_wrap(err, "publish start");
    }
    
    publish_calls_[stream_url] = c;
    *call = c;

    return srs_success;
}

srs_error_t SrsRtcNativeSession::subscribe(const std::string &url, SrsRtcNativeClientSubscribeCall **call)
{
    srs_error_t err = srs_success;
    
    SrsRequest *req = NULL;
    SrsAutoFree(SrsRequest, req);
    if ((err = SrsRtcNativeSession::parse_url(url, &req)) != srs_success) {
        return srs_error_wrap(err, "process url");
    }
    std::string stream_url = req->get_stream_url();

    CallIterator it = subscribe_calls_.find(stream_url);
    if (it != subscribe_calls_.end()) {
        return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, "%s already subscribed", stream_url.c_str());
    }

    SrsRtcNativeClientSubscribeCall *c = new SrsRtcNativeClientSubscribeCall(this, url);
    if ((err = c->start()) != srs_success) {
        return srs_error_wrap(err, "subscribe start");
    }
    
    subscribe_calls_[stream_url] = c;
    *call = c;

    return srs_success;
}

const SrsContextId& SrsRtcNativeSession::get_cid()
{
    return cid_;
}

uint16_t SrsRtcNativeSession::gen_new_msg_id()
{
    return ++msg_id_;
}

SrsRtcConnection* SrsRtcNativeSession::get_rtc_connection()
{
    return conn_;
}

srs_error_t SrsRtcNativeSession::on_signaling(char* data, int nb_data)
{
    if (state_ > SrsRtcNativeSession::STATE_CONNECTED) {
        return srs_success;
    }

    srs_error_t err = srs_success;
    SrsRtcNativeHeader *msg = NULL;
    if ((err = SrsRtcNativeSession::parse_signaling(data, nb_data, &msg)) != srs_success) {
        return srs_error_wrap(err, "signaling");
    }

    SrsAutoFree(SrsRtcNativeHeader, msg);
    return process_signaling(msg);
}

srs_error_t SrsRtcNativeSession::process_signaling(SrsRtcNativeHeader *msg) {

    //TODO: print all signaling info
    if (msg->get_subtype() != SrsRTCNativeSubTypeHeartbeat) {
        srs_trace("RTC: recv signaling : signaling=%s type=%u id=%u",
                msg->get_name().c_str(), msg->get_msg_type(), msg->get_msg_id());
    }

    // process all (request,tmp response, reponse, ack)
    if (msg->get_subtype() == SrsRTCNativeSubTypeConnect) {
        return process_connect(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeDisconnect) {
        return process_disconnect(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeMTUDetect) {
        return process_mtu_detect(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeMTUDetectPacketEnd) {
        return process_mtu_detect(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeNotify) {
        return process_notify(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeWanSwitched) {
        return process_wan_ip_port_switch(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeHeartbeat) {
        return process_heartbeat(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeStop) {
        return process_stop(msg);
    }
    
    // process response
    if (msg->get_msg_type() == SrsRTCNativeMsgType_temp_resp) {
        return process_temp_response(msg);
    } else if (msg->get_msg_type() == SrsRTCNativeMsgType_final_resp) {
        return process_response(msg);
    } else if (msg->get_msg_type() == SrsRTCNativeMsgType_final_ack) {
        return process_final_ack(msg);
    }

    // process request
    if (msg->get_subtype() == SrsRTCNativeSubTypePublish) {
        return process_publish_request(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribe) {
        return process_subscribe_request(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypePublishUpadte) {
        return process_publish_update_request(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribeUpdate) {
        return process_subscribe_update_request(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSwitchMSID) {
        return process_switch_stream_request(msg);
    } 

    return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM,
        "signal=%s type=%u not support", msg->get_name().c_str(), msg->get_msg_type());
}

srs_error_t SrsRtcNativeSession::send_signaling(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;
    if (!conn_) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, "connection not found");
    }

    //TODO: print all signaling info
    if (msg->get_subtype() != SrsRTCNativeSubTypeHeartbeat) {
        srs_trace("RTC: send signaling : signaling=%s type=%u id=%u",
                msg->get_name().c_str(), msg->get_msg_type(), msg->get_msg_id());
    }

    char data[kRtcpPacketSize];
    SrsBuffer *buf = new SrsBuffer(data, sizeof(data));
    SrsAutoFree(SrsBuffer, buf);
    if ((err = msg->encode(buf)) != srs_success) {
        return srs_error_wrap(err, "send_signaling");
    }

    SrsRtcpApp *app = new SrsRtcpApp();
    SrsAutoFree(SrsRtcpApp, app);
    app->set_ssrc(0);
    app->set_subtype(msg->get_subtype());
    app->set_name(msg->get_name());
    app->set_payload((uint8_t*)buf->data(), buf->pos());

    SrsBuffer *rtcp_buf = new SrsBuffer(data, sizeof(data));
    SrsAutoFree(SrsBuffer, rtcp_buf);

    if ((err = app->encode(rtcp_buf)) != srs_success) {
        return srs_error_wrap(err, "send_signaling");   
    }

    if ((err = conn_->send_rtcp(rtcp_buf->data(), rtcp_buf->pos())) != srs_success) {
        return srs_error_wrap(err, "send_signaling");   
    }

    return err;
}

srs_error_t SrsRtcNativeSession::check_state()
{
    srs_error_t err = srs_success;
    srs_utime_t now = srs_get_system_time();
    // process session state
    if (state_ == SrsRtcNativeSession::STATE_CONNECTED) {
        if (last_heartbeat_us_ + SrsRtcNativeSession::SESSION_DEFAULT_TIMEOUT_US < now) {
            update_state(SrsRtcNativeSession::STATE_TIMEOUT); //safe update, no error return
        }
    } else if (state_ < SrsRtcNativeSession::STATE_CONNECTED) {
        if (start_us_ + SrsRtcNativeSession::SESSION_DEFAULT_TIMEOUT_US < now) {
            update_state(SrsRtcNativeSession::STATE_TIMEOUT); //safe update, no error return
        }
    }

    // session will clear by SrsRtcNativeSessionManger
    if (state_ > SrsRtcNativeSession::STATE_CONNECTED) {
        return srs_success;
    }

    SrsRtcNativeCall *call = NULL;
    SrsRtcNativeCall::SrsRtcNativeCallState state = SrsRtcNativeCall::STATE_NONE;
    CallIterator it = publish_calls_.begin();
    while (it != publish_calls_.end()) {
        call = it->second;
        if (( err = call->check_state(state)) != srs_success) {
            publish_calls_.erase(it++);
            srs_freep(call);
            // FIXME: need process the err
            srs_freep(err);
        } else {
            it++;
            if (state == SrsRtcNativeCall::STATE_CONNECTED
                    && state_ < SrsRtcNativeSession::STATE_CONNECTED) {
                update_state(SrsRtcNativeSession::STATE_CONNECTED); //safe update, no error return
            }
        } 
    }

    it = subscribe_calls_.begin();
    if (it != subscribe_calls_.end()) {
        call = it->second;
        if (( err = call->check_state(state)) != srs_success) {
            publish_calls_.erase(it++);
            srs_freep(call);
            // FIXME: need process the err
            srs_freep(err);
        } else {
            it++;
            if (state == SrsRtcNativeCall::STATE_CONNECTED
                    && state_ < SrsRtcNativeSession::STATE_CONNECTED) {
                update_state(SrsRtcNativeSession::STATE_CONNECTED); //safe update, no error return
            }
        }     
    }

    return srs_success;
}

srs_error_t SrsRtcNativeSession::update_state(SrsRtcNativeSessionState new_state)
{
    if (state_ == new_state) {
        return srs_success;
    }
    if (new_state == SrsRtcNativeSession::STATE_CONNECTED) {
        last_heartbeat_us_ = srs_get_system_time();
    }
    srs_trace("session state change from %u to %u", state_, new_state);

    state_ = new_state;
    return srs_success;
}

srs_error_t SrsRtcNativeSession::on_udp_packet(SrsUdpMuxSocket* skt)
{
    char* data = skt->data();
    int size = skt->size();
    
    if (is_dtls((uint8_t*)data, size)) {
        return conn_->on_dtls(data, size);
    } else if (is_rtp_or_rtcp((uint8_t*)data, size)) {
        if (is_rtcp((uint8_t*)data, size)) {
            if (SrsRtcpApp::is_rtcp_app((uint8_t*)data, size)) {
                return conn_->on_native_signaling(data, size);
            }
            return conn_->on_rtcp(data, size);
        }
        return conn_->on_rtp(data, size);
    }

    return srs_error_new(ERROR_RTC_UDP, "unknown udp packet type");
}

srs_error_t SrsRtcNativeSession::notify(int event, srs_utime_t interval, srs_utime_t tick)
{
    if (event == SRS_TICKID_HEARTBEAT) {
        return send_heartbeat();
    } else if (event == SRS_TICKID_CHECK_STATE) {
        return check_state();
    }

    return srs_success;
}

srs_error_t SrsRtcNativeSession::on_dtls_done()
{
    return update_state(SrsRtcNativeSession::STATE_CONNECTED);
}

srs_error_t SrsRtcNativeSession::process_connect(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;

    if (msg->get_msg_type() == SrsRTCNativeMsgType_request) {
        SrsRtcNativeConnectRequest *request = dynamic_cast<SrsRtcNativeConnectRequest*>(msg);
        srs_assert(request);

        std::string url = request->get_url();
        connect_msg_id_ = request->get_msg_id();
        
        srs_trace("process connect: url=%s msg_id=%u", url.c_str(), connect_msg_id_);

        SrsRtcNativeTempResponse *tmp_response = new SrsRtcNativeTempResponse();
        SrsAutoFree(SrsRtcNativeTempResponse, tmp_response);
        tmp_response->set_msg_id(msg->get_msg_id());
        tmp_response->set_subtype(msg->get_subtype());
        tmp_response->set_name(msg->get_name());

        if ((err = send_signaling(tmp_response)) != srs_success) {
            return srs_error_wrap(err, "process connect");
        }

        if ((err = update_state(SrsRtcNativeSession::STATE_TMP_RESPONSE)) != srs_success) {
            return srs_error_wrap(err, "process connect");
        }
        
        //TODO: FIXME: auth signal request, process session params

        //send final reseponse
        SrsRtcNativeConnectResponse *response = new SrsRtcNativeConnectResponse();
        SrsAutoFree(SrsRtcNativeConnectResponse, response);
        response->set_msg_id(msg->get_msg_id());
        response->set_code(200);

        if ((err = send_signaling(response)) != srs_success) {
            return srs_error_wrap(err, "process connect");
        }

        if ((err = update_state(SrsRtcNativeSession::STATE_FINAL_RESPONSE)) != srs_success) {
            return srs_error_wrap(err, "process connect");
        }
    } else if (msg->get_msg_type() == SrsRTCNativeMsgType_temp_resp) {
        if (connect_msg_id_ == msg->get_msg_id()) {
            if ((err = update_state(SrsRtcNativeSession::STATE_TMP_RESPONSE)) != srs_success) {
                return srs_error_wrap(err, "process connect");
            }            
        }
    } else if (msg->get_msg_type() == SrsRTCNativeMsgType_final_resp) {
        if (connect_msg_id_ == msg->get_msg_id()) {
            if ((err = update_state(SrsRtcNativeSession::STATE_CONNECTED)) != srs_success) {
                return srs_error_wrap(err, "process connect");
            }            
        }
        
        //TODO: process session params
        SrsRtcNativeFinalAck *ack = new SrsRtcNativeFinalAck();
        SrsAutoFree(SrsRtcNativeFinalAck, ack);
        ack->set_msg_id(msg->get_msg_id());
        ack->set_subtype(msg->get_subtype());
        ack->set_name(msg->get_name()); 
        
        if ((err = send_signaling(ack)) != srs_success) {
            return srs_error_wrap(err, "process connect");
        }
    } else if (msg->get_msg_type() == SrsRTCNativeMsgType_final_ack) {
        if (connect_msg_id_ == msg->get_msg_id()) {
            if ((err = update_state(SrsRtcNativeSession::STATE_CONNECTED)) != srs_success) {
                return srs_error_wrap(err, "process connect");
            }            
        } 
    }

    return err;
}

srs_error_t SrsRtcNativeSession::process_disconnect(SrsRtcNativeHeader *msg)
{
    //TODO: FIXME: schedule to destory this session
    srs_error_t err = srs_success;
    if (msg->get_msg_type() != SrsRTCNativeMsgType_request) {
        return err;
    }
    
    if ((err = update_state(SrsRtcNativeSession::STATE_CLOSED))) {
        return srs_error_wrap(err, "process DISC");
    }

    SrsRtcNativeDisconnectResponse *response = new SrsRtcNativeDisconnectResponse();
    SrsAutoFree(SrsRtcNativeDisconnectResponse, response);
    response->set_msg_id(msg->get_msg_id());
    response->set_code(200);
    if ((err = send_signaling(response)) != srs_success) {
        return srs_error_wrap(err, "process DISC");
    }

    return err;
}

srs_error_t SrsRtcNativeSession::process_mtu_detect(SrsRtcNativeHeader *msg)
{
    return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, "signal MTU not support");
}

srs_error_t SrsRtcNativeSession::process_notify(SrsRtcNativeHeader *msg)
{
    return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, "signal NOTI not support");
}

srs_error_t SrsRtcNativeSession::process_wan_ip_port_switch(SrsRtcNativeHeader *msg)
{
    return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, "signal CONN not support");
}


srs_error_t SrsRtcNativeSession::process_stop(SrsRtcNativeHeader *msg)
{
    if (msg->get_msg_type() != SrsRTCNativeMsgType_request) {
        return srs_success;
    }

    SrsRtcNativeStopRequest *request = dynamic_cast<SrsRtcNativeStopRequest*>(msg);
    srs_assert(request);
    std::string url = request->get_url();

    bool found = false;
    CallIterator it;
    it = publish_calls_.find(url);
    if (it != publish_calls_.end()) {
        found = true;
        it->second->stop(true);
    }

    it = subscribe_calls_.find(url);
    if (it != subscribe_calls_.end()) {
        found = true;
        it->second->stop(true);
    }

    if (!found) {
        srs_warn("process stop : url=%s not found", url.c_str());
    }

    SrsRtcNativeStopResponse *response = new SrsRtcNativeStopResponse();
    SrsAutoFree(SrsRtcNativeStopResponse, response);

    response->set_msg_id(msg->get_msg_id());
    response->set_code(found ? 200 : 404);

    return send_signaling(response);
}

srs_error_t SrsRtcNativeSession::process_publish_request(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;
    SrsRtcNativePublishRequest *request = dynamic_cast<SrsRtcNativePublishRequest*>(msg);
    srs_assert(request);

    SrsRequest *req = NULL;
    SrsAutoFree(SrsRequest, req);
    if ((err = SrsRtcNativeSession::parse_url(request->get_url(), &req)) != srs_success) {
        return srs_error_wrap(err, "process url");
    }
    std::string url = req->get_stream_url();

    CallIterator it = publish_calls_.find(url);
    if (it != publish_calls_.end()) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "%s already published", url.c_str());
    }

    SrsRtcNativeServerPublishCall *call = new SrsRtcNativeServerPublishCall(this, request->get_url());
    publish_calls_[url] = call;
    
    if ((err = call->start()) != srs_success) {
        return srs_error_wrap(err, "session process publish");
    } 

    return call->on_signaling(msg);
}

srs_error_t SrsRtcNativeSession::process_subscribe_request(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;
    SrsRtcNativeSubscribeRequest *request = dynamic_cast<SrsRtcNativeSubscribeRequest*>(msg);
    srs_assert(request);

    SrsRequest *req = NULL;
    SrsAutoFree(SrsRequest, req);
    if ((err = SrsRtcNativeSession::parse_url(request->get_url(), &req)) != srs_success) {
        return srs_error_wrap(err, "process url");
    }
    std::string url = req->get_stream_url();

    CallIterator it = subscribe_calls_.find(url);
    if (it != subscribe_calls_.end()) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "%s already subscribed", url.c_str());
    }

    SrsRtcNativeServerPlayCall *call = new SrsRtcNativeServerPlayCall(this, request->get_url());
    subscribe_calls_[url] = call;
    
    if ((err = call->start()) != srs_success) {
        return srs_error_wrap(err, "session process subscribe");
    } 

    return call->on_signaling(msg);
}

srs_error_t SrsRtcNativeSession::process_publish_update_request(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;
    SrsRtcNativePublishUpdateRequest *request = dynamic_cast<SrsRtcNativePublishUpdateRequest*>(msg);
    srs_assert(request);

    SrsRequest *req = NULL;
    SrsAutoFree(SrsRequest, req);
    if ((err = SrsRtcNativeSession::parse_url(request->get_url(), &req)) != srs_success) {
        return srs_error_wrap(err, "process url");
    }
    std::string url = req->get_stream_url();

    CallIterator it = publish_calls_.find(url);
    if (it == publish_calls_.end()) {
        SrsRtcNativePublishUpdateResponse *response = new SrsRtcNativePublishUpdateResponse();
        SrsAutoFree(SrsRtcNativePublishUpdateResponse, response);
        response->set_msg_id(msg->get_msg_id());
        response->set_code(404);
        if ((err = send_signaling(response)) != srs_success) {
            srs_freep(err);
        }
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "publish url %s not found", url.c_str());
    }

    SrsRtcNativeCall *call = it->second;
    return call->on_signaling(msg);
}

srs_error_t SrsRtcNativeSession::process_subscribe_update_request(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;
    SrsRtcNativeSubscribeUpdateRequest *request = dynamic_cast<SrsRtcNativeSubscribeUpdateRequest*>(msg);
    srs_assert(request);

    SrsRequest *req = NULL;
    SrsAutoFree(SrsRequest, req);
    if ((err = SrsRtcNativeSession::parse_url(request->get_url(), &req)) != srs_success) {
        return srs_error_wrap(err, "process url");
    }
    std::string url = req->get_stream_url();

    CallIterator it = subscribe_calls_.find(url);
    if (it == subscribe_calls_.end()) {
        SrsRtcNativeSubscribeUpdateResponse *response = new SrsRtcNativeSubscribeUpdateResponse();
        SrsAutoFree(SrsRtcNativeSubscribeUpdateResponse, response);
        response->set_msg_id(msg->get_msg_id());
        response->set_code(404);
        if ((err = send_signaling(response)) != srs_success) {
            srs_freep(err);
        }
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "subscribe url %s not found", url.c_str());
    }

    SrsRtcNativeCall *call = it->second;
    return call->on_signaling(msg);
}

srs_error_t SrsRtcNativeSession::process_switch_stream_request(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;
    SrsRtcNativeSwitchMsidRequest *request = dynamic_cast<SrsRtcNativeSwitchMsidRequest*>(msg);
    srs_assert(request);

    SrsRequest *req = NULL;
    SrsAutoFree(SrsRequest, req);
    if ((err = SrsRtcNativeSession::parse_url(request->get_url(), &req)) != srs_success) {
        return srs_error_wrap(err, "process url");
    }
    std::string url = req->get_stream_url();

    CallIterator it = subscribe_calls_.find(url);
    if (it == subscribe_calls_.end()) {
        SrsRtcNativeSwitchMsidResponse *response = new SrsRtcNativeSwitchMsidResponse();
        SrsAutoFree(SrsRtcNativeSwitchMsidResponse, response);
        response->set_msg_id(msg->get_msg_id());
        response->set_code(404);
        if ((err = send_signaling(response)) != srs_success) {
            srs_freep(err);
        }
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "subscribe url %s not found", url.c_str());
    }

    SrsRtcNativeCall *call = it->second;
    return call->on_signaling(msg);
}

srs_error_t SrsRtcNativeSession::process_temp_response(SrsRtcNativeHeader *msg)
{
    uint16_t msg_id = msg->get_msg_id();
    CallIterator it = publish_calls_.end();
    CallIterator it_end = publish_calls_.end();
    if (msg->get_subtype() == SrsRTCNativeSubTypePublish) {
        it = publish_calls_.begin();
        it_end = publish_calls_.end();
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribe) {
        it = subscribe_calls_.begin();
        it_end = subscribe_calls_.end();
    }

    for ( ; it != it_end; ++it) {
        if (it->second->msg_id() == msg_id) {
            return it->second->update_state(SrsRtcNativeCall::STATE_TMP_RESPONSE);
        }
    }

    return srs_error_new(ERROR_RTC_NATIVE_STATE, "tmp response response with unknown msg_id");

}

srs_error_t SrsRtcNativeSession::process_response(SrsRtcNativeHeader *msg)
{
    uint16_t msg_id = msg->get_msg_id();
    CallIterator it = publish_calls_.end();
    CallIterator it_end = publish_calls_.end();
    if (msg->get_subtype() == SrsRTCNativeSubTypePublish
            || msg->get_subtype() == SrsRTCNativeSubTypePublishUpadte) {
        it = publish_calls_.begin();
        it_end = publish_calls_.end();
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribe
            || msg->get_subtype() == SrsRTCNativeSubTypeSubscribeUpdate) {
        it = subscribe_calls_.begin();
        it_end = subscribe_calls_.end();
    }

    bool is_update = (msg->get_subtype() == SrsRTCNativeSubTypePublishUpadte) 
            || (msg->get_subtype() == SrsRTCNativeSubTypeSubscribeUpdate);
    for ( ; it != it_end; ++it) {
        if (is_update) {
            if (it->second->last_send_msg_id() == msg_id) {
                return it->second->on_signaling(msg);
            }
        } else {
            if (it->second->msg_id() == msg_id) {
                return it->second->on_signaling(msg);
            }
        }
    }

    return srs_error_new(ERROR_RTC_NATIVE_STATE, "response with unknown msg_id");
}

srs_error_t SrsRtcNativeSession::process_final_ack(SrsRtcNativeHeader *msg)
{
    uint16_t msg_id = msg->get_msg_id();
    CallIterator it = publish_calls_.end();
    CallIterator it_end = publish_calls_.end();
    if (msg->get_subtype() == SrsRTCNativeSubTypePublish) {
        it = publish_calls_.begin();
        it_end = publish_calls_.end();
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribe) {
        it = subscribe_calls_.begin();
        it_end = subscribe_calls_.end();
    }

    for ( ; it != it_end; ++it) {
        if (it->second->msg_id() == msg_id) {
            return it->second->update_state(SrsRtcNativeCall::STATE_CONNECTED);
        }
    }

    return srs_error_new(ERROR_RTC_NATIVE_STATE, "final ack with unknown msg_id");
}

srs_error_t SrsRtcNativeSession::process_heartbeat(SrsRtcNativeHeader *msg)
{
    srs_error_t err = NULL;
    last_heartbeat_us_ = srs_get_system_time();
    if (msg->get_msg_type() == SrsRTCNativeMsgType_request) {
        SrsRtcNativeHeartbeatResponse *response = new SrsRtcNativeHeartbeatResponse();
        response->set_msg_id(msg->get_msg_id());
        response->set_code(200);
        if ((err = send_signaling(response)) != srs_success) {
            return srs_error_wrap(err, "process heartbeat");
        }
    }
    return err;
}

srs_error_t SrsRtcNativeSession::send_heartbeat() {
    if (state_ != SrsRtcNativeSession::STATE_CONNECTED) {
        return srs_success;
    }

    SrsRtcNativeHeartbeatRequest *request = new SrsRtcNativeHeartbeatRequest();
    SrsAutoFree(SrsRtcNativeHeartbeatRequest, request);
    request->set_msg_id(gen_new_msg_id());

    return send_signaling(request);
}

SrsRtcNativeSessionManager::SrsRtcNativeSessionManager()
{
    timer_ = NULL;
    rtc_   = NULL;
}

SrsRtcNativeSessionManager::~SrsRtcNativeSessionManager()
{
}

srs_error_t SrsRtcNativeSessionManager::initialize(SrsRtcServer *server)
{
    srs_error_t err = srs_success;

    if (timer_) {
        return err;
    }

    rtc_ = server;

    timer_ = new SrsHourGlass(this, 10 * SRS_UTIME_SECONDS);
    if ((err = timer_->tick(10 * SRS_UTIME_SECONDS)) != srs_success) {
        return srs_error_wrap(err, "native session manager");
    }
    if ((err = timer_->start()) != srs_success) {
        return srs_error_wrap(err, "native session manager");
    }

    return err;
}

srs_error_t SrsRtcNativeSessionManager::fetch_or_create(const std::string &server_ip, int server_port, SrsRtcNativeSession **session)
{
    srs_error_t err = srs_success;
    SrsRtcNativeSession *s = NULL;
    std::string key = server_ip + ":" + srs_int2str(server_port);
    std::map<std::string, SrsRtcNativeSession*>::iterator it;
    it = sessions_.find(key);
    if (it != sessions_.end()) {
        s = it->second;
        if (s->is_alive()) {
            *session = s;
            return srs_success;
        }
        s->stop();
        zombies_.push_back(s);
        sessions_.erase(it);
    }

    s = new SrsRtcNativeSession(rtc_, server_ip, server_port, false);
    if ((err = s->start()) != srs_success) {
        srs_freep(s);
        return srs_error_wrap(err, "start");
    }
    sessions_[key] = s;
    *session = s;

    return err;   
}

srs_error_t SrsRtcNativeSessionManager::create(char* data, int nb_data, SrsRtcNativeSession **session)
{
    SrsRtcNativeHeader *msg = NULL;
    srs_error_t err = NULL;

    if ((err = SrsRtcNativeSession::parse_signaling(data, nb_data, &msg)) != srs_success) {
        return srs_error_wrap(err, "create native session");
    }

    SrsAutoFree(SrsRtcNativeHeader, msg);
    if (msg->get_msg_type() != SrsRTCNativeMsgType_request || (
            msg->get_subtype() != SrsRTCNativeSubTypeConnect &&
            msg->get_subtype() != SrsRTCNativeSubTypePublish &&
            msg->get_subtype() != SrsRTCNativeSubTypeSubscribe)) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, 
                "sub_type=%u msg_type=%u can not be first signaling",
                msg->get_subtype(), msg->get_msg_type());
    }

    SrsRtcNativeSession *s = new SrsRtcNativeSession(rtc_, SrsRtcNativeSession::ROLE_SERVER, false);

    if ((err = s->start()) != srs_success) {
        srs_freep(s);
        return srs_error_wrap(err, "start");
    }

    *session = s;

    std::string key = srs_int2str((int64_t)s);
    sessions_[key] = s;

    return err;
}

srs_error_t SrsRtcNativeSessionManager::notify(int event, srs_utime_t interval, srs_utime_t tick)
{
    std::map<std::string, SrsRtcNativeSession*>::iterator it = sessions_.begin();
    while (it != sessions_.end()) {
        if (it->second->is_alive()) {
            ++it;
        } else {
            it->second->stop();
            zombies_.push_back(it->second);
            sessions_.erase(it++);
        }
    }
        
    SrsRtcNativeSession *session = NULL;
    while (!zombies_.empty()) {
        session = zombies_.back();
        zombies_.pop_back();
        srs_freep(session);
    }

    return srs_success;
}

SrsRtcNativeSessionManager* _srs_rtc_native = new SrsRtcNativeSessionManager();
    
SrsRtcNativeCall::SrsRtcNativeCall(SrsRtcNativeSession *session, SrsRtcNativeCallType type, const std::string &url)
        : url_(url), type_(type), start_us_(srs_get_system_time())
{
    session_ = session;
    req_     = NULL;
    source_  = NULL;
    state_   = SrsRtcNativeCall::STATE_NONE;
    msg_id_  = 0;
    last_recv_msg_id_ = 0;
    last_send_msg_id_ = 0;
    memset(&retry_items_[0], 0, sizeof(retry_items_));

    SrsContextId parent_id = session->get_cid();
    if (type == SrsRtcNativeCall::TYPE_CLIENT_PUBLISH || type == SrsRtcNativeCall::TYPE_SERVER_PLAY) {
        cid_ = _srs_context->generate_id("sub", parent_id);
    } else {
        cid_ = _srs_context->generate_id("pub", parent_id);
    }
    _srs_context->set_id(cid_);

    srs_trace("Native Call: url=%s type=%u", url_.c_str(), type_);
    
}

SrsRtcNativeCall::~SrsRtcNativeCall()
{
    //TODO: FIXME: remove SrsRtcPlayStream or SrsRtcPlayStream from SrsRtcConnection
    srs_freep(req_);
}

srs_error_t SrsRtcNativeCall::check_state(SrsRtcNativeCallState &state)
{
    _srs_context->set_id(cid_);
    state = state_;
    srs_utime_t now = srs_get_system_time();

    if (state_ < SrsRtcNativeCall::STATE_CONNECTED) {
        if (start_us_ + SrsRtcNativeSession::SESSION_DEFAULT_TIMEOUT_US < now) {
            update_state(SrsRtcNativeCall::STATE_TIMEOUT); // safe state update, no error return
        }
        SrsRtcNativeCall::RetryItem *item = &retry_items_[SrsRtcNativeCall::TYPE_CALL];
        int retry_interval = SrsRtcNativeSession::get_retry_interval(item->retry_count);
        if (item->retry_us + retry_interval < now && item->msg) {
            retry(SrsRtcNativeCall::TYPE_CALL);
        }
    }

    if (state_ == SrsRtcNativeCall::STATE_CONNECTED) {
        for (int i = SrsRtcNativeCall::TYPE_UPDATE; i < SrsRtcNativeCall::TYPE_MAX; ++i) {
            SrsRtcNativeCall::RetryItem *item = &retry_items_[i];
            if (item->msg) {
                int retry_interval = SrsRtcNativeSession::get_retry_interval(item->retry_count);
                if (item->retry_us + retry_interval < now) {
                    retry(i);
                }
            }
        }
        return srs_success;
    }

    if (state_ >= SrsRtcNativeCall::STATE_CONNECTED) {
        return srs_error_new(ERROR_RTC_NATIVE_STATE, "call in state %u", state_);
    }

    return srs_success;
}

srs_error_t SrsRtcNativeCall::start()
{
    srs_error_t err = srs_success;
    if ((err = SrsRtcNativeSession::parse_url(url_, &req_)) != srs_success) {
        return srs_error_wrap(err, "process call url");
    }

    return this->do_start();
}

srs_error_t SrsRtcNativeCall::stop(bool from_signaling)
{
    return srs_success;
}

srs_error_t SrsRtcNativeCall::do_start()
{
    return srs_success;
}

srs_error_t SrsRtcNativeCall::retry(int idx)
{   
    SrsRtcNativeCall::RetryItem *item = &retry_items_[idx]; 
    if (!item->msg) {
        return srs_success;
    }

    ++item->retry_count;
    item->retry_us = srs_get_system_time();

    if (item->msg->get_msg_type() == SrsRTCNativeMsgType_request) {
        item->msg->set_msg_id(session_->gen_new_msg_id());
    }

    return session_->send_signaling(item->msg);
}

srs_error_t SrsRtcNativeCall::update_state(SrsRtcNativeCallState state)
{
    _srs_context->set_id(cid_);
    srs_error_t err = srs_success;
    srs_trace("call state try to change from %u to %u", state_, state);
    if ((err = state_change_verify(state)) == srs_success) {
        srs_trace("call state change from %u to %u", state_, state);
        state_ = state;
    }

    if (state_ == SrsRtcNativeCall::STATE_CONNECTED) {
        set_retry_info(SrsRtcNativeCall::TYPE_CALL, NULL);

        //TODO: FIXME: using SrsRtcPublishStream or SrsRtcPlayStream
        SrsRtcConnection *conn = session_->get_rtc_connection();
        conn->set_all_tracks_status(true);
    }

    return err;
}

srs_error_t SrsRtcNativeCall::send_temp_response()
{
    if (type_ != SrsRtcNativeCall::TYPE_SERVER_PUBLISH
            && type_ != SrsRtcNativeCall::TYPE_SERVER_PLAY) {
        return srs_success;
    }

    SrsRtcNativeTempResponse *response = new SrsRtcNativeTempResponse();
    SrsAutoFree(SrsRtcNativeTempResponse, response);
    response->set_msg_id(msg_id_);
    if (type_ == SrsRtcNativeCall::TYPE_SERVER_PUBLISH) {
        response->set_subtype(SrsRTCNativeSubTypePublish);
        response->set_name("PUB");
    } else {
        response->set_subtype(SrsRTCNativeSubTypeSubscribe);
        response->set_name("SUB");
    }

    return session_->send_signaling(response);

}

srs_error_t SrsRtcNativeCall::send_final_ack()
{
    if (type_ != SrsRtcNativeCall::TYPE_CLIENT_PUBLISH
            && type_ != SrsRtcNativeCall::TYPE_CLIENT_SUBSCRIBE) {
        return srs_success;
    }

    SrsRtcNativeFinalAck *ack = new SrsRtcNativeFinalAck();
    SrsAutoFree(SrsRtcNativeFinalAck, ack);
    ack->set_msg_id(msg_id_);
    if (type_ == SrsRtcNativeCall::TYPE_CLIENT_PUBLISH) {
        ack->set_subtype(SrsRTCNativeSubTypePublish);
        ack->set_name("PUB");
    } else {
        ack->set_subtype(SrsRTCNativeSubTypeSubscribe);
        ack->set_name("SUB");
    }

    return session_->send_signaling(ack);
}

void SrsRtcNativeCall::set_retry_info(SrsRtcNativeCallRetryType retry_type, SrsRtcNativeHeader *msg)
{
    SrsRtcNativeCall::RetryItem *item = &retry_items_[retry_type];
    item->retry_count = 0;
    item->retry_us = srs_get_system_time();
    srs_freep(item->msg);
    item->msg = msg;
}


srs_error_t SrsRtcNativeCall::on_signaling(SrsRtcNativeHeader *msg)
{
    _srs_context->set_id(cid_);

    if (msg->get_subtype() == SrsRTCNativeSubTypeMediaControl) {
        return process_media_control(msg);
    } 

    return this->process_signaling(msg);
}

srs_error_t SrsRtcNativeCall::process_media_control(SrsRtcNativeHeader *msg)
{
    return srs_success;
}

srs_error_t SrsRtcNativeCall::state_change_verify(SrsRtcNativeCallState new_state)
{
    if (new_state == SrsRtcNativeCall::STATE_FAILED
            || new_state == SrsRtcNativeCall::STATE_STOP
            || new_state == SrsRtcNativeCall::STATE_TIMEOUT) {
        return srs_success;
    }
    
    switch (new_state) {
        case SrsRtcNativeCall::STATE_INIT: {
            if (state_ == SrsRtcNativeCall::STATE_NONE) {
                return srs_success;
            }
        } break;
        case SrsRtcNativeCall::STATE_TMP_RESPONSE: {
            if (state_ == SrsRtcNativeCall::STATE_INIT) {
                return srs_success;
            }
        } break;
        case SrsRtcNativeCall::STATE_FINAL_RESPONSE: {
            if (state_ == SrsRtcNativeCall::STATE_INIT
                    || state_ == SrsRtcNativeCall::STATE_TMP_RESPONSE) {
                return srs_success;
            }
        } break;
        case SrsRtcNativeCall::STATE_CONNECTED: {
            if (state_ == SrsRtcNativeCall::STATE_INIT
                    || state_ == SrsRtcNativeCall::STATE_TMP_RESPONSE
                    || state_ == SrsRtcNativeCall::STATE_FINAL_RESPONSE
                    || state_ == SrsRtcNativeCall::STATE_CONNECTED) {
                return srs_success;
            }
        } break;
        default: break;
    }

    return srs_error_new(ERROR_RTC_NATIVE_STATE, "state chage %u --> %u is illegal", state_, new_state);
}

SrsRtcNativeServerPublishCall::SrsRtcNativeServerPublishCall(SrsRtcNativeSession *session, const std::string &url)
        :SrsRtcNativeCall(session, SrsRtcNativeCall::TYPE_SERVER_PUBLISH, url)
{
    publish_ = NULL;
}

SrsRtcNativeServerPublishCall::~SrsRtcNativeServerPublishCall()
{

}

srs_error_t SrsRtcNativeServerPublishCall::process_signaling(SrsRtcNativeHeader *msg)
{
    if (msg->get_subtype() == SrsRTCNativeSubTypePublish) {
        return process_publish_request(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypePublishUpadte) {
        return process_publish_update_request(msg);
    }

    return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, 
            "publish call not support signal %s", msg->get_name().c_str());
}

srs_error_t SrsRtcNativeServerPublishCall::process_publish_request(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;

    if ((err = update_state(SrsRtcNativeCall::STATE_INIT)) != srs_success) {
        return srs_error_wrap(err, "process publish");
    }

    msg_id_ = msg->get_msg_id(); // msg id for this call, immutable
    
    if ((err = send_temp_response()) != srs_success) {
        return srs_error_wrap(err, "process publish");
    }

    if ((err = update_state(SrsRtcNativeCall::STATE_TMP_RESPONSE)) != srs_success) {
        return srs_error_wrap(err, "process publish");
    }

    //process add publish
    SrsRtcConnection *conn = session_->get_rtc_connection();
    SrsRtcNativePublishRequest *request = dynamic_cast<SrsRtcNativePublishRequest*>(msg);
    srs_assert(request);

    if ((err = SrsRtcNativeSession::parse_url(request->get_url(), &req_)) != srs_success) {
        return srs_error_wrap(err, "process publish");
    }

    SrsRtcNativePublishResponse *response = new SrsRtcNativePublishResponse();
    response->set_msg_id(msg_id_);

    SrsRtcNativeMiniSDP *remote_sdp = request->get_sdp();
    SrsRtcNativeCommonMediaParam *remote_param = request->get_session_param()->get_media_param();

    SrsRtcNativeMiniSDP *local_sdp = response->get_sdp();
    SrsRtcNativeCommonMediaParam *local_param = response->get_session_param()->get_media_param();

    if ((err = conn->add_publisher(req_, 
            *remote_sdp, *remote_param, *local_sdp, *local_param)) != srs_success) {
        srs_trace("SrsRtcNativeServerPublishCall::process_publish faild: %s", srs_error_summary(err).c_str());
        response->set_code(501);
        srs_error_t tmp_err = session_->send_signaling(response);
        srs_freep(tmp_err);
        srs_freep(response);
        update_state(SrsRtcNativeCall::STATE_FAILED); // update to failed, no error will return;
        return srs_error_wrap(err, "process publish");
    }

    if ((err = conn->start_publish()) != srs_success) {
        srs_error_t tmp_err = session_->send_signaling(response);
        srs_freep(tmp_err);
        srs_freep(response);
        update_state(SrsRtcNativeCall::STATE_FAILED); // update to failed, no error will return;
        return srs_error_wrap(err, "process publish");     
    }

    response->set_code(200);
    if ((err = session_->send_signaling(response)) != srs_success) {
        srs_freep(response);
        return srs_error_wrap(err, "process publish");
    }

    if ((err = update_state(SrsRtcNativeCall::STATE_FINAL_RESPONSE)) != srs_success) {
        srs_freep(response);
        return srs_error_wrap(err, "process publish");
    }

    set_retry_info(SrsRtcNativeCall::TYPE_CALL, response);
    
    return err;
}

srs_error_t SrsRtcNativeServerPublishCall::process_publish_update_request(SrsRtcNativeHeader *msg)
{
    return srs_success;
}

SrsRtcNativeServerPlayCall::SrsRtcNativeServerPlayCall(SrsRtcNativeSession *session, const std::string &url)
        :SrsRtcNativeCall(session, SrsRtcNativeCall::TYPE_SERVER_PLAY, url)
{
    play_ = NULL;
}

SrsRtcNativeServerPlayCall::~SrsRtcNativeServerPlayCall()
{

}

srs_error_t SrsRtcNativeServerPlayCall::process_signaling(SrsRtcNativeHeader *msg)
{
    if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribe) {
        return process_subscribe_request(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribeUpdate) {
        return process_publish_subscribe_request(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSwitchMSID) {
        return process_switch_msid_request(msg);
    }

    return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, 
            "play call not support signal %s", msg->get_name().c_str());
}

srs_error_t SrsRtcNativeServerPlayCall::process_subscribe_request(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;

    if ((err = update_state(SrsRtcNativeCall::STATE_INIT)) != srs_success) {
        return srs_error_wrap(err, "process subscribe");
    }

    msg_id_ = msg->get_msg_id(); // msg id for this call, immutable
    
    if ((err = send_temp_response()) != srs_success) {
        return srs_error_wrap(err, "process subscribe");
    }

    if ((err = update_state(SrsRtcNativeCall::STATE_TMP_RESPONSE)) != srs_success) {
        return srs_error_wrap(err, "process subscribe");
    }

    //TODO: FIXME: may be need wait source to ready

    //process add subscribe
    SrsRtcConnection *conn = session_->get_rtc_connection();
    SrsRtcNativeSubscribeRequest *request = dynamic_cast<SrsRtcNativeSubscribeRequest*>(msg);
    srs_assert(request);

    if ((err = SrsRtcNativeSession::parse_url(request->get_url(), &req_)) != srs_success) {
        return srs_error_wrap(err, "process publish");
    }

    SrsRtcNativeSubscribeResponse *response = new SrsRtcNativeSubscribeResponse();
    response->set_msg_id(msg_id_);

    SrsRtcNativeTenfoldConfig *config = request->get_tenfold_config();
    SrsRtcNativeMiniSDP *remote_sdp = request->get_sdp();
    SrsRtcNativeCommonMediaParam *remote_param = request->get_session_param()->get_media_param();

    SrsRtcNativeMiniSDP *local_sdp = response->get_sdp();
    SrsRtcNativeCommonMediaParam *local_param = response->get_session_param()->get_media_param();
    
    if (config->get_mode() == SrsRtcNativeTenfoldConfig::MODE_CASCADE) {
        remote_param->set_cascade_media(true);
        local_param->set_cascade_media(true);    
    }

    if ((err = conn->add_player(req_, *remote_sdp, *remote_param, *local_sdp, *local_param)) != srs_success) {
        srs_trace("SrsRtcNativeServerPlayCall::process_subscribe_request faild: %s", srs_error_summary(err).c_str());
        response->set_code(501);
        srs_error_t tmp_err = session_->send_signaling(response);
        srs_freep(tmp_err);
        srs_freep(response);
        update_state(SrsRtcNativeCall::STATE_FAILED); // update to failed, no error will return;
        return srs_error_wrap(err, "process subscribe");
    }

    if ((err = conn->start_play()) != srs_success) {
        response->set_code(501);
        srs_error_t tmp_err = session_->send_signaling(response);
        srs_freep(tmp_err);
        srs_freep(response);
        return srs_error_wrap(err, "process subscribe");     
    }

    response->set_code(200);
    if ((err = session_->send_signaling(response)) != srs_success) {
        srs_freep(response);
        return srs_error_wrap(err, "process subscribe");
    }


    if ((err = update_state(SrsRtcNativeCall::STATE_FINAL_RESPONSE)) != srs_success) {
        srs_freep(response);
        return srs_error_wrap(err, "process subscribe");
    }

    set_retry_info(SrsRtcNativeCall::TYPE_CALL, response);

    return err;
}

srs_error_t SrsRtcNativeServerPlayCall::process_publish_subscribe_request(SrsRtcNativeHeader *msg)
{
    return srs_success;
}

srs_error_t SrsRtcNativeServerPlayCall::process_switch_msid_request(SrsRtcNativeHeader *msg)
{
    return srs_success;
}

SrsRtcNativeClientSubscribeCall::SrsRtcNativeClientSubscribeCall(SrsRtcNativeSession *session, const std::string &url)
        :SrsRtcNativeCall(session, SrsRtcNativeCall::TYPE_CLIENT_SUBSCRIBE, url)
{
    publish_ = NULL;
}

SrsRtcNativeClientSubscribeCall::~SrsRtcNativeClientSubscribeCall()
{

}

srs_error_t SrsRtcNativeClientSubscribeCall::do_start()
{
    srs_error_t err = srs_success;
    
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &source_)) != srs_success) {
        return srs_error_wrap(err, "rtc fetch source failed");
    }
    
    //TODO: FIXME: fetch cascade path from source
    SrsRtcNativeSubscribeRequest *request = new SrsRtcNativeSubscribeRequest();
    msg_id_ = session_->gen_new_msg_id();
    request->set_msg_id(msg_id_);
    request->set_url(url_);
    SrsRtcNativeTenfoldConfig *config = request->get_tenfold_config();
    config->set_mode(SrsRtcNativeTenfoldConfig::MODE_CASCADE);

    if ((err = session_->send_signaling(request)) != srs_success) {
        srs_freep(request);
        return srs_error_wrap(err, "client subscribe");
    }

    if ((err = update_state(SrsRtcNativeCall::STATE_INIT)) != srs_success) {
        srs_freep(request);
        return srs_error_wrap(err, "client subscribe");
    }

    set_retry_info(SrsRtcNativeCall::TYPE_CALL, request);

    return err; 
}

srs_error_t SrsRtcNativeClientSubscribeCall::process_signaling(SrsRtcNativeHeader *msg)
{
    if (msg->get_msg_type() == SrsRTCNativeMsgType_request) {
        return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, 
                "client publish call not support signal request %s", msg->get_name().c_str());
    }

    if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribe) {
        return process_subscribe_response(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSubscribeUpdate) {
        return process_subscribe_update_response(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypeSwitchMSID) {
    }

    return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT,
            "publish call not support signal response %s", msg->get_name().c_str());
}

srs_error_t SrsRtcNativeClientSubscribeCall::process_subscribe_response(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;
    SrsRtcNativeSubscribeResponse *response = dynamic_cast<SrsRtcNativeSubscribeResponse*>(msg);
    srs_assert(response);

    if (response->get_code() != 200) {
        srs_error("client subscribe failed code=%u msg=%s", response->get_code(), response->get_msg().c_str());
        update_state(SrsRtcNativeCall::STATE_FAILED); //no error set state to FAILED
        return srs_error_new(ERROR_RTC_NATIVE_STATE, 
                "client subscribe failed code=%u msg=%s", 
                response->get_code(), response->get_msg().c_str());
    }

    if ((err = send_final_ack()) != srs_success) {
        return srs_error_wrap(err, "client subscribe");
    }

    // already process the subscribe response
    if (state_ >= SrsRtcNativeCall::STATE_CONNECTED) {
        return err;
    }

    SrsRtcNativeMiniSDP *remote_sdp = response->get_sdp();
    SrsRtcNativeCommonMediaParam *remote_param = response->get_session_param()->get_media_param();

    SrsRtcNativeMiniSDP *local_sdp = new SrsRtcNativeMiniSDP();
    SrsAutoFree(SrsRtcNativeMiniSDP, local_sdp);
    SrsRtcNativeCommonMediaParam *local_param = new SrsRtcNativeCommonMediaParam();
    SrsAutoFree(SrsRtcNativeCommonMediaParam, local_param);

    SrsRtcConnection *conn = session_->get_rtc_connection();
    if ((err = conn->add_publisher(req_, 
            *remote_sdp, *remote_param, *local_sdp, *local_param)) != srs_success) {
        srs_trace("SrsRtcNativeServerPublishCall::process_publish faild: %s", srs_error_summary(err).c_str());
        response->set_code(501);
        update_state(SrsRtcNativeCall::STATE_FAILED); // update to failed, no error will return;
        return srs_error_wrap(err, "procese subscribe response");
    }

    if ((err = conn->start_publish()) != srs_success) {
        return srs_error_wrap(err, "procese subscribe response");     
    }

    if ((err = update_state(SrsRtcNativeCall::STATE_CONNECTED)) != srs_success) {
        return srs_error_wrap(err, "update state");
    }

    return err;
}

srs_error_t SrsRtcNativeClientSubscribeCall::process_subscribe_update_response(SrsRtcNativeHeader *msg)
{
    return srs_success;
}

SrsRtcNativeClientPublishCall::SrsRtcNativeClientPublishCall(SrsRtcNativeSession *session, const std::string &url)
        :SrsRtcNativeCall(session, SrsRtcNativeCall::TYPE_CLIENT_PUBLISH, url)
{
    play_ = NULL;
}

SrsRtcNativeClientPublishCall::~SrsRtcNativeClientPublishCall()
{

}

srs_error_t SrsRtcNativeClientPublishCall::do_start()
{
    srs_error_t err = srs_success;

    if (state_ != SrsRtcNativeCall::STATE_NONE) {
        return err;
    }

    if ((err = _srs_rtc_sources->fetch_or_create(req_, &source_)) != srs_success) {
        return srs_error_wrap(err, "rtc fetch source failed");
    }

    SrsRtcStreamDescription *stream_desc = new SrsRtcStreamDescription();
    SrsAutoFree(SrsRtcStreamDescription, stream_desc);
    
    // 0. check source
    if (source_->can_publish(false)) {
        return srs_error_wrap(err, "source not ready");
    }

    // 1. use source sdp as player's remote sdp
    int track_count = 0;
    std::vector<SrsRtcTrackDescription*> tracks;
    tracks = source_->get_track_desc("audio", "opus");
    if (!tracks.empty()) {
        stream_desc->audio_track_desc_ = tracks.at(0)->copy();
        ++track_count;
    }
    tracks = source_->get_track_desc("video", "H264");
    for (int i = 0; i < (int)tracks.size(); ++i) {
        stream_desc->video_track_descs_.push_back(tracks.at(i)->copy());
        ++track_count;
    }
    if (track_count == 0) {
        return srs_error_new(ERROR_RTC_SOURCE_CHECK, "no track in source");
    }
    SrsRtcNativeCommonMediaParam *remote_param = new SrsRtcNativeCommonMediaParam();
    SrsAutoFree(SrsRtcNativeCommonMediaParam, remote_param); 
    SrsRtcNativeMiniSDP *remote_sdp = new SrsRtcNativeMiniSDP();
    SrsAutoFree(SrsRtcNativeMiniSDP, remote_sdp);
    if ((err = stream_desc->generate_mini_sdp(req_->vhost, *remote_sdp, *remote_param)) != srs_success) {
        return srs_error_wrap(err, "client publish gen mini sdp");
    }

    // 2. create player, use plays's local sdp as client publish sdp
    SrsRtcNativePublishRequest *request = new SrsRtcNativePublishRequest();
    SrsRtcNativeMiniSDP *local_sdp = request->get_sdp();
    SrsRtcNativeCommonMediaParam *local_param = request->get_session_param()->get_media_param();
    SrsRtcConnection *conn = session_->get_rtc_connection();
    if ((err = conn->add_player(req_, *remote_sdp, *remote_param, *local_sdp, *local_param)) != srs_success) {
        return srs_error_wrap(err, "create rtc player");
    }

    // 3. send publish request
    msg_id_ = session_->gen_new_msg_id();
    request->set_msg_id(msg_id_);
    request->set_url(url_);
    if ((err = stream_desc->generate_mini_sdp(req_->vhost, *local_sdp, *local_param)) != srs_success) {
        srs_freep(request);
        return srs_error_wrap(err, "client publish gen mini sdp");
    }

    if ((err = session_->send_signaling(request)) != srs_success) {
        srs_freep(request);
        return srs_error_wrap(err, "client publish");
    }

    if ((err = update_state(SrsRtcNativeCall::STATE_INIT)) != srs_success) {
        srs_freep(request);
        return srs_error_wrap(err, "client publish");
    }

    set_retry_info(SrsRtcNativeCall::TYPE_CALL, request); 

    return err;
}

srs_error_t SrsRtcNativeClientPublishCall::process_signaling(SrsRtcNativeHeader *msg)
{
    if (msg->get_msg_type() == SrsRTCNativeMsgType_request) {
        return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, 
                "client play call not support signal request %s", msg->get_name().c_str());
    }

    if (msg->get_subtype() == SrsRTCNativeSubTypePublish) {
        return process_publish_response(msg);
    } else if (msg->get_subtype() == SrsRTCNativeSubTypePublishUpadte) {
        return process_publish_update_response(msg);
    }

    return srs_error_new(ERROR_RTC_NATIVE_NOT_SUPPORT, 
            "client play call not support signal response %s", msg->get_name().c_str());
}

srs_error_t SrsRtcNativeClientPublishCall::process_publish_response(SrsRtcNativeHeader *msg)
{
    srs_error_t err = srs_success;
    SrsRtcNativePublishResponse *response = dynamic_cast<SrsRtcNativePublishResponse*>(msg);
    srs_assert(response);

    if (response->get_code() != 200) {
        srs_error("client publish failed code=%u msg=%s", response->get_code(), response->get_msg().c_str());
        update_state(SrsRtcNativeCall::STATE_FAILED); //no error set state to FAILED
        return srs_error_new(ERROR_RTC_NATIVE_STATE, 
                "client publish failed code=%u msg=%s", 
                response->get_code(), response->get_msg().c_str());
    }
    
    if ((err = send_final_ack()) != srs_success) {
        return srs_error_wrap(err, "client publish");
    }

    // already process the publish response
    if (state_ >= SrsRtcNativeCall::STATE_CONNECTED) {
        return err;
    }

    SrsRtcConnection *conn = session_->get_rtc_connection();
    if ((err = conn->start_play()) != srs_success) {
        update_state(SrsRtcNativeCall::STATE_FAILED); //no error set state to FAILED
        return srs_error_wrap(err, "client publish start player");
    }

    return update_state(SrsRtcNativeCall::STATE_CONNECTED);
}

srs_error_t SrsRtcNativeClientPublishCall::process_publish_update_response(SrsRtcNativeHeader *msg)
{
    return srs_success;
}