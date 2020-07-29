/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2013-2020 Winlin
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

#include <srs_app_rtc_janus.hpp>

#include <unistd.h>
#include <string>
using namespace std;

#include <srs_app_rtc_conn.hpp>
#include <srs_app_server.hpp>
#include <srs_protocol_json.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_core_autofree.hpp>
#include <srs_service_st.hpp>
#include <srs_app_config.hpp>
#include <srs_app_rtc_conn.hpp>
#include <srs_app_rtc_server.hpp>
#include <srs_service_http_conn.hpp>
#include <srs_app_rtc_source.hpp>
#include <srs_service_utility.hpp>

// SLS log writers.
SrsLogWriterCallstack* _sls_callstack = new SrsLogWriterCallstack();
SrsLogWriterRelation* _sls_relation = new SrsLogWriterRelation();
SrsLogWriteDataStatistic* _sls_data_statistic = new SrsLogWriteDataStatistic();
SrsLogWriteDownlinkBwe* _sls_downlink_bwe = new SrsLogWriteDownlinkBwe();

// When API error, limit the request by sleep for a while.
srs_utime_t API_ERROR_LIMIT = 10 * SRS_UTIME_SECONDS;

// TODO: FIXME: Use cond to wait.
// For Long polling keep alive, sleep for a while.
srs_utime_t API_POLLING_LIMIT = 1 * SRS_UTIME_SECONDS;

extern srs_error_t srs_api_response(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, std::string json);
extern srs_error_t srs_api_response_code(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, int code);

SrsJanusMessage::SrsJanusMessage()
{
    session_id = sender = feed_id = 0;
    private_id = 0;
}

SrsGoApiRtcJanus::SrsGoApiRtcJanus(SrsJanusServer* j)
{
    janus_ = j;
}

SrsGoApiRtcJanus::~SrsGoApiRtcJanus()
{
}

srs_error_t SrsGoApiRtcJanus::serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
{
    srs_error_t err = srs_success;

    // Remember current cid and restore it when done.
    SrsContextRestore(_srs_context->get_id());

    SrsJsonObject* res = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, res);

    if ((err = do_serve_http(w, r, res)) != srs_success) {
        // TODO: FIXME: Response in Janus error style.
        srs_warn("RTC janus error %s", srs_error_desc(err).c_str()); srs_freep(err);
        return srs_api_response_code(w, r, SRS_CONSTS_HTTP_BadRequest);
    }

    return srs_api_response(w, r, res->dumps());
}

srs_error_t SrsGoApiRtcJanus::do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    // Parse session id from path, which is:
    //          /janus/$session_id/$handler_id
    // For example:
    //          /janus/2422535898231440/7338815075475232
    uint64_t janus_session_id = 0;
    uint64_t janus_handler_id = 0;
    if (true) {
        string path = r->path();
        const string flag = "/janus/";
        if (path.length() > flag.length()) {
            string s0 = path.substr(flag.length()), s1;
            size_t pos = s0.find("/");
            if (pos != string::npos) {
                s1 = s0.substr(pos + 1);
                s0 = s0.substr(0, pos);
            }

            if (!s0.empty()) {
                janus_session_id = ::atoll(s0.c_str());
            }
            if (!s1.empty()) {
                janus_handler_id = ::atoll(s1.c_str());
            }
        }
    }

    SrsJanusSession* session = NULL;
    if (janus_session_id || janus_handler_id) {
        session = janus_->fetch(janus_session_id);
        if (!session) {
            srs_usleep(API_ERROR_LIMIT);
            return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "no session id=%" PRId64, janus_session_id);
        }
    }

    SrsJanusCall* call = NULL;
    if (janus_handler_id) {
        call = session->fetch(janus_handler_id);
        if (!session) {
            srs_usleep(API_ERROR_LIMIT);
            return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "no call id=%" PRId64, janus_handler_id);
        }
    }

    // Switch to the context of session or call.
    if (session) {
        if (!call) {
            _srs_context->set_id(session->cid_);
        } else {
            _srs_context->set_id(call->cid_);
        }
    }

    // Whether parse the HTTP body.
    bool has_body = true;
    bool long_polling = false;
    if (r->method() == SRS_CONSTS_HTTP_GET && janus_session_id && !janus_handler_id) {
        has_body = false;
        long_polling = true;
    }

    SrsJsonObject* req = NULL;
    SrsAutoFree(SrsJsonObject, req);

    string req_json;
    SrsJanusMessage req_msg;
    if (has_body) {
        // Parse req, the request json object, from body.
        if ((err = r->body_read_all(req_json)) != srs_success) {
            return srs_error_wrap(err, "read body");
        }

        SrsJsonAny* json = SrsJsonAny::loads(req_json);
        if (!json || !json->is_object()) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "body not json");
        }

        req = json->to_object();

        // Fetch params from req object.
        SrsJsonAny* prop = NULL;
        if ((prop = req->ensure_property_string("janus")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no janus");
        }
        req_msg.janus = prop->to_str();

        if ((prop = req->ensure_property_string("transaction")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no transaction");
        }
        req_msg.transaction = prop->to_str();

        if ((prop = req->ensure_property_string("client_tid")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no client_tid");
        }
        req_msg.client_tid = prop->to_str();

        if ((prop = req->ensure_property_string("rpcid")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no rpcid");
        }
        req_msg.rpcid = prop->to_str();

        if ((prop = req->ensure_property_string("source_module")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no source_module");
        }
        req_msg.source_module = prop->to_str();
    }

    // Fill client IP to janus message.
    if (true) {
        SrsHttpMessage* hreq = dynamic_cast<SrsHttpMessage*>(r);
        SrsConnection* conn = dynamic_cast<SrsConnection*>(hreq->connection());
        req_msg.client_ip = conn->remote_ip();
    }

    // For long polling, handle by session.
    if (long_polling) {
        if (!session) {
            return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "polling, no session id=%" PRId64, janus_session_id);
        }
        return session->polling(req, res);
    }

    // Set the common response header.
    if (!req_msg.transaction.empty()) {
        res->set("janus", SrsJsonAny::str("success"));
        res->set("transaction", SrsJsonAny::str(req_msg.transaction.c_str()));
    }

    if (req_msg.janus == "create") {
        if ((err = janus_->create(req, &req_msg, res)) != srs_success) {
            return srs_error_wrap(err, "body %s", req_json.c_str());
        }
    } else if (req_msg.janus == "attach") {
        if (!session) {
            return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "attach, no session id=%" PRId64, janus_session_id);
        }
        if ((err = session->attach(req, &req_msg, res)) != srs_success) {
            return srs_error_wrap(err, "body %s", req_json.c_str());
        }
    } else if (req_msg.janus == "message") {
        if (!call) {
            return srs_error_new(ERROR_RTC_JANUS_NO_CALL, "attach, no call id=%" PRId64, janus_handler_id);
        }

        // TODO: FIXME: Maybe we should response error.
        res->set("janus", SrsJsonAny::str("ack"));
        res->set("session", SrsJsonAny::integer(session->id_));

        if ((err = call->message(req, &req_msg)) != srs_success) {
            return srs_error_wrap(err, "body %s", req_json.c_str());
        }
    } else if (req_msg.janus == "trickle") {
        if (!call) {
            return srs_error_new(ERROR_RTC_JANUS_NO_CALL, "attach, no call id=%" PRId64, janus_handler_id);
        }

        // TODO: FIXME: Maybe we should response error.
        res->set("janus", SrsJsonAny::str("ack"));
        res->set("session", SrsJsonAny::integer(session->id_));

        if ((err = call->trickle(req, &req_msg)) != srs_success) {
            return srs_error_wrap(err, "body %s", req_json.c_str());
        }
    } else if (req_msg.janus == "detach") {
        if (!session) {
            return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "detach, no session id=%" PRId64, janus_session_id);
        }
        if ((err = session->detach(&req_msg, janus_handler_id)) != srs_success) {
            return srs_error_wrap(err, "body %s", req_json.c_str());
        }
    } else if (req_msg.janus == "destroy") {
        if (!session) {
            return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "destroy, no session id=%" PRId64, janus_session_id);
        }

        SrsJanusDestroyMessage(session, &req_msg).write_callstack("leave", 0);
        // TODO: FIXME: Maybe we should response error.
        res->set("session", SrsJsonAny::integer(session->id_));

        janus_->destroy(session, &req_msg);
    } else {
        srs_warn("RTC unknown action=%s, body=%s", req_msg.janus.c_str(), req_json.c_str());
        srs_usleep(API_ERROR_LIMIT);
    }

    return err;
}

SrsJanusServer::SrsJanusServer(SrsRtcServer* r)
{
    rtc_ = r;
}

SrsJanusServer::~SrsJanusServer()
{
    map<uint64_t, SrsJanusSession*>::iterator it;
    for (it = sessions_.begin(); it != sessions_.end(); ++it) {
        SrsJanusSession* session = it->second;
        srs_freep(session);
    }
}

srs_error_t SrsJanusServer::listen_api()
{
    srs_error_t err = srs_success;

    // TODO: FIXME: Fetch api from hybrid manager, not from SRS.
    SrsHttpServeMux* http_api_mux = _srs_hybrid->srs()->instance()->api_server();

    SrsGoApiRtcJanus* handler = new SrsGoApiRtcJanus(this);

    if ((err = http_api_mux->handle("/janus", handler)) != srs_success) {
        return srs_error_wrap(err, "handle janus");
    }

    if ((err = http_api_mux->handle("/janus/", handler)) != srs_success) {
        return srs_error_wrap(err, "handle janus");
    }

    if ((err = _sls_callstack->initialize()) != srs_success) {
        return srs_error_wrap(err, "sls callstack");
    }

    if ((err = _sls_relation->initialize()) != srs_success) {
        return srs_error_wrap(err, "sls relation");
    }

    if ((err = _sls_data_statistic->initialize()) != srs_success) {
        return srs_error_wrap(err, "sls data statistic");
    }

    if ((err = _sls_downlink_bwe->initialize()) != srs_success) {
        return srs_error_wrap(err, "sls downlink bwe");
    }

    // Handle the session timeout event.
    rtc_->set_handler(this);

    return err;
}

srs_error_t SrsJanusServer::create(SrsJsonObject* req, SrsJanusMessage* msg, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    SrsJsonAny* prop = NULL;
    if ((prop = req->ensure_property_string("userID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no userID");
    }
    string userid = prop->to_str();

    if ((prop = req->ensure_property_string("appID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no appID");
    }
    string appid = prop->to_str();

    if ((prop = req->ensure_property_string("channelID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no channelID");
    }
    string channel = prop->to_str();

    if ((prop = req->ensure_property_string("sessionID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no sessionID");
    }
    string session_id = prop->to_str();

    // Switch to configure object.
    if ((prop = req->get_property("configure")) == NULL || !prop->is_object()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no configure");
    }
    SrsJanusUserConf* user_conf = SrsJanusUserConf::parse_janus_user_conf(req->get_property("configure")->to_object());

    // Switch to the session.
    SrsContextId cid = _srs_context->generate_id("sid", appid, session_id);
    _srs_context->bind(cid, "rtc janus session");
    _srs_context->set_id(cid);

    // Process message.
    SrsJanusSession* session = new SrsJanusSession(this, cid);
    session->appid_ = appid;
    session->channel_ = channel;
    session->userid_ = userid;
    session->sessionid_ = session_id;
    session->user_conf_ = user_conf;

    SrsJanusCreateSessionMessage* cs_msg = new SrsJanusCreateSessionMessage(session, msg, user_conf);
    SrsAutoFree(SrsJanusCreateSessionMessage, cs_msg);
    
    // For SIBI callstack SLS log. for enter
    cs_msg->write_callstack("enter", 0);

    do {
        srs_random_generate((char*)&session->id_, 8);
        session->id_ &= 0x7fffffffffffffffLL;
    } while (sessions_.find(session->id_) != sessions_.end());

    // TODO: FIXME: Cleanup sessions.
    sessions_[session->id_] = session;

    // Set response data.
    SrsJsonObject* data = SrsJsonAny::object();
    res->set("data", data);

    data->set("id", SrsJsonAny::integer((int64_t)session->id_));

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, appid=%s, channel=%s, userid=%s, session_id=%s, unified=%d, web=%s, profile=%s, session=%" PRId64,
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        appid.c_str(), channel.c_str(), userid.c_str(), session_id.c_str(), user_conf->need_unified_plan, user_conf->web_sdk.c_str(),
        user_conf->channel_profile.c_str(), session->id_);

    // write leave callstack log
    cs_msg->write_callstack("leave", 0);

    return err;
}

void SrsJanusServer::destroy(SrsJanusSession* session, SrsJanusMessage* msg)
{
    string appid = session->appid_;
    string channel = session->channel_;
    string userid = session->userid_;
    string session_id = session->sessionid_;
    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, appid=%s, channel=%s, userid=%s, session_id=%s, session=%" PRId64,
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        appid.c_str(), channel.c_str(), userid.c_str(), session_id.c_str(), session->id_);

    do_destroy(session);
}

void SrsJanusServer::do_destroy(SrsJanusSession* session)
{
    session->destroy();

    // Remove session from server and destroy it.
    map<uint64_t, SrsJanusSession*>::iterator it = sessions_.find(session->id_);
    if (it != sessions_.end()) {
        sessions_.erase(it);
    }

    srs_freep(session);
}

void SrsJanusServer::do_destroy_calls(SrsJanusSession* session, SrsRtcConnection* rtc_session)
{
    // Destroy the call which binding to rtc_session.
    session->destroy_calls(rtc_session);

    // If exists calls in session, do not destroy it.
    if (session->nn_calls()) {
        return;
    }

    // Remove session from server and destroy it.
    map<uint64_t, SrsJanusSession*>::iterator it = sessions_.find(session->id_);
    if (it != sessions_.end()) {
        sessions_.erase(it);
    }

    srs_freep(session);
}

SrsJanusSession* SrsJanusServer::fetch(uint64_t sid)
{
    map<uint64_t, SrsJanusSession*>::iterator it = sessions_.find(sid);
    if (it == sessions_.end()) {
        return NULL;
    }
    return it->second;
}

void SrsJanusServer::set_callee(SrsJanusCall* call)
{
    string ucid = call->session_->appid_ + "/" + call->session_->channel_ + "/" + srs_int2str(call->feed_id_);
    publishers_[ucid] = call;
}

void SrsJanusServer::destroy_callee(SrsJanusCall* call)
{
    string ucid = call->session_->appid_ + "/" + call->session_->channel_ + "/" + srs_int2str(call->feed_id_);

    std::map<std::string, SrsJanusCall*>::iterator it = publishers_.find(ucid);
    if (it != publishers_.end()) {
        publishers_.erase(it);
    }
}

SrsJanusCall* SrsJanusServer::callee(string appid, string channel, uint64_t feed_id)
{
    string ucid = appid + "/" + channel + "/" + srs_int2str(feed_id);
    map<string, SrsJanusCall*>::iterator it = publishers_.find(ucid);
    if (it == publishers_.end()) {
        return NULL;
    }
    return it->second;
}

void SrsJanusServer::on_timeout(SrsRtcConnection* rtc_session)
{
    map<uint64_t, SrsJanusSession*>::iterator it;
    for (it = sessions_.begin(); it != sessions_.end(); ++it) {
        SrsJanusSession* session = it->second;
        if (!session->find(rtc_session)) {
            continue;
        }

        string appid = session->appid_;
        string channel = session->channel_;
        string userid = session->userid_;
        string session_id = session->sessionid_;
        srs_trace("RTC janus timeout remove, appid=%s, channel=%s, userid=%s, session_id=%s, session=%" PRId64,
            appid.c_str(), channel.c_str(), userid.c_str(), session_id.c_str(), session->id_);

        do_destroy_calls(session, rtc_session);
        return;
    }
}

SrsJanusUserConf::SrsJanusUserConf()
{
}

SrsJanusUserConf::~SrsJanusUserConf()
{
}

bool SrsJanusUserConf::is_web_sdk()
{
    // If no configure info which client send to signaling when join,
    // consider as old client.
    if(no_extra_config_when_join) {
        return true;
    }

    if (!web_sdk.empty()) {
        return true;
    }

    return false;
}

SrsJanusUserConf* SrsJanusUserConf::parse_janus_user_conf(SrsJsonObject* req)
{
    SrsJanusUserConf* user_conf = new SrsJanusUserConf();
    SrsJsonAny* prop = NULL;

    if ((prop = req->get_property("DownlinkStreamMerge")) != NULL && prop->is_boolean()) {
        user_conf->stream_merge = prop->to_boolean();
    }

    if ((prop = req->get_property("1v1TccForwardEnable")) != NULL && prop->is_boolean()) {
        user_conf->enable_forward_twcc = prop->to_boolean();
    }

    if ((prop = req->get_property("NeedSDPUnified")) != NULL && prop->is_boolean()) {
        user_conf->need_unified_plan = prop->to_boolean();
    }

    if ((prop = req->get_property("EnableBWEStatusReport")) != NULL && prop->is_boolean()) {
        user_conf->enable_bwe_status_report = prop->to_boolean();
    }

    if ((prop = req->get_property("EnableVideoNackFECV1")) != NULL && prop->is_boolean()) {
        user_conf->enable_video_nack_rs_v1 = prop->to_boolean();
    }

    user_conf->no_extra_config_when_join = false;
    if ((prop = req->get_property("NoExtraConfig")) != NULL && prop->is_boolean()) {
        user_conf->no_extra_config_when_join = prop->to_boolean();
    }

    if ((prop = req->get_property("MPUSuperClientEnable")) != NULL && prop->is_boolean()) {
        user_conf->no_extra_config_when_join = prop->to_boolean();
    }

    if ((prop = req->ensure_property_string("WebSDK")) != NULL && prop->is_string()) {
        user_conf->web_sdk = prop->to_str();
    }

    if ((prop = req->ensure_property_string("channelprofile")) != NULL && prop->is_string()) {
        user_conf->channel_profile = prop->to_str();
    }

    return user_conf;
}

SrsJanusStreamInfo::SrsJanusStreamInfo()
{
    temporal_layers_ = 0;
    sub_streams_ = 0;
}

SrsJanusStreamInfo::~SrsJanusStreamInfo()
{
}

SrsJanusStreamInfo SrsJanusStreamInfo::parse_stream_info(SrsJsonObject* stream)
{
    SrsJanusStreamInfo stream_info;
    SrsJsonAny* prop = NULL;

    if ((prop = stream->get_property("mslabel")) != NULL && prop->is_string()) {
        stream_info.mslabel_ = prop->to_str();
    }

    if ((prop = stream->get_property("label")) != NULL && prop->is_string()) {
        stream_info.label_ = prop->to_str();
    }

    if ((prop = stream->get_property("type")) != NULL && prop->is_string()) {
        stream_info.type_ = prop->to_str();
    }

    if ((prop = stream->get_property("state")) != NULL && prop->is_string()) {
        stream_info.state_ = prop->to_str();
    }

    if ((prop = stream->get_property("temporalLayer")) != NULL && prop->is_number()) {
        stream_info.temporal_layers_ = prop->to_number();
    }

    if ((prop = stream->get_property("substream")) != NULL && prop->is_number()) {
        stream_info.sub_streams_ = prop->to_number();
    }

    if ((prop = stream->get_property("videoprofile")) != NULL && prop->is_string()) {
        stream_info.video_profile_ = prop->to_str();
    }

    if ((prop = stream->get_property("audioprofile")) != NULL && prop->is_string()) {
        stream_info.audio_profile_ = prop->to_str();
    }

    return stream_info;
}

SrsJanusSession::SrsJanusSession(SrsJanusServer* j, SrsContextId cid)
{
    id_ = 0;
    janus_ = j;
    cid_ = cid;
}

SrsJanusSession::~SrsJanusSession()
{
    if (true) {
        map<uint64_t, SrsJanusCall*>::iterator it;
        for (it = calls_.begin(); it != calls_.end(); ++it) {
            SrsJanusCall* call = it->second;
            srs_freep(call);
        }
    }

    if (true) {
        vector<SrsJanusMessage*>::iterator it;
        for (it = msgs_.begin(); it != msgs_.end(); ++it) {
            SrsJanusMessage* msg = *it;
            srs_freep(msg);
        }
    }

    srs_freep(user_conf_);
}

srs_error_t SrsJanusSession::polling(SrsJsonObject* req, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    if (msgs_.empty()) {
        // No data, keep-alive.
        srs_usleep(API_POLLING_LIMIT);
        res->set("janus", SrsJsonAny::str("keepalive"));
        srs_verbose("RTC polling, session=%" PRId64 ", keepalive", id_);
        return err;
    }

    SrsJanusMessage* msg = msgs_[0];
    SrsAutoFree(SrsJanusMessage, msg);
    msgs_.erase(msgs_.begin());

    if (msg->janus == "event") {
        res->set("janus", SrsJsonAny::str(msg->janus.c_str()));
        res->set("session_id", SrsJsonAny::integer(msg->session_id));
        res->set("sender", SrsJsonAny::integer(msg->sender));
        res->set("transaction", SrsJsonAny::str(msg->transaction.c_str()));

        SrsJsonObject* plugindata = SrsJsonAny::object();
        res->set("plugindata", plugindata);
        plugindata->set("plugin", SrsJsonAny::str(msg->plugin.c_str()));

        SrsJsonObject* data = SrsJsonAny::object();
        plugindata->set("data", data);
        if (msg->videoroom == "joined") {
            // Attach to plugin.
            data->set("videoroom", SrsJsonAny::str("joined"));
            data->set("id", SrsJsonAny::integer(msg->feed_id));
            data->set("private_id", SrsJsonAny::integer(msg->private_id));
        } else if (msg->videoroom == "configured") {
            // Answer as publisher
            data->set("videoroom", SrsJsonAny::str("event"));
            data->set("configured", SrsJsonAny::str("ok"));

            SrsJsonObject* jsep = SrsJsonObject::object();
            res->set("jsep", jsep);
            jsep->set("type", SrsJsonAny::str(msg->jsep_type.c_str()));
            jsep->set("sdp", SrsJsonAny::str(msg->jsep_sdp.c_str()));
        } else if (msg->videoroom == "attached") {
            // Offer as subscriber.
            data->set("videoroom", SrsJsonAny::str("attached"));
            data->set("id", SrsJsonAny::integer(msg->feed_id));
            data->set("display", SrsJsonAny::str(msg->display.c_str()));

            SrsJsonObject* jsep = SrsJsonObject::object();
            res->set("jsep", jsep);
            jsep->set("type", SrsJsonAny::str(msg->jsep_type.c_str()));
            jsep->set("sdp", SrsJsonAny::str(msg->jsep_sdp.c_str()));
        } else if (msg->videoroom == "started") {
            // Answer as subscriber.
            data->set("videoroom", SrsJsonAny::str("event"));
            data->set("started", SrsJsonAny::str("ok"));
        } else if (msg->videoroom == "event") {
            // reconfig-publisher and reconfig-subscriber
            data->set("videoroom", SrsJsonAny::str("event"));
            data->set("reconfigured", SrsJsonAny::str("ok"));
        }

        srs_trace("RTC polling, session=%" PRId64 ", janus=%s, sender=%" PRId64 ", transaction=%s, feed=%" PRId64 ", private=%u",
            id_, msg->janus.c_str(), msg->sender, msg->transaction.c_str(), msg->feed_id, msg->private_id);
    } else if (msg->janus == "webrtcup") {
    } else if (msg->janus == "media") {
    } else if (msg->janus == "keepalive") {
    } else if (msg->janus == "hangup") {
    } else if (msg->janus == "detached") {
    }

    return err;
}

void SrsJanusSession::enqueue(SrsJanusMessage* msg)
{
    msgs_.push_back(msg);
}

srs_error_t SrsJanusSession::attach(SrsJsonObject* req, SrsJanusMessage* msg, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    SrsJsonAny* prop = NULL;
    if ((prop = req->ensure_property_string("plugin")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no plugin");
    }
    string plugin = prop->to_str();

    if ((prop = req->ensure_property_string("opaque_id")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no opaque_id");
    }
    string opaque_id = prop->to_str();

    if ((prop = req->get_property("force-bundle")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no force-bundle");
    }
    bool force_bundle = prop->to_boolean();

    if ((prop = req->get_property("force-rtcp-mux")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no force-rtcp-mux");
    }
    bool force_rtcp_mux = prop->to_boolean();

    if ((prop = req->ensure_property_string("callID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no callID");
    }
    string callid = prop->to_str();

    // We do not know the call type(pub or sub), so we reuse the cid of session.
    SrsContextId cid = _srs_context->get_id();

    // Process message.
    SrsJanusCall* call = new SrsJanusCall(this, cid);
    call->callid_ = callid;

    SrsJanusAttachMessage* attach_msg = new SrsJanusAttachMessage(call, msg);
    SrsAutoFree(SrsJanusAttachMessage, attach_msg);
    
    // Write enter callstack log.
    attach_msg->write_callstack("enter", 0);

    do {
        srs_random_generate((char*)&call->id_, 8);
        call->id_ &= 0x7fffffffffffffffLL;
    } while (janus_->fetch(call->id_) || calls_.find(call->id_) != calls_.end());

    // TODO: FIXME: Cleanup calls.
    calls_[call->id_] = call;

    // Set response data.
    SrsJsonObject* data = SrsJsonAny::object();
    res->set("data", data);

    data->set("id", SrsJsonAny::integer((int64_t)call->id_));

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, plugin=%s, opaque_id=%s, force_bundle=%d, force_rtcp_mux=%d, callid=%s, call=%" PRId64,
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        plugin.c_str(), opaque_id.c_str(), force_bundle, force_rtcp_mux, callid.c_str(), call->id_);

    // Write leave callstack log
    attach_msg->write_callstack("leave", 0);

    return err;
}

srs_error_t SrsJanusSession::detach(SrsJanusMessage* msg, uint64_t callid) 
{
    srs_error_t err = srs_success;
    map<uint64_t, SrsJanusCall*>::iterator it = calls_.find(callid);
    if (it == calls_.end()) {
        return err;
    }

    SrsJanusCall* call = it->second;
    if (call->publisher_) {
        janus_->destroy_callee(call);
    }

    // write detach callstack log before call destroy.
    SrsJanusDetachMessage(call, msg, callid).write_callstack("leave", 0);
    
    call->destroy();
    calls_.erase(it);
    srs_freep(call);

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, call=%" PRId64,
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(), callid);
    
    return err;
}

SrsJanusCall* SrsJanusSession::fetch(uint64_t sid)
{
    map<uint64_t, SrsJanusCall*>::iterator it = calls_.find(sid);
    if (it == calls_.end()) {
        return NULL;
    }
    return it->second;
}

SrsJanusCall* SrsJanusSession::find(SrsRtcConnection* session)
{
    map<uint64_t, SrsJanusCall*>::iterator it;
    for (it = calls_.begin(); it != calls_.end(); ++it) {
        SrsJanusCall* call = it->second;
        if (call->rtc_session_ == session) {
            return call;
        }
    }

    return NULL;
}

int SrsJanusSession::nn_calls()
{
    return (int)calls_.size();
}

void SrsJanusSession::destroy()
{
    map<uint64_t, SrsJanusCall*>::iterator it;
    for (it = calls_.begin(); it != calls_.end(); ++it) {
        SrsJanusCall* call = it->second;

        // For publisher, destroy the callee in server.
        if (call->publisher_) {
            janus_->destroy_callee(call);
        }

        call->destroy();
    }
}

void SrsJanusSession::destroy_calls(SrsRtcConnection* session)
{
    map<uint64_t, SrsJanusCall*>::iterator it;
    for (it = calls_.begin(); it != calls_.end();++it) {
        SrsJanusCall* call = it->second;
        if (call->rtc_session_ != session) {
            continue;
        } 
        
        // For publisher, destroy the callee in server.
        if (call->publisher_) {
            janus_->destroy_callee(call);
        }

        call->destroy();
        calls_.erase(it++);
        srs_freep(call);
        
        return;  
    }
}

uint32_t SrsJanusCall::ssrc_num = 0;

SrsJanusCall::SrsJanusCall(SrsJanusSession* s, SrsContextId cid)
{
    id_ = 0;
    session_ = s;
    parent_cid_ = cid;
    cid_ = cid;

    publisher_ = false;
    rtc_session_ = NULL;
}

SrsJanusCall::~SrsJanusCall()
{
}

void SrsJanusCall::destroy()
{
    // Note that the rtc_session_ will be freed by rtc server.
    if (rtc_session_) {
        session_->janus_->rtc_->destroy(rtc_session_);
    }
}

srs_error_t SrsJanusCall::message(SrsJsonObject* req, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    // Switch to body object.
    SrsJsonAny* prop = NULL;
    if ((prop = req->get_property("body")) == NULL || !prop->is_object()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "body");
    }
    SrsJsonObject* body = prop->to_object();

    if ((prop = body->ensure_property_string("request")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no request");
    }
    string request = prop->to_str();

    if (request == "join") {
        return on_join_message(body, msg);
    } else if (request == "configure") {
        return on_configure_publisher(req, body, msg);
    } else if (request == "start") {
        SrsJanusProcessAnswerMessage answer_msg = SrsJanusProcessAnswerMessage(this, msg);
        answer_msg.write_callstack("enter", 0);

        err = on_start_subscriber(req, body, msg);

        answer_msg.write_callstack("leave", err->error_code(err));
        return err;
    } else if (request == "reconfig-publisher") {
        return on_reconfigure_publisher(req, body, msg);
    } else if (request == "reconfig-subscriber" || request == "reconfig-stream") {
        return on_reconfigure_subscriber(req, body, msg);
    } else {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "request %s", request.c_str());
    }

    return err;
}

srs_error_t SrsJanusCall::trickle(SrsJsonObject* req, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    // Switch to candidate object.
    SrsJsonAny* prop = NULL;
    if ((prop = req->get_property("candidate")) == NULL || !prop->is_object()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "candidate");
    }
    req = prop->to_object();

    bool completed = false;
    if ((prop = req->get_property("completed")) != NULL && prop->is_boolean()) {
        completed = prop->to_boolean();
    }

    string candidate;
    if (!completed) {
        if ((prop = req->ensure_property_string("candidate")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no candidate");
        }
        candidate = prop->to_str();
    }

    SrsJanusTrickleMessage* trikle_msg = new SrsJanusTrickleMessage(this, msg, candidate, completed);
    SrsAutoFree(SrsJanusTrickleMessage, trikle_msg);

    // Write enter callstack log.
    trikle_msg->write_callstack("enter", 0);

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, completed=%d, candidate=%s",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        completed, candidate.c_str());

    // Write leave callstack log
    trikle_msg->write_callstack("leave", 0);

    return err;
}

SrsSdp* SrsJanusCall::get_remote_sdp()
{
    return rtc_session_->get_remote_sdp();
}

srs_error_t SrsJanusCall::on_join_message(SrsJsonObject* req, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    SrsJsonAny* prop = NULL;
    if ((prop = req->ensure_property_string("ptype")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no ptype");
    }
    string ptype = prop->to_str();

    if (ptype != "publisher" && ptype != "listener") {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "invalid ptype=%s", ptype.c_str());
    }
    publisher_ = (ptype == "publisher");

    if (ptype == "publisher") {
        if ((prop = req->get_property("feed_id")) == NULL || !prop->is_integer()) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no feed_id");
        }
        uint64_t feed_id = prop->to_integer();

        if ((prop = req->ensure_property_string("display")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no display");
        }
        string display = prop->to_str();

        SrsJanusMessage* res_msg = new SrsJanusMessage();
        res_msg->janus = "event";
        res_msg->session_id = session_->id_;
        res_msg->sender = id_;
        res_msg->transaction = msg->transaction;
        res_msg->plugin = "janus.plugin.videoroom";
        res_msg->videoroom = "joined";
        res_msg->feed_id = feed_id;
        srs_random_generate((char*)&res_msg->private_id, 4);
        session_->enqueue(res_msg);

        display_ = display;
        feed_id_ = feed_id;
        session_->janus_->set_callee(this);

        SrsJanusJoinMessage* join_msg = new SrsJanusJoinMessage(this, msg, ptype, "success");
        SrsAutoFree(SrsJanusJoinMessage, join_msg);

        // Write enter callstack log.
        join_msg->write_callstack("enter", 0);

        srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, request=%s, ptype=%s, feed_id=%" PRId64 ", display=%s, sender=%" PRId64 ", private=%u, publisher=%d",
            msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
            "join", ptype.c_str(), feed_id, display.c_str(), res_msg->sender, res_msg->private_id, publisher_);
        
        // Write enter callstack log.
        join_msg->write_callstack("leave", 0);
    } else {
        return on_join_as_subscriber(req, msg);
    }

    return err;
}

srs_error_t SrsJanusCall::on_join_as_subscriber(SrsJsonObject* req, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    // Find the callee in room.
    SrsJsonAny* prop = NULL;
    if ((prop = req->get_property("feed")) == NULL || !prop->is_integer()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no feed");
    }
    uint64_t feed_id = prop->to_integer();

    SrsJanusCall* callee = session_->janus_->callee(session_->appid_, session_->channel_, feed_id);
    if (!callee) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no callee feed_id=%" PRId64, feed_id);
    }

    if ((prop = req->get_property("audio")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no audio");
    }
    bool audio = prop->to_boolean();

    if ((prop = req->get_property("video")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no video");
    }
    bool video = prop->to_boolean();

    if ((prop = req->get_property("offer_audio")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no offer_audio");
    }
    bool offer_audio = prop->to_boolean();

    if ((prop = req->get_property("offer_video")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no offer_video");
    }
    bool offer_video = prop->to_boolean();

    if ((prop = req->get_property("streams")) == NULL || !prop->is_array()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no streams");
    }
    SrsJsonArray* streams = prop->to_array();

    std::ostringstream log_stream;
    // parser stream infos
    std::vector<SrsTrackConfig> track_cfgs;
    for (int i = 0; i < streams->count(); i++) {
        SrsJsonAny* stream = streams->at(i);
        if (!stream->is_object()) {
            continue;
        }

        SrsJsonObject* obj = streams->at(i)->to_object();
        SrsTrackConfig cfg = SrsTrackConfig::parse(obj);
        track_cfgs.push_back(cfg);

        log_stream << "{ type=" << cfg.type_
                   << ", label=" << cfg.label_
                   << ", active=" << cfg.active
                   << " }, ";
    }

    // Generate new context for publisher.
    cid_ = _srs_context->generate_id("sub", parent_cid_);
    _srs_context->set_id(cid_);

    // TODO: FIXME: We should apply appid.
    request.app = session_->appid_ + string(":") + session_->channel_;
    request.stream = callee->callid_;
    srs_trace("RTC janus play stream=/%s/%s, feed_id=%" PRId64 ", self=%" PRId64 ", track config=%s",
        request.app.c_str(), request.stream.c_str(), callee->feed_id_, feed_id_, log_stream.str().c_str());

    // TODO: FIXME: Parse vhost.
    // discovery vhost, resolve the vhost from config
    SrsConfDirective* parsed_vhost = _srs_config->get_vhost("");
    if (parsed_vhost) {
        request.vhost = parsed_vhost->arg0();
    }

    // Whether enabled.
    bool server_enabled = _srs_config->get_rtc_server_enabled();
    bool rtc_enabled = _srs_config->get_rtc_enabled(request.vhost);
    if (server_enabled && !rtc_enabled) {
        srs_warn("RTC disabled in vhost %s", request.vhost.c_str());
    }
    if (!server_enabled || !rtc_enabled) {
        return srs_error_new(ERROR_RTC_DISABLED, "Disabled server=%d, rtc=%d, vhost=%s",
            server_enabled, rtc_enabled, request.vhost.c_str());
    }

    // Generate offer.
    SrsSdp local_sdp;
    local_sdp.session_config_.dtls_role = _srs_config->get_rtc_dtls_version(request.vhost);
    local_sdp.session_config_.dtls_version = _srs_config->get_rtc_dtls_version(request.vhost);
    if (!session_->user_conf_->is_web_sdk()) {
        local_sdp.session_config_.dtls_role = "active";
        local_sdp.session_config_.dtls_version = "dtls1.0";
    }

    // TODO: FIXME: When server enabled, but vhost disabled, should report error.
    string mock_eip; // No MOCK EIP for janus.
    if ((err = session_->janus_->rtc_->create_session2(&request, local_sdp, mock_eip, &rtc_session_)) != srs_success) {
        return srs_error_wrap(err, "create session");
    }

    // for set_play_track_active write sub_stream_relation callstack log.
    // set_rtc_callid before set_play_track_active.
    if (true) {
        SrsRtcCallTraceId id;
        id.appid = session_->appid_;
        id.channel = session_->channel_;
        id.user = session_->userid_;
        id.session = session_->sessionid_;
        id.call = callid_;

        rtc_session_->set_rtc_callid(id);
    }

    if (!track_cfgs.empty()) {
        rtc_session_->set_play_track_active(track_cfgs);
    }

    ostringstream os;
    if ((err = local_sdp.encode(os)) != srs_success) {
        return srs_error_wrap(err, "encode sdp");
    }
    string local_sdp_str = os.str();

    SrsJanusMessage* res_msg = new SrsJanusMessage();
    res_msg->janus = "event";
    res_msg->session_id = session_->id_;
    res_msg->sender = id_;
    res_msg->transaction = msg->transaction;
    res_msg->plugin = "janus.plugin.videoroom";
    res_msg->videoroom = "attached";
    res_msg->feed_id = callee->feed_id_;
    res_msg->display = callee->display_;
    res_msg->jsep_type = "offer";
    res_msg->jsep_sdp = local_sdp_str;
    srs_random_generate((char*)&res_msg->private_id, 4);
    session_->enqueue(res_msg);

    SrsJanusJoinMessage* join_msg = new SrsJanusJoinMessage(this, msg, "listener", "success");
    SrsAutoFree(SrsJanusJoinMessage, join_msg);

    // Write enter callstack log.
    join_msg->write_callstack("enter", 0);

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, request=%s, ptype=%s, callee(feed_id=%" PRId64 ", display=%s), audio=%d/%d, video=%d/%d, streams=%d, sender=%" PRId64 ", private=%u, publisher=%d, offer=%dB, cid=[%u][%s]",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        "join", "listener", callee->feed_id_, callee->display_.c_str(), audio, offer_audio, video, offer_video, streams->count(),
        res_msg->sender, res_msg->private_id, publisher_, local_sdp_str.length(), ::getpid(), rtc_session_->context_id().c_str());
    srs_trace("RTC local offer: %s", srs_string_replace(local_sdp_str.c_str(), "\r\n", "\\r\\n").c_str());

    // Write enter callstack log.
    join_msg->write_callstack("leave", 0);

    //TODO: FIXME: add error check
    write_sub_relations(&request, callee, &local_sdp);

    return err;
}

srs_error_t SrsJanusCall::subscirber_build_offer(SrsRequest* req, SrsJanusCall* callee, SrsSdp& local_sdp)
{
    srs_error_t err = srs_success;

    local_sdp.version_ = "0";

    local_sdp.username_        = RTMP_SIG_SRS_SERVER;
    local_sdp.session_id_      = srs_int2str(session_->id_);
    local_sdp.session_version_ = "2";
    local_sdp.nettype_         = "IN";
    local_sdp.addrtype_        = "IP4";
    local_sdp.unicast_address_ = "0.0.0.0";

    local_sdp.session_name_ = "TenfoldPlaySession";

    local_sdp.msid_semantic_ = "WMS";
    local_sdp.msids_.push_back(req->app + "/" + req->stream);

    local_sdp.group_policy_ = "BUNDLE";

    bool nack_enabled = _srs_config->get_rtc_nack_enabled(req->vhost);

    // TODO: FIXME: Avoid SSRC collision.
    if (!ssrc_num) {
        ssrc_num = ::getpid() * 10000 + ::getpid() * 100 + ::getpid();
    }

    SrsSdp* remote_sdp = callee->get_remote_sdp();
    // The msid/mslabel for MediaStream, we use the callee.
    string mslabel = callee->callid_;

    for (size_t i = 0; i < remote_sdp->media_descs_.size(); ++i) {
        const SrsMediaDesc& remote_media_desc = remote_sdp->media_descs_[i];

        if (remote_media_desc.is_audio()) {
            local_sdp.media_descs_.push_back(SrsMediaDesc("audio"));
        } else if (remote_media_desc.is_video()) {
            local_sdp.media_descs_.push_back(SrsMediaDesc("video"));
        }

        SrsMediaDesc& local_media_desc = local_sdp.media_descs_.back();
        map<int, std::string> extmap = remote_media_desc.get_extmaps();
        for(map<int, std::string>::iterator it = extmap.begin(); it != extmap.end(); ++it) {
            if(kTWCCExt == it->second) {
                local_media_desc.extmaps_[it->first] = kTWCCExt;
            }
        }

        if (remote_media_desc.is_audio()) {
            std::vector<SrsMediaPayloadType> payloads = remote_media_desc.find_media_with_encoding_name("red");
            for (std::vector<SrsMediaPayloadType>::iterator iter = payloads.begin(); iter != payloads.end(); ++iter) {
                local_media_desc.payload_types_.push_back(*iter);
                // Only choose one match opus red codec.
                break;
            }

            payloads = remote_media_desc.find_media_with_encoding_name("opus");
            for (std::vector<SrsMediaPayloadType>::iterator iter = payloads.begin(); iter != payloads.end(); ++iter) {
                local_media_desc.payload_types_.push_back(*iter);
                SrsMediaPayloadType& payload_type = local_media_desc.payload_types_.back();

                // TODO: FIXME: add support some transport algorithms. e.g. nack, nack pli, transport cc...
                vector<string> rtcp_fb;
                payload_type.rtcp_fb_.swap(rtcp_fb);
                for (int j = 0; j < (int)rtcp_fb.size(); j++) {
                    if (nack_enabled) {
                        if (rtcp_fb.at(j) == "nack" || rtcp_fb.at(j) == "nack pli") {
                            payload_type.rtcp_fb_.push_back(rtcp_fb.at(j));
                        }
                    }
                }
                // Only choose one match opus codec.
                break;
            }

            if (local_media_desc.payload_types_.empty()) {
                return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "no found valid opus payload type");
            }
        } else if (remote_media_desc.is_video()) {
            std::deque<SrsMediaPayloadType> backup_payloads;
            std::vector<SrsMediaPayloadType> payloads = remote_media_desc.find_media_with_encoding_name("H264");

            for (std::vector<SrsMediaPayloadType>::iterator iter = payloads.begin(); iter != payloads.end(); ++iter) {
                if (iter->format_specific_param_.empty()) {
                    backup_payloads.push_front(*iter);
                    continue;
                }
                H264SpecificParam h264_param;
                if ((err = srs_parse_h264_fmtp(iter->format_specific_param_, h264_param)) != srs_success) {
                    srs_error_reset(err); continue;
                }

                // Try to pick the "best match" H.264 payload type.
                if (h264_param.packetization_mode == "1" && h264_param.level_asymmerty_allow == "1") {
                    local_media_desc.payload_types_.push_back(*iter);
                    SrsMediaPayloadType& payload_type = local_media_desc.payload_types_.back();

                    // TODO: FIXME: add support some transport algorithms. e.g. nack, nack pli, transport cc...
                    vector<string> rtcp_fb;
                    payload_type.rtcp_fb_.swap(rtcp_fb);
                    for (int j = 0; j < (int)rtcp_fb.size(); j++) {
                        if (nack_enabled) {
                            if (rtcp_fb.at(j) == "nack" || rtcp_fb.at(j) == "nack pli") {
                                payload_type.rtcp_fb_.push_back(rtcp_fb.at(j));
                            }
                        }
                    }
                    // Only choose first match H.264 payload type.
                    break;
                }

                backup_payloads.push_back(*iter);
            }
            // Try my best to pick at least one media payload type.
            if (local_media_desc.payload_types_.empty() && ! backup_payloads.empty()) {
                srs_warn("choose backup H.264 payload type=%d", backup_payloads.front().payload_type_);
                local_media_desc.payload_types_.push_back(backup_payloads.front());
            }

            if (local_media_desc.payload_types_.empty()) {
                return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "no found valid H.264 payload type");
            }
        }

        local_media_desc.mid_ = remote_media_desc.mid_;
        local_sdp.groups_.push_back(local_media_desc.mid_);

        local_media_desc.port_ = 9;
        local_media_desc.protos_ = "UDP/TLS/RTP/SAVPF";

        // Offerer must use actpass value for setup attribute.
        local_media_desc.session_info_.setup_ = "actpass";
        local_media_desc.rtcp_mux_ = true;
        // For subscriber, we are sendonly.
        local_media_desc.sendonly_ = true;
        local_media_desc.recvonly_ = false;
        local_media_desc.sendrecv_ = false;
        local_media_desc.rtcp_rsize_ = false;

        // find sub_stream
        std::vector<SrsSSRCInfo> sub_specified_streams;
        std::vector<SrsSSRCInfo>::const_iterator it;
        for (it = remote_media_desc.ssrc_infos_.begin(); it != remote_media_desc.ssrc_infos_.end(); ++it) {
            if (it->msid_tracker_ == "") {
                sub_specified_streams.push_back(*it);
                SrsSSRCInfo& ssrc_info = sub_specified_streams.back();
                ssrc_info.ssrc_ = ++ssrc_num;
                continue;
            }

            std::vector<SrsJanusStreamInfo>::iterator it_stream;
            for (it_stream = stream_infos_.begin(); it_stream != stream_infos_.end(); ++it_stream) {
                if(remote_media_desc.is_audio() && it_stream->type_ == "audio") {
                    if (it_stream->label_ == it->label_) {
                        sub_specified_streams.push_back(*it);
                        SrsSSRCInfo& ssrc_info = sub_specified_streams.back();
                        ssrc_info.ssrc_ = ++ssrc_num;
                    }
                } else if (remote_media_desc.is_video() && it_stream->type_ == "video") {
                    if (it_stream->label_ == it->label_) {
                        sub_specified_streams.push_back(*it);
                        SrsSSRCInfo& ssrc_info = sub_specified_streams.back();
                        ssrc_info.ssrc_ = ++ssrc_num;
                    }
                }
            }
        }

        if (sub_specified_streams.size()) {
            // Native-SDK
            sub_specified_streams.swap(local_media_desc.ssrc_infos_);
        } else {
            // H5Demo
            SrsSSRCInfo ssrc_info;
            ssrc_info.ssrc_ = ++ssrc_num;
            if (remote_media_desc.is_audio()) {
                ssrc_info.cname_ = "sophonaudio";
                ssrc_info.label_ = srs_random_str(16);
                ssrc_info.mslabel_ = mslabel;
                ssrc_info.msid_ = ssrc_info.mslabel_;
                ssrc_info.msid_tracker_ = ssrc_info.label_;
            } else if (remote_media_desc.is_video()){
                ssrc_info.cname_ = "sophonvideo";
                ssrc_info.label_ = srs_random_str(16);
                ssrc_info.mslabel_ = mslabel;
                ssrc_info.msid_ = ssrc_info.mslabel_;
                ssrc_info.msid_tracker_ = ssrc_info.label_;
            }
        
            local_media_desc.ssrc_infos_.push_back(ssrc_info);
        }
    }

    return err;
}

srs_error_t SrsJanusCall::on_start_subscriber(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    SrsJsonAny* prop = NULL;
    if ((prop = req->get_property("jsep")) == NULL || !prop->is_object()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no jsep");
    }
    SrsJsonObject* jsep = prop->to_object();

    if ((prop = jsep->ensure_property_string("type")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no jsep.type");
    }
    string type = prop->to_str();

    if ((prop = jsep->ensure_property_string("sdp")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no jsep.sdp");
    }
    string remote_sdp_str = prop->to_str();

    if (!rtc_session_) {
        return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "no session");
    }

    // TODO: FIXME: It seems remote_sdp doesn't represents the full SDP information.
    SrsSdp remote_sdp;
    if ((err = remote_sdp.parse(remote_sdp_str)) != srs_success) {
        return srs_error_wrap(err, "parse sdp failed: %s", remote_sdp_str.c_str());
    }

    if ((err = session_->janus_->rtc_->setup_session2(rtc_session_, &request, remote_sdp)) != srs_success) {
        return srs_error_wrap(err, "setup session");
    }

    SrsJanusMessage* res_msg = new SrsJanusMessage();
    res_msg->janus = "event";
    res_msg->session_id = session_->id_;
    res_msg->sender = id_;
    res_msg->transaction = msg->transaction;
    res_msg->plugin = "janus.plugin.videoroom";
    res_msg->videoroom = "started";
    srs_random_generate((char*)&res_msg->private_id, 4);
    session_->enqueue(res_msg);

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, request=%s, jsep=%s/%dB",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        "start", type.c_str(), remote_sdp_str.length());
    srs_trace("RTC remote answer: %s", srs_string_replace(remote_sdp_str.c_str(), "\r\n", "\\r\\n").c_str());

    return err;
}

srs_error_t SrsJanusCall::on_configure_publisher(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    SrsJsonAny* prop = NULL;
    if ((prop = body->get_property("audio")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no audio");
    }
    bool has_audio = prop->to_boolean();

    if ((prop = body->get_property("video")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no video");
    }
    bool has_video = prop->to_boolean();

    if ((prop = body->get_property("streams")) == NULL || !prop->is_array()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no streams");
    }
    SrsJsonArray* streams = prop->to_array();

    if ((prop = req->get_property("jsep")) == NULL || !prop->is_object()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no jsep");
    }
    SrsJsonObject* jsep = prop->to_object();

    if ((prop = jsep->ensure_property_string("type")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no jsep.type");
    }
    string type = prop->to_str();

    if ((prop = jsep->ensure_property_string("sdp")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no jsep.sdp");
    }
    string remote_sdp_str = prop->to_str();

    // For client to specifies the EIP of server.
    string eip;

    // Generate new context for publisher.
    cid_ = _srs_context->generate_id("pub", parent_cid_);
    _srs_context->set_id(cid_);

    // TODO: FIXME: We should apply appid.
    request.app = session_->appid_ + string(":") + session_->channel_;
    request.stream = callid_;
    srs_trace("RTC janus publish stream=/%s/%s, feed_id=%" PRId64,
        request.app.c_str(), request.stream.c_str(), feed_id_);

    // TODO: FIXME: Parse vhost.
    // discovery vhost, resolve the vhost from config
    SrsConfDirective* parsed_vhost = _srs_config->get_vhost("");
    if (parsed_vhost) {
        request.vhost = parsed_vhost->arg0();
    }

    // Whether enabled.
    bool server_enabled = _srs_config->get_rtc_server_enabled();
    bool rtc_enabled = _srs_config->get_rtc_enabled(request.vhost);
    if (server_enabled && !rtc_enabled) {
        srs_warn("RTC disabled in vhost %s", request.vhost.c_str());
    }
    if (!server_enabled || !rtc_enabled) {
        return srs_error_new(ERROR_RTC_DISABLED, "Disabled server=%d, rtc=%d, vhost=%s",
            server_enabled, rtc_enabled, request.vhost.c_str());
    }

    // TODO: FIXME: It seems remote_sdp doesn't represents the full SDP information.
    SrsSdp remote_sdp;
    if ((err = remote_sdp.parse(remote_sdp_str)) != srs_success) {
        return srs_error_wrap(err, "parse sdp failed: %s", remote_sdp_str.c_str());
    }

    SrsSdp local_sdp;
    local_sdp.session_config_.dtls_role = _srs_config->get_rtc_dtls_role(request.vhost);
    local_sdp.session_config_.dtls_version = _srs_config->get_rtc_dtls_version(request.vhost);
    if (!session_->user_conf_->is_web_sdk()) {
        local_sdp.session_config_.dtls_role = "active";
        local_sdp.session_config_.dtls_version = "dtls1.0";
    }

    // TODO: FIXME: When server enabled, but vhost disabled, should report error.
    if ((err = session_->janus_->rtc_->create_session(&request, remote_sdp, local_sdp, eip, true, &rtc_session_)) != srs_success) {
        return srs_error_wrap(err, "create session");
    }

    if (true) {
        SrsRtcCallTraceId id;
        id.appid = session_->appid_;
        id.channel = session_->channel_;
        id.user = session_->userid_;
        id.session = session_->sessionid_;
        id.call = callid_;
        
        rtc_session_->set_rtc_callid(id);
    }

    ostringstream os;
    if ((err = local_sdp.encode(os)) != srs_success) {
        return srs_error_wrap(err, "encode sdp");
    }
    string local_sdp_str = os.str();

    SrsJanusMessage* res_msg = new SrsJanusMessage();
    res_msg->janus = "event";
    res_msg->session_id = session_->id_;
    res_msg->sender = id_;
    res_msg->transaction = msg->transaction;
    res_msg->plugin = "janus.plugin.videoroom";
    res_msg->videoroom = "configured";
    res_msg->jsep_type = "answer";
    res_msg->jsep_sdp = local_sdp_str;
    srs_random_generate((char*)&res_msg->private_id, 4);
    session_->enqueue(res_msg);

    SrsJanusProcessOfferMessage* offer_msg = new SrsJanusProcessOfferMessage(this, msg);
    SrsAutoFree(SrsJanusProcessOfferMessage, offer_msg);

    // Write enter callstack log.
    offer_msg->write_callstack("enter", 0);

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, request=%s, audio=%d, video=%d, streams=%d, jsep=%s/%dB, answer=%dB, cid=[%u][%s]",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        "configure", has_audio, has_video, streams->count(), type.c_str(), remote_sdp_str.length(), local_sdp_str.length(), ::getpid(), rtc_session_->context_id().c_str());
    srs_trace("RTC remote offer: %s", srs_string_replace(remote_sdp_str.c_str(), "\r\n", "\\r\\n").c_str());
    srs_trace("RTC local answer: %s", srs_string_replace(local_sdp_str.c_str(), "\r\n", "\\r\\n").c_str());

    // Write enter callstack log.
    offer_msg->write_callstack("leave", 0);

    return err;
}

srs_error_t SrsJanusCall::on_reconfigure_publisher(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    // reconfig-publisher stream_info:
    // {"request":"reconfig-publisher","streams":[
    //     {"mslabel":"sophon_stream","label":"sophon_video_camera_large","type":"video","temporalLayers":3,"substreams":1,"state":"active","videoprofile":"UD_640_480P_15","audioprofile":""},
    //     {"mslabel":"sophon_stream","label":"sophon_video_camera_small","type":"video","temporalLayers":3,"substreams":1,"state":"active","videoprofile":"UD_90_160P_15","audioprofile":""},
    //     {"mslabel":"sophon_stream","label":"sophon_video_screen_share","type":"video","temporalLayers":3,"substreams":1,"state":"active","videoprofile":"UD_2880_1800P_5","audioprofile":""},
    //     {"mslabel":"sophon_stream","label":"sophon_video_camera_super","type":"video","temporalLayers":3,"substreams":1,"state":"inactive","videoprofile":"UD_640_480P_15","audioprofile":""},
    //     {"mslabel":"sophon_stream","label":"sophon_audio","type":"audio","temporalLayers":0,"substreams":0,"state":"active","videoprofile":"","audioprofile":"ENGINE_BASIC_QUALITY_MODE"}
    // ]}
    SrsJsonAny* prop = NULL;
    if ((prop = body->get_property("streams")) == NULL || !prop->is_array()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no streams");
    }
    SrsJsonArray* streams = prop->to_array();

    // parser stream infos
    std::ostringstream log_stream;
    std::vector<SrsTrackConfig> track_cfgs;
    for (int i = 0; i < streams->count(); i++) {
        SrsJsonAny* stream = streams->at(i);
        if (!stream->is_object()) {
            continue;
        }

        SrsJsonObject* obj = streams->at(i)->to_object();
        SrsTrackConfig cfg = SrsTrackConfig::parse(obj);
        track_cfgs.push_back(cfg);

        log_stream << "{ type=" << cfg.type_ 
                   << ", label=" << cfg.label_ 
                   << ", active=" << cfg.active
                   << " }, ";
    }

    if (!track_cfgs.empty()) {
        rtc_session_->set_play_track_active(track_cfgs);
    }

    SrsJanusMessage* res_msg = new SrsJanusMessage();
    res_msg->janus = "event";
    res_msg->session_id = session_->id_;
    res_msg->sender = id_;
    res_msg->transaction = msg->transaction;
    res_msg->plugin = "janus.plugin.videoroom";
    res_msg->videoroom = "event";
    res_msg->reconfigured = "ok";
    srs_random_generate((char*)&res_msg->private_id, 4);
    session_->enqueue(res_msg);

    srs_trace("RTC janus %s transaction %s, tid=%s, rpc=%s, module=%s, request=%s, streams=%d, stream_info=%s",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        "reconfig-publisher", streams->count(), log_stream.str().c_str());

    return err;
}

srs_error_t SrsJanusCall::on_reconfigure_subscriber(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    // reconfig-publisher stream_info:
    // {"request":"reconfig-publisher","streams":[
    //     {"mslabel":"sophon_stream","label":"sophon_video_camera_large","type":"video","temporalLayers":3,"substreams":1,"state":"active","videoprofile":"UD_640_480P_15","audioprofile":""},
    //     {"mslabel":"sophon_stream","label":"sophon_video_camera_small","type":"video","temporalLayers":3,"substreams":1,"state":"active","videoprofile":"UD_90_160P_15","audioprofile":""},
    //     {"mslabel":"sophon_stream","label":"sophon_video_screen_share","type":"video","temporalLayers":3,"substreams":1,"state":"active","videoprofile":"UD_2880_1800P_5","audioprofile":""},
    //     {"mslabel":"sophon_stream","label":"sophon_video_camera_super","type":"video","temporalLayers":3,"substreams":1,"state":"inactive","videoprofile":"UD_640_480P_15","audioprofile":""},
    //     {"mslabel":"sophon_stream","label":"sophon_audio","type":"audio","temporalLayers":0,"substreams":0,"state":"active","videoprofile":"","audioprofile":"ENGINE_BASIC_QUALITY_MODE"}
    // ]}
    SrsJsonAny* prop = NULL;
    if ((prop = body->get_property("streams")) == NULL || !prop->is_array()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no streams");
    }
    SrsJsonArray* streams = prop->to_array();

    // parser stream infos
    std::ostringstream log_stream;
    std::vector<SrsTrackConfig> track_cfgs;
    for (int i = 0; i < streams->count(); i++) {
        SrsJsonAny* stream = streams->at(i);
        if (!stream->is_object()) {
            continue;
        }

        SrsJsonObject* obj = streams->at(i)->to_object();
        SrsTrackConfig cfg = SrsTrackConfig::parse(obj);
        track_cfgs.push_back(cfg);

        log_stream << "{ type=" << cfg.type_ 
                   << ", label=" << cfg.label_ 
                   << ", active=" << cfg.active
                   << " }, ";
    }

    if (!track_cfgs.empty()) {
        rtc_session_->set_play_track_active(track_cfgs);
    }

    SrsJanusMessage* res_msg = new SrsJanusMessage();
    res_msg->janus = "event";
    res_msg->session_id = session_->id_;
    res_msg->sender = id_;
    res_msg->transaction = msg->transaction;
    res_msg->plugin = "janus.plugin.videoroom";
    res_msg->videoroom = "event";
    res_msg->reconfigured = "ok";
    srs_random_generate((char*)&res_msg->private_id, 4);
    session_->enqueue(res_msg);

    srs_trace("RTC janus %s transaction %s, tid=%s, rpc=%s, module=%s, request=%s, streams=%d, stream_info=%s",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        "reconfig-subscriber", streams->count(), log_stream.str().c_str());

    return err;
}

srs_error_t SrsJanusCall::publisher_exchange_sdp(SrsRequest* req, const SrsSdp& remote_sdp, SrsSdp& local_sdp)
{
    srs_error_t err = srs_success;

    local_sdp.version_ = "0";

    local_sdp.username_        = RTMP_SIG_SRS_SERVER;
    local_sdp.session_id_      = srs_int2str(session_->id_);
    local_sdp.session_version_ = "2";
    local_sdp.nettype_         = "IN";
    local_sdp.addrtype_        = "IP4";
    local_sdp.unicast_address_ = "0.0.0.0";

    local_sdp.session_name_ = "TenfoldPublishSession";

    local_sdp.msid_semantic_ = "WMS";
    local_sdp.msids_.push_back(req->app + "/" + req->stream);

    local_sdp.group_policy_ = "BUNDLE";

    bool nack_enabled = _srs_config->get_rtc_nack_enabled(req->vhost);

    for (size_t i = 0; i < remote_sdp.media_descs_.size(); ++i) {
        const SrsMediaDesc& remote_media_desc = remote_sdp.media_descs_[i];

        if (remote_media_desc.is_audio()) {
            local_sdp.media_descs_.push_back(SrsMediaDesc("audio"));
        } else if (remote_media_desc.is_video()) {
            local_sdp.media_descs_.push_back(SrsMediaDesc("video"));
        }

        SrsMediaDesc& local_media_desc = local_sdp.media_descs_.back();

        if (remote_media_desc.is_audio()) {
            // TODO: check opus format specific param
            std::vector<SrsMediaPayloadType> payloads = remote_media_desc.find_media_with_encoding_name("opus");
            for (std::vector<SrsMediaPayloadType>::iterator iter = payloads.begin(); iter != payloads.end(); ++iter) {
                local_media_desc.payload_types_.push_back(*iter);
                SrsMediaPayloadType& payload_type = local_media_desc.payload_types_.back();

                // TODO: FIXME: Only support some transport algorithms.
                vector<string> rtcp_fb;
                payload_type.rtcp_fb_.swap(rtcp_fb);
                for (int j = 0; j < (int)rtcp_fb.size(); j++) {
                    if (nack_enabled) {
                        if (rtcp_fb.at(j) == "nack" || rtcp_fb.at(j) == "nack pli") {
                            payload_type.rtcp_fb_.push_back(rtcp_fb.at(j));
                        }
                    }
                }

                // Only choose one match opus codec.
                break;
            }

            map<int, string> extmaps = remote_media_desc.get_extmaps();
            for(map<int, string>::iterator it_ext = extmaps.begin(); it_ext != extmaps.end(); ++it_ext) {
                if (it_ext->second == kTWCCExt) {
                    local_media_desc.extmaps_[it_ext->first] = kTWCCExt;
                    break;
                }
            }

            if (local_media_desc.payload_types_.empty()) {
                return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "no valid found opus payload type");
            }
        } else if (remote_media_desc.is_video()) {
            std::deque<SrsMediaPayloadType> backup_payloads;
            std::vector<SrsMediaPayloadType> payloads = remote_media_desc.find_media_with_encoding_name("H264");
            for (std::vector<SrsMediaPayloadType>::iterator iter = payloads.begin(); iter != payloads.end(); ++iter) {
                if (iter->format_specific_param_.empty()) {
                    backup_payloads.push_front(*iter);
                    continue;
                }
                H264SpecificParam h264_param;
                if ((err = srs_parse_h264_fmtp(iter->format_specific_param_, h264_param)) != srs_success) {
                    srs_error_reset(err); continue;
                }

                // Try to pick the "best match" H.264 payload type.
                if (h264_param.packetization_mode == "1" && h264_param.level_asymmerty_allow == "1") {
                    local_media_desc.payload_types_.push_back(*iter);
                    SrsMediaPayloadType& payload_type = local_media_desc.payload_types_.back();

                    // TODO: FIXME: Only support some transport algorithms.
                    vector<string> rtcp_fb;
                    payload_type.rtcp_fb_.swap(rtcp_fb);
                    for (int j = 0; j < (int)rtcp_fb.size(); j++) {
                        if (nack_enabled) {
                            if (rtcp_fb.at(j) == "nack" || rtcp_fb.at(j) == "nack pli") {
                                payload_type.rtcp_fb_.push_back(rtcp_fb.at(j));
                            }
                        }
                    }

                    // Only choose first match H.264 payload type.
                    break;
                }

                backup_payloads.push_back(*iter);
            }

            map<int, string> extmaps = remote_media_desc.get_extmaps();
            for(map<int, string>::iterator it_ext = extmaps.begin(); it_ext != extmaps.end(); ++it_ext) {
                if (it_ext->second == kTWCCExt) {
                    local_media_desc.extmaps_[it_ext->first] = kTWCCExt;
                    break;
                }
            }

            // Try my best to pick at least one media payload type.
            if (local_media_desc.payload_types_.empty() && ! backup_payloads.empty()) {
                srs_warn("choose backup H.264 payload type=%d", backup_payloads.front().payload_type_);
                local_media_desc.payload_types_.push_back(backup_payloads.front());
            }

            if (local_media_desc.payload_types_.empty()) {
                return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "no found valid H.264 payload type");
            }

            // TODO: FIXME: Support RRTR?
            //local_media_desc.payload_types_.back().rtcp_fb_.push_back("rrtr");
        }

        local_media_desc.mid_ = remote_media_desc.mid_;
        local_sdp.groups_.push_back(local_media_desc.mid_);

        local_media_desc.port_ = 9;
        local_media_desc.protos_ = "UDP/TLS/RTP/SAVPF";

        if (remote_media_desc.session_info_.setup_ == "active") {
            local_media_desc.session_info_.setup_ = "passive";
        } else if (remote_media_desc.session_info_.setup_ == "passive") {
            local_media_desc.session_info_.setup_ = "active";
        } else if (remote_media_desc.session_info_.setup_ == "actpass") {
            local_media_desc.session_info_.setup_ = local_sdp.session_config_.dtls_role;
        } else {
            // @see: https://tools.ietf.org/html/rfc4145#section-4.1
            // The default value of the setup attribute in an offer/answer exchange
            // is 'active' in the offer and 'passive' in the answer.
            local_media_desc.session_info_.setup_ = "passive";
        }

        local_media_desc.rtcp_mux_ = true;

        // For publisher, we are always sendonly.
        local_media_desc.sendonly_ = false;
        local_media_desc.recvonly_ = true;
        local_media_desc.sendrecv_ = false;
    }

    return err;
}

srs_error_t SrsJanusCall::write_sub_relations(SrsRequest* req, SrsJanusCall* callee, SrsSdp* sub_offer_sdp)
{
    srs_error_t err = srs_success;

    SrsRtcStream* source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req, &source)) != srs_success) {
        return srs_error_wrap(err, "fetch rtc source");
    }

    // Init Relation publish info
    SrsJanusRelationPublishInfo* pub_info = new SrsJanusRelationPublishInfo();
    SrsAutoFree(SrsJanusRelationPublishInfo, pub_info);
    pub_info->appid = callee->session_->appid_;
    pub_info->channel = callee->session_->channel_;
    pub_info->publisher_session_id = callee->session_->sessionid_;
    pub_info->publisher_user_id = callee->session_->userid_;
    pub_info->publisher_call_id = callee->callid_;


    // Init Relation publish info
    SrsJanusRelationSubscribeInfo* sub_info = new SrsJanusRelationSubscribeInfo();
    SrsAutoFree(SrsJanusRelationSubscribeInfo, sub_info);
    sub_info->subscriber_session_id = session_->sessionid_;
    sub_info->subscriber_user_id = session_->userid_;
    sub_info->subscriber_call_id = callid_;

    std::vector<SrsRtcTrackDescription*> audio_track_descs = source->get_track_desc("audio", "opus");
    for (size_t i = 0; i < audio_track_descs.size(); ++i) {
        SrsRtcTrackDescription* track_desc = audio_track_descs.at(i);
        std::string track_id = track_desc->id_;

        pub_info->track_id = track_id;
        pub_info->publisher_ssrc = track_desc->ssrc_;

        const SrsMediaDesc* media_desc = sub_offer_sdp->find_media_desc("audio");
        for (int j = 0; j < (int)media_desc->ssrc_infos_.size(); ++j) {
            SrsSSRCInfo ssrc_info = media_desc->ssrc_infos_.at(j);
            if (ssrc_info.msid_tracker_ != track_id) {
                continue;
            }

            sub_info->subscriber_ssrc = ssrc_info.ssrc_;
            _sls_relation->write(pub_info, sub_info);
        }
    }

    std::vector<SrsRtcTrackDescription*> video_track_descs = source->get_track_desc("video", "H264");
    for (size_t i = 0; i < video_track_descs.size(); ++i) {
        SrsRtcTrackDescription* track_desc = video_track_descs.at(i);
        std::string track_id = track_desc->id_;
        std::string merged_track_id = _srs_track_id_group->get_merged_track_id(track_id);

        pub_info->track_id = track_id;
        pub_info->publisher_ssrc = track_desc->ssrc_;

        const SrsMediaDesc* media_desc = sub_offer_sdp->find_media_desc("video");
        for (int j = 0; j < (int)media_desc->ssrc_infos_.size(); ++j) {
            SrsSSRCInfo ssrc_info = media_desc->ssrc_infos_.at(j);
            if (ssrc_info.msid_tracker_ != merged_track_id) {
                continue;
            }

            sub_info->subscriber_ssrc = ssrc_info.ssrc_;
            _sls_relation->write(pub_info, sub_info);
        }
    }

    return err;
}

SrsJanusCallstackMessage::SrsJanusCallstackMessage(SrsJanusSession* s, SrsJanusMessage* m, std::string command)
{
    appid_     = s->appid_;
    sessionid_ = s->sessionid_;
    channel_   = s->channel_;
    userid_    = s->userid_;

    transaction_ = m->transaction;
    sfu_ = srs_get_public_internet_address(true);
    signaling_ = m->client_ip;

    command_ = command;
}

SrsJanusCallstackMessage::~SrsJanusCallstackMessage()
{
}

SrsJanusCreateSessionMessage::SrsJanusCreateSessionMessage(SrsJanusSession* s, SrsJanusMessage* m, SrsJanusUserConf* uc)
    : SrsJanusCallstackMessage(s, m, "createJanusSession")
{
    uc_ = uc;

    event_ = new SrsRtcCallstackEvent("create", "createJanusSession");
    event_->cid_  = s->cid_.k_ + string("-") + s->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
}

SrsJanusCreateSessionMessage::~SrsJanusCreateSessionMessage()
{
    srs_freep(event_);
}

void SrsJanusCreateSessionMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusCreateSessionMessage::marshal() 
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("appID", SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID", SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID", SrsJsonAny::str(channel_.c_str()));
    obj->set("userID", SrsJsonAny::str(userid_.c_str()));
    obj->set("command", SrsJsonAny::str(command_.c_str()));
    obj->set("transaction", SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu", SrsJsonArray::str(sfu_.c_str()));
    obj->set("signaling", SrsJsonArray::str(signaling_.c_str()));

    obj->set("DownlinkStreamMerge", SrsJsonArray::boolean(uc_->stream_merge));
    obj->set("1v1TccForwardEnable", SrsJsonArray::boolean(uc_->enable_forward_twcc));
    obj->set("NeedSDPUnified", SrsJsonArray::boolean(uc_->need_unified_plan));
    obj->set("WebSDK", SrsJsonArray::str(uc_->web_sdk.c_str()));
    obj->set("EnableBWEStatusReport", SrsJsonArray::boolean(uc_->enable_bwe_status_report));
    obj->set("NoExtraConfig", SrsJsonArray::boolean(uc_->no_extra_config_when_join));
    obj->set("IsMPU", SrsJsonArray::boolean(uc_->is_mpu_client));
    
    return obj->dumps();
}

SrsJanusAttachMessage::SrsJanusAttachMessage(SrsJanusCall* c, SrsJanusMessage* m)
    : SrsJanusCallstackMessage(c->session_, m, "attach")
{
    callid_ = c->callid_;

    event_ = new SrsRtcCallstackEvent("create", "attachJanusHandle");
    event_->cid_  = c->cid_.k_ + string("-") + c->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
    event_->call_    = callid_;
}

SrsJanusAttachMessage::~SrsJanusAttachMessage()
{
    srs_freep(event_);
}

void SrsJanusAttachMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusAttachMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID", SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",  SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",  SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",   SrsJsonAny::str(userid_.c_str()));
    obj->set("transaction",  SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu",  SrsJsonAny::str(sfu_.c_str()));
    obj->set("signaling",    SrsJsonAny::str(signaling_.c_str()));

    obj->set("command",  SrsJsonAny::str(command_.c_str()));
    
    return obj->dumps();
}

SrsJanusTrickleMessage::SrsJanusTrickleMessage(SrsJanusCall* c, SrsJanusMessage* m, std::string candidate, bool completed)
    : SrsJanusCallstackMessage(c->session_, m, "trickle")
{
    callid_ = c->callid_;
    candidate_  = candidate;
    completed_  = completed;

    event_ = new SrsRtcCallstackEvent("Media", "TrickleCandidate");
    event_->cid_  = c->cid_.k_ + string("-") + c->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
    event_->call_    = callid_;
}

SrsJanusTrickleMessage::~SrsJanusTrickleMessage()
{
    srs_freep(event_);
}

void SrsJanusTrickleMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusTrickleMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("transaction", SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("signaling",   SrsJsonAny::str(signaling_.c_str()));

    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("candidate",   SrsJsonAny::str(candidate_.c_str()));
    obj->set("completed",   SrsJsonAny::boolean(completed_));

    return obj->dumps();
}

SrsJanusJoinMessage::SrsJanusJoinMessage(SrsJanusCall* c, SrsJanusMessage* m, std::string ptype, std::string result)
    : SrsJanusCallstackMessage(c->session_, m, "join") 
{
    callid_ = c->callid_;
    participant_type_ = ptype;
    result_ = result;
    feedid_ = c->feed_id_;

    std::string stage = "join";
    if (ptype == "publisher") {
        stage = "PublisherJoin";
    } else if (ptype == "listener") {
        stage = "SubscriberJoin";
    }

    event_ = new SrsRtcCallstackEvent("MediaSignaling", stage);
    event_->cid_  = c->cid_.k_ + string("-") + c->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
    event_->call_    = callid_;
}

SrsJanusJoinMessage::~SrsJanusJoinMessage()
{
    srs_freep(event_);
}

void SrsJanusJoinMessage::write_callstack(std::string status, int err_code)
{
    event_->status_ = status;
    event_->error_code_ = err_code;
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusJoinMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("transaction", SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("signaling",   SrsJsonAny::str(signaling_.c_str()));

    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("participantType", SrsJsonAny::str(participant_type_.c_str()));
    obj->set("result", SrsJsonAny::str(result_.c_str()));
    obj->set("feedID", SrsJsonAny::integer(feedid_));

    return obj->dumps();
}

SrsJanusProcessOfferMessage::SrsJanusProcessOfferMessage(SrsJanusCall* c, SrsJanusMessage* m)
    : SrsJanusCallstackMessage(c->session_, m, "processOffer") 
{
    callid_ = c->callid_;

    event_ = new SrsRtcCallstackEvent("MediaSignaling", "processOffer");
    event_->cid_  = c->cid_.k_ + string("-") + c->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
    event_->call_    = callid_;
}

SrsJanusProcessOfferMessage::~SrsJanusProcessOfferMessage()
{
    srs_freep(event_);
}

void SrsJanusProcessOfferMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusProcessOfferMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("transaction", SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("signaling",   SrsJsonAny::str(signaling_.c_str()));

    obj->set("command",     SrsJsonAny::str(command_.c_str()));

    return obj->dumps();
}

SrsJanusUnpublishMessage::SrsJanusUnpublishMessage(SrsJanusCall* c, SrsJanusMessage* m)
    : SrsJanusCallstackMessage(c->session_, m, "unpublish") 
{
    callid_ = c->callid_;

    event_ = new SrsRtcCallstackEvent("MediaSignaling", "unpublish");
    event_->cid_  = c->cid_.k_ + string("-") + c->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
    event_->call_    = callid_;
}

SrsJanusUnpublishMessage::~SrsJanusUnpublishMessage()
{
    srs_freep(event_);
}

void SrsJanusUnpublishMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusUnpublishMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("transaction", SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("signaling",   SrsJsonAny::str(signaling_.c_str()));

    obj->set("command",     SrsJsonAny::str(command_.c_str()));

    return obj->dumps();
}

SrsJanusDestroyMessage::SrsJanusDestroyMessage(SrsJanusSession* s, SrsJanusMessage* m)
    : SrsJanusCallstackMessage(s, m, "destroy") 
{
    result_ = "success";

    event_ = new SrsRtcCallstackEvent("Destroy", "DestroySession");
    event_->cid_  = s->cid_.k_ + string("-") + s->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
}

SrsJanusDestroyMessage::~SrsJanusDestroyMessage()
{
    srs_freep(event_);
}

void SrsJanusDestroyMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;
    
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusDestroyMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("transaction", SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("signaling",   SrsJsonAny::str(signaling_.c_str()));

    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("result",      SrsJsonAny::str(result_.c_str()));

    return obj->dumps();
}

SrsJanusProcessAnswerMessage::SrsJanusProcessAnswerMessage(SrsJanusCall* c, SrsJanusMessage* m)
    : SrsJanusCallstackMessage(c->session_, m, "sdpAnswer") 
{
    callid_ = c->callid_;
    result_ = "success";

    event_ = new SrsRtcCallstackEvent("MediaSignaling", "processAnswer");
    event_->cid_  = c->cid_.k_ + string("-") + c->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
    event_->call_    = callid_;
}

SrsJanusProcessAnswerMessage::~SrsJanusProcessAnswerMessage()
{
    srs_freep(event_);
}

void SrsJanusProcessAnswerMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;
    
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusProcessAnswerMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("transaction", SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("signaling",   SrsJsonAny::str(signaling_.c_str()));

    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("result",      SrsJsonAny::str(result_.c_str()));

    return obj->dumps();
}

SrsJanusDetachMessage::SrsJanusDetachMessage(SrsJanusCall* c, SrsJanusMessage* m, uint64_t handle_id)
    : SrsJanusCallstackMessage(c->session_, m, "detach") 
{
    callid_ = c->callid_;
    result_ = "success";
    handle_id_ = handle_id;

    event_ = new SrsRtcCallstackEvent("Destroy", "detach");
    event_->cid_  = c->cid_.k_ + string("-") + c->cid_.v_;
    event_->appid_   = appid_;
    event_->channel_ = channel_;
    event_->user_    = userid_;
    event_->session_ = sessionid_;
    event_->tid_     = transaction_;
    event_->call_    = callid_;
}

SrsJanusDetachMessage::~SrsJanusDetachMessage()
{
    srs_freep(event_);
}

void SrsJanusDetachMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;
    
    _sls_callstack->write(event_, marshal());
}

std::string SrsJanusDetachMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("transaction", SrsJsonAny::str(transaction_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("signaling",   SrsJsonAny::str(signaling_.c_str()));

    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("result",      SrsJsonAny::str(result_.c_str()));
    obj->set("janusHandleID", SrsJsonAny::integer(handle_id_));

    return obj->dumps();
}