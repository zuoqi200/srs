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

#include <srs_app_janus.hpp>

#include <string>
using namespace std;

#include <srs_app_rtc_conn.hpp>
#include <srs_app_server.hpp>
#include <srs_protocol_json.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_core_autofree.hpp>
#include <srs_service_st.hpp>
#include <srs_app_config.hpp>

// When API error, limit the request by sleep for a while.
srs_utime_t API_ERROR_LIMIT = 3 * SRS_UTIME_SECONDS;

// TODO: FIXME: Use cond to wait.
// For Long polling keep alive, sleep for a while.
srs_utime_t API_POLLING_LIMIT = 1 * SRS_UTIME_SECONDS;

extern srs_error_t srs_api_response(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, std::string json);
extern srs_error_t srs_api_response_code(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, int code);

SrsGoApiRtcJanus::SrsGoApiRtcJanus(SrsJanusServer* j)
{
    janus = j;
}

SrsGoApiRtcJanus::~SrsGoApiRtcJanus()
{
}

srs_error_t SrsGoApiRtcJanus::serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
{
    srs_error_t err = srs_success;

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
        session = janus->fetch(janus_session_id);
        if (!session) {
            srs_usleep(API_ERROR_LIMIT);
            return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "no session id=%" PRId64, janus_session_id);
        }

        // Switch to the session.
        _srs_context->set_id(session->cid);
    }

    SrsJanusCall* call = NULL;
    if (janus_handler_id) {
        call = session->fetch(janus_handler_id);
        if (!session) {
            srs_usleep(API_ERROR_LIMIT);
            return srs_error_new(ERROR_RTC_JANUS_NO_SESSION, "no call id=%" PRId64, janus_handler_id);
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
        if ((err = janus->create(req, &req_msg, res)) != srs_success) {
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
        res->set("session", SrsJsonAny::integer(session->id));

        if ((err = call->message(req, &req_msg)) != srs_success) {
            return srs_error_wrap(err, "body %s", req_json.c_str());
        }
    } else if (req_msg.janus == "trickle") {
        if (!call) {
            return srs_error_new(ERROR_RTC_JANUS_NO_CALL, "attach, no call id=%" PRId64, janus_handler_id);
        }

        // TODO: FIXME: Maybe we should response error.
        res->set("janus", SrsJsonAny::str("ack"));
        res->set("session", SrsJsonAny::integer(session->id));

        if ((err = call->trickle(req, &req_msg)) != srs_success) {
            return srs_error_wrap(err, "body %s", req_json.c_str());
        }
    } else {
        srs_warn("RTC unknown action=%s, body=%s", req_msg.janus.c_str(), req_json.c_str());
        srs_usleep(API_ERROR_LIMIT);
    }

    return err;
}

SrsJanusServer::SrsJanusServer(SrsRtcServer* r)
{
    rtc = r;
}

SrsJanusServer::~SrsJanusServer()
{
    map<uint64_t, SrsJanusSession*>::iterator it;
    for (it = sessions.begin(); it != sessions.end(); ++it) {
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
    req = prop->to_object();

    if ((prop = req->get_property("NeedSDPUnified")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no NeedSDPUnified");
    }
    bool need_unified = prop->to_boolean();

    if ((prop = req->ensure_property_string("WebSDK")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no WebSDK");
    }
    string websdk = prop->to_str();

    if ((prop = req->ensure_property_string("channelprofile")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no channelprofile");
    }
    string profile = prop->to_str();

    // Process message.
    SrsJanusSession* session = new SrsJanusSession(this);
    session->appid = appid;
    session->channel = channel;
    session->userid = userid;
    session->sessionid = session_id;

    // Switch to the session.
    _srs_context->set_id(session->cid);

    do {
        srs_random_generate((char*)&session->id, 8);
        session->id &= 0x7fffffffffffffffLL;
    } while (sessions.find(session->id) != sessions.end());

    sessions[session->id] = session;

    // Set response data.
    SrsJsonObject* data = SrsJsonAny::object();
    res->set("data", data);

    data->set("id", SrsJsonAny::integer((int64_t)session->id));

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, appid=%s, channel=%s, userid=%s, session_id=%s, unified=%d, web=%s, profile=%s, session=%" PRId64,
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        appid.c_str(), channel.c_str(), userid.c_str(), session_id.c_str(), need_unified, websdk.c_str(), profile.c_str(), session->id);

    return err;
}

SrsJanusSession* SrsJanusServer::fetch(uint64_t sid)
{
    map<uint64_t, SrsJanusSession*>::iterator it = sessions.find(sid);
    if (it == sessions.end()) {
        return NULL;
    }
    return it->second;
}

SrsRtcServer* SrsJanusServer::server()
{
    return rtc;
}

SrsJanusSession::SrsJanusSession(SrsJanusServer* j)
{
    id = 0;
    janus = j;
    cid = _srs_context->generate_id();
}

SrsJanusSession::~SrsJanusSession()
{
    if (true) {
        map<uint64_t, SrsJanusCall*>::iterator it;
        for (it = calls.begin(); it != calls.end(); ++it) {
            SrsJanusCall* call = it->second;
            srs_freep(call);
        }
    }

    if (true) {
        vector<SrsJanusMessage*>::iterator it;
        for (it = msgs.begin(); it != msgs.end(); ++it) {
            SrsJanusMessage* msg = *it;
            srs_freep(msg);
        }
    }
}

srs_error_t SrsJanusSession::polling(SrsJsonObject* req, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    if (msgs.empty()) {
        // No data, keep-alive.
        srs_usleep(API_POLLING_LIMIT);
        res->set("janus", SrsJsonAny::str("keepalive"));
        srs_trace("RTC polling, session=%" PRId64 ", keepalive", id);
        return err;
    }

    SrsJanusMessage* msg = msgs[0];
    SrsAutoFree(SrsJanusMessage, msg);
    msgs.erase(msgs.begin());

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
            data->set("videoroom", SrsJsonAny::str("joined"));
            data->set("id", SrsJsonAny::integer(msg->feed_id));
            data->set("private_id", SrsJsonAny::integer(msg->private_id));
        } else if (msg->videoroom == "configured") {
            data->set("videoroom", SrsJsonAny::str("event"));
            data->set("configured", SrsJsonAny::str("ok"));

            SrsJsonObject* jsep = SrsJsonObject::object();
            res->set("jsep", jsep);
            jsep->set("type", SrsJsonAny::str(msg->jsep_type.c_str()));
            jsep->set("sdp", SrsJsonAny::str(msg->jsep_sdp.c_str()));
        }

        srs_trace("RTC polling, session=%" PRId64 ", janus=%s, sender=%" PRId64 ", transaction=%s, feed=%" PRId64 ", private=%u",
            id, msg->janus.c_str(), msg->sender, msg->transaction.c_str(), msg->feed_id, msg->private_id);
    }

    return err;
}

void SrsJanusSession::enqueue(SrsJanusMessage* msg)
{
    msgs.push_back(msg);
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

    // Process message.
    SrsJanusCall* call = new SrsJanusCall(this);
    call->callid = callid;

    do {
        srs_random_generate((char*)&call->id, 8);
        call->id &= 0x7fffffffffffffffLL;
    } while (janus->fetch(call->id) || calls.find(call->id) != calls.end());

    calls[call->id] = call;

    // Set response data.
    SrsJsonObject* data = SrsJsonAny::object();
    res->set("data", data);

    data->set("id", SrsJsonAny::integer((int64_t)call->id));

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, plugin=%s, opaque_id=%s, force_bundle=%d, force_rtcp_mux=%d, callid=%s, call=%" PRId64,
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        plugin.c_str(), opaque_id.c_str(), force_bundle, force_rtcp_mux, callid.c_str(), call->id);

    return err;
}

SrsJanusCall* SrsJanusSession::fetch(uint64_t sid)
{
    map<uint64_t, SrsJanusCall*>::iterator it = calls.find(sid);
    if (it == calls.end()) {
        return NULL;
    }
    return it->second;
}

SrsRtcServer* SrsJanusSession::server()
{
    return janus->server();
}

SrsJanusCall::SrsJanusCall(SrsJanusSession* s)
{
    id = 0;
    session = s;
    server_ = s->server();
}

SrsJanusCall::~SrsJanusCall()
{
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
        return on_configure_message(req, body, msg);
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

    srs_trace("RTC janus %s transaction %s, tid=%s, rpc=%s, module=%s, completed=%d, candidate=%s",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        completed, candidate.c_str());

    return err;
}

srs_error_t SrsJanusCall::on_join_message(SrsJsonObject* req, SrsJanusMessage* msg)
{
    srs_error_t err = srs_success;

    SrsJsonAny* prop = NULL;
    if ((prop = req->get_property("room")) == NULL || (!prop->is_string() && !prop->is_integer())) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no room");
    }
    string room;
    if (prop->is_string()) {
        room = prop->to_str();
    } else if (prop->is_integer()) {
        room = srs_int2str(prop->to_integer());
    }

    if ((prop = req->ensure_property_string("ptype")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no ptype");
    }
    string ptype = prop->to_str();

    if ((prop = req->ensure_property_string("display")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no display");
    }
    string display = prop->to_str();

    if ((prop = req->get_property("feed_id")) == NULL || !prop->is_integer()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "no feed_id");
    }
    uint64_t feed_id = prop->to_integer();

    SrsJanusMessage* res_msg = new SrsJanusMessage();
    res_msg->janus = "event";
    res_msg->session_id = session->id;
    res_msg->sender = id;
    res_msg->transaction = msg->transaction;
    res_msg->plugin = "janus.plugin.videoroom";
    res_msg->videoroom = "joined";
    res_msg->feed_id = feed_id;
    srs_random_generate((char*)&res_msg->private_id, 4);
    session->enqueue(res_msg);

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, request=%s, room=%s, ptype=%s, display=%s, feed_id=%" PRId64 ", sender=%" PRId64 ", private=%u",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        "join", room.c_str(), ptype.c_str(), display.c_str(), feed_id, res_msg->sender, res_msg->private_id);

    return err;
}

srs_error_t SrsJanusCall::on_configure_message(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg)
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
    string sdp = prop->to_str();

    // TODO: FIXME: It seems remote_sdp doesn't represents the full SDP information.
    SrsSdp remote_sdp;
    if ((err = remote_sdp.parse(sdp)) != srs_success) {
        return srs_error_wrap(err, "parse sdp failed: %s", sdp.c_str());
    }

    SrsRequest request;
    request.app = session->channel;
    request.stream = callid;

    // TODO: FIXME: Parse vhost.
    // discovery vhost, resolve the vhost from config
    SrsConfDirective* parsed_vhost = _srs_config->get_vhost("");
    if (parsed_vhost) {
        request.vhost = parsed_vhost->arg0();
    }

    SrsSdp local_sdp;
    if ((err = exchange_sdp(&request, remote_sdp, local_sdp)) != srs_success) {
        return srs_error_wrap(err, "remote sdp have error or unsupport attributes");
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

    // For client to specifies the EIP of server.
    string eip;

    // TODO: FIXME: When server enabled, but vhost disabled, should report error.
    SrsRtcSession* rtc_session = NULL;
    if ((err = server_->create_session(&request, remote_sdp, local_sdp, eip, true, &rtc_session)) != srs_success) {
        return srs_error_wrap(err, "create session");
    }

    ostringstream os;
    if ((err = local_sdp.encode(os)) != srs_success) {
        return srs_error_wrap(err, "encode sdp");
    }

    string local_sdp_str = os.str();
    srs_verbose("local_sdp=%s", local_sdp_str.c_str());

    SrsJanusMessage* res_msg = new SrsJanusMessage();
    res_msg->janus = "event";
    res_msg->session_id = session->id;
    res_msg->sender = id;
    res_msg->transaction = msg->transaction;
    res_msg->plugin = "janus.plugin.videoroom";
    res_msg->videoroom = "configured";
    res_msg->jsep_type = "answer";
    res_msg->jsep_sdp = local_sdp_str;
    srs_random_generate((char*)&res_msg->private_id, 4);
    session->enqueue(res_msg);

    srs_trace("RTC janus %s transaction %s, tid=%s, rpc=%s, module=%s, request=%s, audio=%d, video=%d, streams=%d, jsep=%s/%dB, answer=%dB",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        "configure", has_audio, has_video, streams->count(), type.c_str(), sdp.length(), local_sdp_str.length());

    return err;
}

srs_error_t SrsJanusCall::exchange_sdp(SrsRequest* req, const SrsSdp& remote_sdp, SrsSdp& local_sdp)
{
    srs_error_t err = srs_success;

    local_sdp.version_ = "0";

    local_sdp.username_        = RTMP_SIG_SRS_SERVER;
    local_sdp.session_id_      = srs_int2str((int64_t)this);
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
                if ((err = parse_h264_fmtp(iter->format_specific_param_, h264_param)) != srs_success) {
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
            local_media_desc.session_info_.setup_ = "passive";
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

