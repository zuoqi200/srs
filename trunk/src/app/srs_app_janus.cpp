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
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not json");
        }

        req = json->to_object();

        // Fetch params from req object.
        SrsJsonAny* prop = NULL;
        if ((prop = req->ensure_property_string("janus")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not janus");
        }
        req_msg.janus = prop->to_str();

        if ((prop = req->ensure_property_string("transaction")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not transaction");
        }
        req_msg.transaction = prop->to_str();

        if ((prop = req->ensure_property_string("client_tid")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not client_tid");
        }
        req_msg.client_tid = prop->to_str();

        if ((prop = req->ensure_property_string("rpcid")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not rpcid");
        }
        req_msg.rpcid = prop->to_str();

        if ((prop = req->ensure_property_string("source_module")) == NULL) {
            return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not source_module");
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
        if ((err = call->message(req, &req_msg, res)) != srs_success) {
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
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not userID");
    }
    string userid = prop->to_str();

    if ((prop = req->ensure_property_string("appID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not appID");
    }
    string appid = prop->to_str();

    if ((prop = req->ensure_property_string("channelID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not channelID");
    }
    string channel = prop->to_str();

    if ((prop = req->ensure_property_string("sessionID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not sessionID");
    }
    string session_id = prop->to_str();

    // Switch to configure object.
    if ((prop = req->get_property("configure")) == NULL || !prop->is_object()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not configure");
    }
    req = prop->to_object();

    if ((prop = req->get_property("NeedSDPUnified")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not NeedSDPUnified");
    }
    bool need_unified = prop->to_boolean();

    if ((prop = req->ensure_property_string("WebSDK")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not WebSDK");
    }
    string websdk = prop->to_str();

    if ((prop = req->ensure_property_string("channelprofile")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not channelprofile");
    }
    string profile = prop->to_str();

    // Process message.
    SrsJanusSession* session = new SrsJanusSession(this);

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
        data->set("videoroom", SrsJsonAny::str(msg->videoroom.c_str()));
        data->set("id", SrsJsonAny::integer(msg->feed_id));
        data->set("private_id", SrsJsonAny::integer(msg->private_id));

        srs_trace("RTC polling, session=%" PRId64 ", janus=%s, sender=%" PRId64 ", transaction=%s, feed=%" PRId64 ", private=%d",
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
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not plugin");
    }
    string plugin = prop->to_str();

    if ((prop = req->ensure_property_string("opaque_id")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not opaque_id");
    }
    string opaque_id = prop->to_str();

    if ((prop = req->get_property("force-bundle")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not force-bundle");
    }
    bool force_bundle = prop->to_boolean();

    if ((prop = req->get_property("force-rtcp-mux")) == NULL || !prop->is_boolean()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not force-rtcp-mux");
    }
    bool force_rtcp_mux = prop->to_boolean();

    if ((prop = req->ensure_property_string("callID")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not callID");
    }
    string callid = prop->to_str();

    // Process message.
    SrsJanusCall* call = new SrsJanusCall(this);

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

SrsJanusCall::SrsJanusCall(SrsJanusSession* s)
{
    id = 0;
    session = s;
}

SrsJanusCall::~SrsJanusCall()
{
}

srs_error_t SrsJanusCall::message(SrsJsonObject* req, SrsJanusMessage* msg, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    // Switch to body object.
    SrsJsonAny* prop = NULL;
    if ((prop = req->get_property("body")) == NULL || !prop->is_object()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "body");
    }
    req = prop->to_object();

    if ((prop = req->ensure_property_string("request")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not request");
    }
    string request = prop->to_str();

    if ((prop = req->get_property("room")) == NULL || (!prop->is_string() && !prop->is_integer())) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not room");
    }
    string room;
    if (prop->is_string()) {
        room = prop->to_str();
    } else if (prop->is_integer()) {
        room = srs_int2str(prop->to_integer());
    }

    if ((prop = req->ensure_property_string("ptype")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not ptype");
    }
    string ptype = prop->to_str();

    if ((prop = req->ensure_property_string("display")) == NULL) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not display");
    }
    string display = prop->to_str();

    if ((prop = req->get_property("feed_id")) == NULL || !prop->is_integer()) {
        return srs_error_new(ERROR_RTC_JANUS_INVALID_PARAMETER, "not feed_id");
    }
    uint64_t feed_id = prop->to_integer();

    // Response.
    res->set("janus", SrsJsonAny::str("ack"));
    res->set("session", SrsJsonAny::integer(session->id));

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

    srs_trace("RTC janus %s transaction=%s, tid=%s, rpc=%s, module=%s, request=%s, room=%s, ptype=%s, display=%s, feed_id=%" PRId64 ", sender=%" PRId64 ", private=%d",
        msg->janus.c_str(), msg->transaction.c_str(), msg->client_tid.c_str(), msg->rpcid.c_str(), msg->source_module.c_str(),
        request.c_str(), room.c_str(), ptype.c_str(), display.c_str(), feed_id, res_msg->sender, res_msg->private_id);

    return err;
}


