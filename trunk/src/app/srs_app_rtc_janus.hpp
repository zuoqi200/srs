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

#ifndef SRS_APP_JANUS_HPP
#define SRS_APP_JANUS_HPP

#include <srs_core.hpp>

#include <srs_http_stack.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_app_rtc_server.hpp>

#include <map>
#include <string>
#include <vector>

class SrsRtcServer;
class SrsJsonObject;
class SrsJanusServer;
class SrsJanusSession;
class SrsJanusCall;
class SrsRequest;
class SrsSdp;
class SrsRtcConnection;

struct SrsJanusMessage
{
    // The janus action field.
    std::string janus;

    // The client IP address.
    std::string client_ip;

    // The common request header, except polling.
    std::string transaction;
    std::string client_tid;
    std::string rpcid;
    std::string source_module;

    // For janus event.
    // {"janus": "event", "session_id": xxx, "sender": xxx, "transaction": "xxx", "plugindata":
    //      {"plugin": "janus.plugin.videoroom", "data": {"videoroom": "xxx", "id": xxx, "private_id": xxx}}
    // }
    uint64_t session_id;
    uint64_t sender;
    std::string plugin;
    std::string videoroom;
    // For video-room, joined.
    uint64_t feed_id;
    uint32_t private_id;
    // For video-room, configured.
    std::string jsep_type;
    std::string jsep_sdp;
    // For subscriber, the display of publisher.
    std::string display;
    // For reconfig-publisher and reconfig-subscriber, the result of reconfig;
    std::string reconfigured;

    SrsJanusMessage() {
        session_id = sender = feed_id = 0;
        private_id = 0;
    }
};

class SrsGoApiRtcJanus : public ISrsHttpHandler
{
private:
    SrsJanusServer* janus_;
public:
    SrsGoApiRtcJanus(SrsJanusServer* j);
    virtual ~SrsGoApiRtcJanus();
public:
    virtual srs_error_t serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r);
private:
    srs_error_t do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res);
};

class SrsJanusServer : public ISrsRtcServerHandler
{
private:
    std::map<uint64_t, SrsJanusSession*> sessions_;
    std::map<std::string, SrsJanusCall*> publishers_;
public:
    SrsRtcServer* rtc_;
public:
    SrsJanusServer(SrsRtcServer* r);
    virtual ~SrsJanusServer();
public:
    srs_error_t listen_api();
public:
    srs_error_t create(SrsJsonObject* req, SrsJanusMessage* msg, SrsJsonObject* res);
    void destroy(SrsJanusSession* session, SrsJanusMessage* msg);
private:
    void do_destroy(SrsJanusSession* session);
    void do_destroy_calls(SrsJanusSession* session, SrsRtcConnection* rtc_session);
public:
    SrsJanusSession* fetch(uint64_t sid);
    void set_callee(SrsJanusCall* call);
    void destroy_callee(SrsJanusCall* call);
    SrsJanusCall* callee(std::string appid, std::string channel, uint64_t feed_id);
    virtual void on_timeout(SrsRtcConnection* rtc_session);
};

class SrsJanusUserConf
{
public:
    bool stream_merge;
    bool enable_forward_twcc;
    bool need_unified_plan;
    bool enable_bwe_status_report;
    bool enable_video_nack_rs_v1;
    bool no_extra_config_when_join;
    bool is_mpu_client;
    std::string web_sdk;
    std::string channel_profile;
public:
    SrsJanusUserConf();
    virtual ~SrsJanusUserConf();
public:
    bool is_web_sdk();
public:
    static SrsJanusUserConf* parse_janus_user_conf(SrsJsonObject* res);
};

class SrsJanusStreamInfo
{
public:
    // mslabel:
    std::string mslabel_;
    // label:
    std::string label_;
    // type:
    std::string type_;
    // state:
    std::string state_;
    // temporalLayers:
    int temporal_layers_;
    // substreams:
    int sub_streams_;
    // videoprofile:
    std::string video_profile_;
    // audioprofile:
    std::string audio_profile_;
public:
    SrsJanusStreamInfo();
    virtual ~SrsJanusStreamInfo();
public:
    static SrsJanusStreamInfo parse_stream_info(SrsJsonObject* stream);
};

class SrsJanusSession
{
public:
    std::string appid_;
    std::string channel_;
    std::string userid_;
    std::string sessionid_;
    SrsJanusUserConf *user_conf_;
private:
    std::map<uint64_t, SrsJanusCall*> calls_;
    std::vector<SrsJanusMessage*> msgs_;
public:
    SrsJanusServer* janus_;
    uint64_t id_;
    SrsContextId cid_;
public:
    SrsJanusSession(SrsJanusServer* j, SrsContextId cid);
    virtual ~SrsJanusSession();
public:
    srs_error_t polling(SrsJsonObject* req, SrsJsonObject* res);
    void enqueue(SrsJanusMessage* msg);
public:
    srs_error_t attach(SrsJsonObject* req, SrsJanusMessage* msg, SrsJsonObject* res);
    srs_error_t detach(SrsJanusMessage* msg, uint64_t callid);
    SrsJanusCall* fetch(uint64_t sid);
    SrsJanusCall* find(SrsRtcConnection* session);
    int nn_calls();
    void destroy();
    void destroy_calls(SrsRtcConnection* session);
};

struct SrsJanusForwardMap
{
    uint32_t publish_ssrc;
    uint32_t subscribe_ssrc;
    uint32_t brother_ssrc;

    std::string stream_id;
    std::string track_id;

    // the current temporal layer level, influenced by congestion control.
    int temporal_layer;
    // the temporal layer level setted by subscribe.
    int target_temporal_layer;

    std::string type;
    // #define STREAM_FORMAT_SMALL 0
    // #define STREAM_FORMAT_LARGE 1
    // #define STREAM_FORMAT_SUPER 2
    int stream_format;
    bool enable_stream;
};

struct SrsJuanusVideoGroupPolicy
{
    std::vector<uint32_t> stream_ssrcs;

    uint32_t last_active_ssrc;
    uint32_t current_active_ssrc;
    uint32_t target_active_ssrc;
};

struct SrsJanusRelationPublishInfo
{
    // appid: app id.
    std::string appid;
    // channelid: channel id.
    std::string channel;
    // trackID: track id.
    std::string track_id;
    // publisher_session_id: publish session id.
    std::string publisher_session_id;
    // publisher_call_id: publish call id.
    std::string publisher_call_id;
    // publisher_user_id: publish user id.
    std::string publisher_user_id;
    // publisher_ssrc: publish ssrc;
    uint32_t publisher_ssrc;
};

struct SrsJanusRelationSubscribeInfo
{
    // subscriber_session_id: subscriber session id.
    std::string subscriber_session_id;
    // subscriber_call_id: subscriber call id.
    std::string subscriber_call_id;
    // subscriber_user_id: subscriber user id.
    std::string subscriber_user_id;
    // subscriber_ssrc: subscriber ssrc.
    uint32_t subscriber_ssrc;
};

class SrsJanusCall
{
    friend class SrsJanusSession;
private:
    // TODO: FIXME: For subscriber, should free session if no answer.
    SrsRtcConnection* rtc_session_;
    SrsRequest request;
    static uint32_t ssrc_num;
    // key: publish ssrc
    std::map<uint32_t, SrsJanusForwardMap> subscribe_forward_map_;
    SrsJuanusVideoGroupPolicy video_group_policy_;
public:
    bool publisher_;
    SrsJanusSession* session_;
    std::string callid_;
    uint64_t id_;
    uint64_t feed_id_;
    std::string display_;
    std::vector<SrsJanusStreamInfo> stream_infos_;
    SrsContextId parent_cid_;
    SrsContextId cid_;
public:
    SrsJanusCall(SrsJanusSession* s, SrsContextId cid);
    virtual ~SrsJanusCall();
public:
    void destroy();
    srs_error_t message(SrsJsonObject* req, SrsJanusMessage* msg);
    srs_error_t trickle(SrsJsonObject* req, SrsJanusMessage* msg);
    SrsSdp* get_remote_sdp();
private:
    srs_error_t on_join_message(SrsJsonObject* req, SrsJanusMessage* msg);
    srs_error_t on_join_as_subscriber(SrsJsonObject* req, SrsJanusMessage* msg);
    srs_error_t subscirber_build_offer(SrsRequest* req, SrsJanusCall* callee, SrsSdp& local_sdp);
    srs_error_t subscriber_camera_stream_merge(SrsSdp& local_sdp);
    srs_error_t on_start_subscriber(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg);
    srs_error_t on_configure_publisher(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg);
    srs_error_t on_reconfigure_publisher(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg);
    srs_error_t on_reconfigure_subscriber(SrsJsonObject* req, SrsJsonObject* body, SrsJanusMessage* msg);
    srs_error_t publisher_exchange_sdp(SrsRequest* req, const SrsSdp& remote_sdp, SrsSdp& local_sdp);
    srs_error_t write_sub_relations(SrsRequest* req, SrsJanusCall* callee, SrsSdp* sub_offer_sdp);
};

struct SrsRtcCallstackEvent;
class SrsJanusCallstackMessage
{
protected:
    std::string appid_;
    std::string sessionid_;
    std::string channel_;
    std::string userid_;
    std::string transaction_;
    std::string sfu_;
    std::string signaling_;
    std::string command_;
public:
    SrsJanusCallstackMessage(SrsJanusSession* s, SrsJanusMessage* m, std::string command);
    virtual ~SrsJanusCallstackMessage();
};

class SrsJanusCreateSessionMessage : public SrsJanusCallstackMessage
{
private:
    SrsJanusUserConf* uc_;

    SrsRtcCallstackEvent* event_;
public:
    SrsJanusCreateSessionMessage(SrsJanusSession* s, SrsJanusMessage* m, SrsJanusUserConf* uc);
    virtual ~SrsJanusCreateSessionMessage();
public:
    void write_callstack(std::string status, int ecode);
private:
    std::string marshal();
};

class SrsJanusAttachMessage : public SrsJanusCallstackMessage
{
private:
    std::string callid_;
    SrsRtcCallstackEvent* event_;
public:
    SrsJanusAttachMessage(SrsJanusCall* c, SrsJanusMessage* m);
    ~SrsJanusAttachMessage();
public:
    void write_callstack(std::string status, int ecode);
private:
    std::string marshal();
};

class SrsJanusTrickleMessage : public SrsJanusCallstackMessage
{
private:
    std::string callid_;
    std::string candidate_;
    bool completed_;

    SrsRtcCallstackEvent* event_;
public:
    SrsJanusTrickleMessage(SrsJanusCall* c, SrsJanusMessage* m, std::string candidate, bool completed);
    virtual ~SrsJanusTrickleMessage();
public:
    void write_callstack(std::string status, int ecode);
private:
    std::string marshal();
};

class SrsJanusJoinMessage : public SrsJanusCallstackMessage
{
private:
    std::string callid_;
    std::string participant_type_;
    std::string result_;
    uint64_t feedid_;

    SrsRtcCallstackEvent* event_;
public:
    SrsJanusJoinMessage(SrsJanusCall* c, SrsJanusMessage* m, std::string ptype, std::string result);
    virtual ~SrsJanusJoinMessage();
public:
    void write_callstack(std::string status, int ecode);
private:
    std::string marshal();
};

struct SrsJanusProcessOfferMessage : public SrsJanusCallstackMessage
{
public:
    std::string callid_;

    SrsRtcCallstackEvent* event_;
public:
    SrsJanusProcessOfferMessage(SrsJanusCall* c, SrsJanusMessage* m);
    ~SrsJanusProcessOfferMessage();
public:
    void write_callstack(std::string status, int ecode);
private:
    std::string marshal();
};

#endif

