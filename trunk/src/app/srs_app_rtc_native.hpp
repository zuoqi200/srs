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

#ifndef SRS_APP_RTC_NATIVE_HPP
#define SRS_APP_RTC_NATIVE_HPP

#include <srs_core.hpp>
#include <srs_app_listener.hpp>
#include <srs_app_hourglass.hpp>
#include <srs_app_rtc_conn.hpp>

#include <map>
#include <string>
#include <vector>

class SrsRtcConnection;
class SrsRtcPlayStream;
class SrsRtcPublishStream;
class SrsRtcServer;
class SrsUdpMuxListener;
class SrsRtcNativeHeader;
class SrsRtcNativeCall;
class SrsRequest;
class SrsRtcStream;

class SrsRtcNativeClientPublishCall;
class SrsRtcNativeClientSubscribeCall;

class SrsRtcNativeSession : virtual public ISrsUdpMuxHandler, virtual public ISrsHourGlass, virtual public ISrsRtcConnectionHijacker
{
public:
    enum SrsRtcNativeSessionRole {
        ROLE_SERVER,
        ROLE_CLIENT,
    };
    enum SrsRtcNativeSessionState {
        STATE_INIT,
        STATE_DTLS, //for encryption mode
        STATE_TMP_RESPONSE,  //only for connect
        STATE_FINAL_RESPONSE, //only for connect
        STATE_CONNECTED,
        STATE_CLOSED,
        STATE_FAILED,
        STATE_TIMEOUT,
    };
    enum {
        SESSION_DEFAULT_TIMEOUT_US = 15000000, //15s
        SESSION_HEARTBEAT_INTERVAL = 500000,   //500ms
        SESSION_TIMER_INTERVAL     = 100000,   //100ms
    };
public:
    static const int RETRY_INTERVAL[];
    SrsRtcServer      *rtc_;
private:
    const SrsRtcNativeSessionRole   role_;
    const bool                      encrypt_;
    const srs_utime_t               start_us_;
    SrsRtcNativeSessionState        state_;
    srs_utime_t                     last_heartbeat_us_;
    uint16_t                        msg_id_;              //last send msg id
    uint16_t                        connect_msg_id_;      //only for connect request
    // publish call and play call may has same url, using two container
    std::map<std::string, SrsRtcNativeCall*> publish_calls_;
    std::map<std::string, SrsRtcNativeCall*> subscribe_calls_;
    typedef std::map<std::string, SrsRtcNativeCall*>::iterator CallIterator;
private:
    SrsRtcConnection               *conn_;
    SrsHourGlass                   *timer_;
    SrsContextId                    cid_;
// for ROLE_CLIENT
private:
    SrsUdpMuxListener              *listener_;
    SrsUdpMuxSocket                *udp_socket_;
    std::string                     server_ip_;
    int                             server_port_;
public:
    static srs_error_t parse_signaling(char *data, int nb_data, SrsRtcNativeHeader **msg);
    static srs_error_t parse_url(const std::string &url, SrsRequest **request);
    static int get_retry_interval(int retry_count);
public:
    SrsRtcNativeSession(SrsRtcServer* server, SrsRtcNativeSessionRole role, bool encrypt);
    SrsRtcNativeSession(SrsRtcServer* server, const std::string &server_ip, int server_port, bool encrypt);
    virtual ~SrsRtcNativeSession();
    // start timer and udp listener
    srs_error_t start();
    void stop();
    bool is_alive();
public:
    srs_error_t publish(const std::string &url, SrsRtcNativeClientPublishCall **call);
    srs_error_t subscribe(const std::string &url, SrsRtcNativeClientSubscribeCall **call);
public:
    SrsRtcConnection* get_rtc_connection();
    srs_error_t on_signaling(char* data, int nb_data);
    srs_error_t update_state(SrsRtcNativeSessionState new_state);
// for self and SrsRtcNativeCall
public:
    srs_error_t send_signaling(SrsRtcNativeHeader *msg);
    const SrsContextId& get_cid();
    uint16_t gen_new_msg_id();
// for ISrsUdpMuxHandler
public:
    virtual srs_error_t on_udp_packet(SrsUdpMuxSocket* skt);
// for ISrsHourGlass
public:
    virtual srs_error_t notify(int event, srs_utime_t interval, srs_utime_t tick);
// for ISrsRtcConnectionHijacker
public:
    virtual srs_error_t on_dtls_done();
private:
    srs_error_t check_state();
// process incoming signaling
private:
// signalling entrance
    srs_error_t process_signaling(SrsRtcNativeHeader *msg);
// session level signaling request & response
    srs_error_t process_connect(SrsRtcNativeHeader *msg);
    srs_error_t process_disconnect(SrsRtcNativeHeader *msg);
    srs_error_t process_mtu_detect(SrsRtcNativeHeader *msg);
    srs_error_t process_notify(SrsRtcNativeHeader *msg);
    srs_error_t process_wan_ip_port_switch(SrsRtcNativeHeader *msg);
    srs_error_t process_heartbeat(SrsRtcNativeHeader *msg);
// call level stop request & response
    srs_error_t process_stop(SrsRtcNativeHeader *msg);
// call level signaling request process
    srs_error_t process_publish_request(SrsRtcNativeHeader *msg);
    srs_error_t process_subscribe_request(SrsRtcNativeHeader *msg);
    srs_error_t process_publish_update_request(SrsRtcNativeHeader *msg);
    srs_error_t process_subscribe_update_request(SrsRtcNativeHeader *msg);
    srs_error_t process_switch_stream_request(SrsRtcNativeHeader *msg);
// call level signaling response process
    srs_error_t process_temp_response(SrsRtcNativeHeader *msg);
    srs_error_t process_response(SrsRtcNativeHeader *msg);
    srs_error_t process_final_ack(SrsRtcNativeHeader *msg);
// for client mode
    srs_error_t send_heartbeat();
};


class SrsRtcNativeSessionManager : virtual public ISrsHourGlass
{
private:
    SrsRtcServer                   *rtc_;
    SrsHourGlass                   *timer_;
    std::map<std::string, SrsRtcNativeSession*> sessions_;
    std::vector<SrsRtcNativeSession*> zombies_;
public:
    SrsRtcNativeSessionManager();
    virtual ~SrsRtcNativeSessionManager();
    srs_error_t initialize(SrsRtcServer *server);
public:
    // client mode
    srs_error_t fetch_or_create(const std::string &server_ip, int server_port, SrsRtcNativeSession **session);
    // server mode 
    srs_error_t create(char* data, int nb_data, SrsRtcNativeSession **session);
// for ISrsHourGlass
public:
    virtual srs_error_t notify(int event, srs_utime_t interval, srs_utime_t tick);
};

// Global singleton instance.
extern SrsRtcNativeSessionManager* _srs_rtc_native;

class SrsRtcNativeCall
{
public:
    enum SrsRtcNativeCallState {
        STATE_NONE,
        STATE_INIT,
        STATE_TMP_RESPONSE,
        STATE_FINAL_RESPONSE,
        STATE_CONNECTED,
        STATE_STOP,
        STATE_FAILED,
        STATE_TIMEOUT,
    };
    enum SrsRtcNativeCallType {
        TYPE_SERVER_PUBLISH,
        TYPE_SERVER_PLAY,
        TYPE_CLIENT_PUBLISH,
        TYPE_CLIENT_SUBSCRIBE,
    };
    enum SrsRtcNativeCallRetryType {
        TYPE_CALL       = 0,
        TYPE_UPDATE,
        TYPE_SWITCH,
        TYPE_CONTROL,
        TYPE_MAX,    
    };
private:
    class RetryItem {
    public:
        srs_utime_t         retry_us;
        int                 retry_count;
        SrsRtcNativeHeader *msg;
    };
protected:
    const std::string           url_;
    SrsRtcNativeCallState       state_;
    SrsRtcNativeSession        *session_;
    SrsRequest                 *req_;
    SrsRtcStream               *source_;
    uint16_t                    msg_id_;  // msg id for call originate msg
    uint16_t                    last_recv_msg_id_;
    uint16_t                    last_send_msg_id_;
    SrsContextId                cid_;
private:
    const SrsRtcNativeCallType  type_;
    const srs_utime_t           start_us_;
    RetryItem                   retry_items_[TYPE_MAX];
public:
    SrsRtcNativeCall(SrsRtcNativeSession *session, SrsRtcNativeCallType type, const std::string &url);
    virtual ~SrsRtcNativeCall();
public:
    srs_error_t check_state(SrsRtcNativeCallState &state);
    srs_error_t on_signaling(SrsRtcNativeHeader *msg);
public:
    srs_error_t start();
    srs_error_t stop(bool from_signaling);
    // for call or session signaling process
    srs_error_t update_state(SrsRtcNativeCallState state);
public:
    // for session manager call;
    uint16_t msg_id() const { return msg_id_;}
    uint16_t last_recv_msg_id() const { return last_recv_msg_id_; }
    uint16_t last_send_msg_id() const { return last_send_msg_id_; }
protected:
    srs_error_t send_temp_response();
    srs_error_t send_final_ack();
    void set_retry_info(SrsRtcNativeCallRetryType retry_type, SrsRtcNativeHeader *msg);
protected:
    virtual srs_error_t do_start();
    virtual srs_error_t process_signaling(SrsRtcNativeHeader *msg) = 0;
private:
    // for play call
    srs_error_t process_media_control(SrsRtcNativeHeader *msg);
    srs_error_t state_change_verify(SrsRtcNativeCallState new_state);
    srs_error_t retry(int idx); 
};


// Incoming call for SrsRTCNativeSubTypePublish
class SrsRtcNativeServerPublishCall : public SrsRtcNativeCall
{
private:
    SrsRtcPublishStream *publish_;
public:
    SrsRtcNativeServerPublishCall(SrsRtcNativeSession *session, const std::string &url);
    virtual ~SrsRtcNativeServerPublishCall();
protected:
    virtual srs_error_t process_signaling(SrsRtcNativeHeader *msg);
private:
    srs_error_t process_publish_request(SrsRtcNativeHeader *msg);
    srs_error_t process_publish_update_request(SrsRtcNativeHeader *msg);
};


// Incoming call for SrsRTCNativeSubTypeSubscribe
class SrsRtcNativeServerPlayCall : public SrsRtcNativeCall
{
private:
    SrsRtcPlayStream *play_;
public:
    SrsRtcNativeServerPlayCall(SrsRtcNativeSession *session, const std::string &url);
    virtual ~SrsRtcNativeServerPlayCall();
protected:
    virtual srs_error_t process_signaling(SrsRtcNativeHeader *msg);
private:
    srs_error_t process_subscribe_request(SrsRtcNativeHeader *msg);
    srs_error_t process_publish_subscribe_request(SrsRtcNativeHeader *msg);
    srs_error_t process_switch_msid_request(SrsRtcNativeHeader *msg);
};


// Outgoing call for SrsRTCNativeSubTypeSubscribe
class SrsRtcNativeClientSubscribeCall : public SrsRtcNativeCall
{
private:
    SrsRtcPublishStream *publish_;
public:
    SrsRtcNativeClientSubscribeCall(SrsRtcNativeSession *session, const std::string &url);
    virtual ~SrsRtcNativeClientSubscribeCall();
public:
    virtual srs_error_t do_start();
protected:
    virtual srs_error_t process_signaling(SrsRtcNativeHeader *msg);
private:
    srs_error_t process_subscribe_response(SrsRtcNativeHeader *msg);
    srs_error_t process_subscribe_update_response(SrsRtcNativeHeader *msg);
};


// Outgoing call for SrsRTCNativeSubTypePublish
class SrsRtcNativeClientPublishCall : public SrsRtcNativeCall
{
private:
    SrsRtcPlayStream *play_;
public:
    SrsRtcNativeClientPublishCall(SrsRtcNativeSession *session, const std::string &url);
    virtual ~SrsRtcNativeClientPublishCall();
public:
    virtual srs_error_t do_start();
protected:
    virtual srs_error_t process_signaling(SrsRtcNativeHeader *msg);
private:
    srs_error_t process_publish_response(SrsRtcNativeHeader *msg);
    srs_error_t process_publish_update_response(SrsRtcNativeHeader *msg);  
}; 

#endif
