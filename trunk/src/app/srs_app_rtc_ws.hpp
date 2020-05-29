/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2013-2020 Li Peng
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

#ifndef SRS_APP_RTC_WEBSOCKET_HPP
#define SRS_APP_RTC_WEBSOCKET_HPP

#include <srs_core.hpp>

#include <srs_service_http_client.hpp>
#include <srs_service_st.hpp>
#include <srs_http_stack.hpp>
#include <srs_app_st.hpp>

#include <string>

class SrsHttpUri;
class ISrsHttpMessage;
class SrsStSocket;
class SrsTcpClient;

// @see https://tools.ietf.org/html/rfc6455
// @see https://zhuanlan.zhihu.com/p/36904470

enum SrsWebsocketStatusCode {
    SrsWebsocketStatusCode_normal = 1000,
    SrsWebsocketStatusCode_goway = 1001,
    SrsWebsocketStatusCode_protocol_error = 1002,
    SrsWebsocketStatusCode_type_error = 1003,
    SrsWebsocketStatusCode_diff_msg = 1007,
    SrsWebsocketStatusCode_voilate = 1008,
    SrsWebsocketStatusCode_too_big = 1009,
    SrsWebsocketStatusCode_extension = 1010,
    SrsWebsocketStatusCode_server_error = 1011,
};

class ISrsWebsocket 
{
public:
    enum SrsWebsocketMsgType {
        SrsWebsocketMsgType_text = 1,
        SrsWebsocketMsgType_bin = 2,
    };
public:
    ISrsWebsocket();
    virtual ~ISrsWebsocket();
public:
    // TODO: FIXME: Add comments for interface.
    virtual srs_error_t on_recv_msg(int id, SrsWebsocketMsgType type, int msg_len, uint8_t* msg) = 0;
    virtual srs_error_t on_pong(int id, int msg_len, uint8_t* msg) = 0;
    virtual srs_error_t on_close(int id, uint16_t code, int msg_len, uint8_t* msg) = 0;
};

class SrsWebsocketClient : public ISrsCoroutineHandler
{
private:
    enum SrsWebsocketState {
        SrsWebsocketState_not_start,
        SrsWebsocketState_negotiating,
        SrsWebsocketState_connected,
        SrsWebsocketState_closing,
        SrsWebsocketState_closed,
    };

    SrsWebsocketState state_;
    // The underlayer TCP transport, set to NULL when disconnect, or never not NULL when connected.
    // We will disconnect transport when initialize or channel error, such as send/recv error.
    SrsTcpClient* transport;
    std::map<std::string, std::string> headers;
    // The timeout in srs_utime_t.
    srs_utime_t timeout;
    srs_utime_t recv_timeout;
    // The host name or ip.
    std::string host;
    int port;

    SrsCoroutine* trd;
    int id_;
    ISrsWebsocket* wb_handler_;

private:
    srs_error_t negotiate(std::string uri);
    virtual void disconnect();
    virtual srs_error_t connect();

    srs_error_t do_send(uint8_t opcode, uint64_t len, uint8_t* msg);
    srs_error_t handle_msg(uint8_t opcode, uint64_t len, uint8_t* msg);

public:
    SrsWebsocketClient(ISrsWebsocket* wb, int id=0);
    virtual ~SrsWebsocketClient();

    srs_error_t connect(std::string url, srs_utime_t tm = SRS_HTTP_CLIENT_TIMEOUT);
    srs_error_t send(ISrsWebsocket::SrsWebsocketMsgType type, uint64_t len, uint8_t* msg);
    // msg : would the application define message. Generally msg is NULL
    srs_error_t ping(uint64_t len = 0, uint8_t* msg = NULL);
    // msg : the reason of close. 
    srs_error_t close(SrsWebsocketStatusCode code = SrsWebsocketStatusCode_normal, int len = 0, uint8_t* msg = NULL);

public:
    virtual srs_error_t cycle();

};

#endif

