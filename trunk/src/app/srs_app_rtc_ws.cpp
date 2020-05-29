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

#include <srs_app_rtc_ws.hpp>

#include <string>
#include <arpa/inet.h>
#include <sstream>
using namespace std;

#include <srs_kernel_utility.hpp>
#include <srs_kernel_consts.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_core_autofree.hpp>
#include <srs_service_http_conn.hpp>
#include <srs_kernel_buffer.hpp>

ISrsWebsocket::ISrsWebsocket()
{
}

ISrsWebsocket::~ISrsWebsocket()
{
}

SrsWebsocketClient::SrsWebsocketClient(ISrsWebsocket* wb, int id)
{
    id_ = id;
    wb_handler_ = wb;
    state_ = SrsWebsocketClient::SrsWebsocketState_not_start;
    transport = NULL;
    recv_timeout = timeout = SRS_UTIME_NO_TIMEOUT;
    port = 0;

    trd = new SrsDummyCoroutine();
}
    
SrsWebsocketClient::~SrsWebsocketClient()
{
    disconnect();
    
    srs_freep(trd);
}

srs_error_t SrsWebsocketClient::connect(std::string url, srs_utime_t tm)
{
    srs_error_t err = srs_success;

    state_ = SrsWebsocketClient::SrsWebsocketState_negotiating;

    SrsHttpUri uri;
    if ((err = uri.initialize(url)) != srs_success) {
        return srs_error_wrap(err, "http: parse url. url=%s", url.c_str());
    }
    
    // Always disconnect the transport.
    host = uri.get_host();
    port = uri.get_port();
    recv_timeout = timeout = tm;
    disconnect();
    
    // ep used for host in header.
    string ep = host;
    if (port > 0 && port != SRS_CONSTS_HTTP_DEFAULT_PORT) {
        ep += ":" + srs_int2str(port);
    }
    
    // Set default value for headers.
    headers["Host"] = ep;
    headers["User-Agent"] = RTMP_SIG_SRS_SERVER;
    // websocket header
    headers["Connection"] = "Upgrade";
    headers["Upgrade"] = "websocket";
    headers["Sec-WebSocket-Version"] = "13";
    // TODO: FIXME: generate by random and encode by base64
    headers["Sec-WebSocket-Key"] = "Cukm8ELu8audsfP6PqiQ7A==";

    string path = uri.get_path();
    if (!uri.get_query().empty()) {
        path += "?" + uri.get_query();
    }
    
    if (srs_success != (err = negotiate(path))) {
        return srs_error_wrap(err, "websocket: fail to negotiate");
    }
    
    srs_freep(trd);
    trd = new SrsSTCoroutine("wb_receive", this);
    if ((err = trd->start()) != srs_success) {
        return srs_error_wrap(err, "start thread");
    }
    state_ = SrsWebsocketClient::SrsWebsocketState_connected;

    return err;
}

srs_error_t SrsWebsocketClient::negotiate(std::string uri)
{
    srs_error_t err = srs_success;
    
    if ((err = connect()) != srs_success) {
        return srs_error_wrap(err, "http: connect server");
    }
    
    // send POST request to uri
    // GET %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s
    std::stringstream ss;
    ss << "GET " << uri << " " << "HTTP/1.1" << SRS_HTTP_CRLF;
    for (map<string, string>::iterator it = headers.begin(); it != headers.end(); ++it) {
        string key = it->first;
        string value = it->second;
        ss << key << ": " << value << SRS_HTTP_CRLF;
    }
    ss<<SRS_HTTP_CRLF;
    
    std::string data = ss.str();
    if ((err = transport->write((void*)data.c_str(), data.length(), NULL)) != srs_success) {
        // Disconnect the transport when channel error, reconnect for next operation.
        disconnect();
        return srs_error_wrap(err, "http: write");
    }

    SrsHttpParser parser;
    if ((err = parser.initialize(HTTP_RESPONSE, false)) != srs_success) {
        return srs_error_wrap(err, "http: init parser");
    }
    
    ISrsHttpMessage* msg = NULL;
    if ((err = parser.parse_message(transport, &msg)) != srs_success) {
        return srs_error_wrap(err, "http: parse response");
    }
    srs_assert(msg);
    SrsAutoFree(ISrsHttpMessage, msg);

    int code = msg->status_code();
    if (101 != code) {
        return srs_error_new(ERROR_WEBSOCKET_STATUS_CODE, "invalid status code %d", code);
    }

    //TODO: check header
    
    return err;
}
    
srs_error_t SrsWebsocketClient::send(ISrsWebsocket::SrsWebsocketMsgType type, uint64_t len, uint8_t* msg)
{
    if (SrsWebsocketClient::SrsWebsocketState_connected != state_) {
        return srs_error_new(ERROR_WEBSOCKET_INVALID_STATUS, "cannot send. current state %d", state_);
    }

    uint8_t opcode = 0x01;
    if (ISrsWebsocket::SrsWebsocketMsgType_text == type) {
        opcode = 0x01;
    } else if (ISrsWebsocket::SrsWebsocketMsgType_bin == type) {
        opcode = 0x02;
    } else {
        return srs_error_new(ERROR_WEBSOCKET_OPCODE, "unkown type %d", type);
    }

    return do_send(opcode, len, msg);
}
srs_error_t SrsWebsocketClient::do_send(uint8_t opcode, uint64_t len, uint8_t* msg)
{
    srs_error_t err = srs_success;

    uint32_t mask_tmp = rand();
    uint8_t mask[4];
    memcpy(mask, &mask_tmp, sizeof(mask));
    uint64_t msg_len = 2 /* header*/ + sizeof(mask) + len;
    if ((125 < len) && (0xFFFF >= len)) {
        msg_len += 2;
    } else if ( 0xFFFF < len) {
        msg_len += 8;
    }

    uint8_t* bin = new uint8_t[msg_len+8];
    SrsBuffer buf((char*)bin, msg_len);
    buf.write_1bytes(0x80 | opcode);

    if (125 >= len) {
        buf.write_1bytes(0x80 | len);
    } else if (0xFFFF >= len) {
        buf.write_1bytes((int8_t)(0x80 | 0x7E));
        buf.write_2bytes(len);
    } else {
        buf.write_1bytes((int8_t)(0x80 | 0x7F));
        buf.write_8bytes(len);
    }

    buf.write_bytes((char*)&mask, sizeof(mask));
    for(uint64_t i = 0; i<len; ++i) {
        buf.write_1bytes(msg[i] ^ mask[i % 4]);
    }

    while(0 < msg_len) {
        ssize_t nwrite = 0;
        if (srs_success != (err = transport->write(bin, msg_len, &nwrite))) {
            return srs_error_wrap(err, "fail to send websocket msg. msg_len:%d", msg_len);
        }
        msg_len -= nwrite;
        bin += nwrite;
    }
    return err;
}
    
srs_error_t SrsWebsocketClient::close(SrsWebsocketStatusCode code, int len, uint8_t* msg)
{
    srs_error_t err = srs_success;

    if (SrsWebsocketClient::SrsWebsocketState_not_start == state_ || 
        SrsWebsocketClient::SrsWebsocketState_negotiating == state_) {
        return srs_error_new(ERROR_WEBSOCKET_INVALID_STATUS, "cannot close. state:%d", state_);
    }

    if (SrsWebsocketClient::SrsWebsocketState_closing == state_ || 
        SrsWebsocketClient::SrsWebsocketState_closed == state_) {
        return srs_success;
    }

    state_ = SrsWebsocketClient::SrsWebsocketState_closing;
    uint16_t net_code = htons(code);
    uint8_t* close_msg = new uint8_t[len + 8];
    SrsAutoFreeA(uint8_t, close_msg);
    memcpy(close_msg, &net_code, sizeof(net_code));
    memcpy(close_msg+sizeof(net_code), msg, len);
    if (srs_success != (err = do_send(0x08, len+2, close_msg))) {
        return srs_error_wrap(err, "fail to send");
    }

    return err;
}

srs_error_t SrsWebsocketClient::ping(uint64_t len, uint8_t* msg)
{
    if (SrsWebsocketClient::SrsWebsocketState_connected != state_) {
        return srs_error_new(ERROR_WEBSOCKET_INVALID_STATUS, "cannot ping. state:%d", state_);
    }
    return do_send(0x09, len, msg);
}

void SrsWebsocketClient::disconnect()
{
    srs_freep(transport);
}

srs_error_t SrsWebsocketClient::connect()
{
    srs_error_t err = srs_success;
    
    // When transport connected, ignore.
    if (transport) {
        return err;
    }
    
    transport = new SrsTcpClient(host, port, timeout);
    if ((err = transport->connect()) != srs_success) {
        disconnect();
        return srs_error_wrap(err, "http: tcp connect %s:%d to=%dms, rto=%dms",
            host.c_str(), port, srsu2msi(timeout), srsu2msi(recv_timeout));
    }
    
    // Set the recv/send timeout in srs_utime_t.
    transport->set_recv_timeout(recv_timeout);
    transport->set_send_timeout(timeout);
    
    return err;
}

srs_error_t SrsWebsocketClient::handle_msg(uint8_t opcode, uint64_t len, uint8_t* msg)
{
    srs_error_t err = srs_success;

    if (0x09 == opcode) {
        // handle ping request and response pong
        return do_send(0x0A, len, msg);
    } else if ( 0x01 == opcode) {
        // invoke handler->recv
        return wb_handler_->on_recv_msg(id_, ISrsWebsocket::SrsWebsocketMsgType_text, len , msg);
    } else if (0x02 == opcode) {
        return wb_handler_->on_recv_msg(id_, ISrsWebsocket::SrsWebsocketMsgType_bin, len , msg);
    } else if (0x0A == opcode) {
        // receive pong response and invoke header->on_pong
        return wb_handler_->on_pong(id_, len, msg);
    } else if (0x08 == opcode) {
        //receive close msg
        //if it has send close request, so it is response, then just close
        // if not , it is request. Then send close response and invoke handler on_close
        if (SrsWebsocketClient::SrsWebsocketState_closing != state_) {
            // invoke handler
            if (2 <= len) {
                uint16_t code = ntohs(*((uint16_t*)msg));
                if (srs_success != (err = wb_handler_->on_close(id_, code, len - 2 , msg + 2))) {
                    return srs_error_wrap(err, "fail to handle close request");
                }
            } else {
                if (srs_success != (err = wb_handler_->on_close(id_, 1000, 0 , NULL))) {
                    return srs_error_wrap(err, "fail to handle close request");
                }
            }
            // send close response
            if (srs_success != (err = do_send(0x08, 0, NULL))) {
                return srs_error_wrap(err, "fail to send close response. %s", msg);
            }
        } 
        state_ = SrsWebsocketClient::SrsWebsocketState_closed;
        disconnect();
    } else {
        srs_warn("websocket - unkown opcode %x", opcode);
    }

    return err;
}

srs_error_t SrsWebsocketClient::cycle()
{
    srs_error_t err = srs_success;

    const int fix_size = 500 * 1024;
    uint8_t* payload_fix = new uint8_t[fix_size];
    SrsAutoFreeA(uint8_t, payload_fix);
    uint8_t* payload_large = NULL;
    uint8_t header[16];
    ssize_t nread = 0;
    while(SrsWebsocketClient::SrsWebsocketState_closed != state_) {
        if ((err = trd->pull()) != srs_success) {
            srs_error("Failed, %s", srs_error_desc(err).c_str());
            return srs_error_wrap(err, "websocket listener");
        }

        memset(header, 0, sizeof(header));
        if (srs_success != (err = transport->read(header, 2, &nread))) {
            return srs_error_wrap(err, "fail to read websocket header");
        }

        if (0 == nread) {
            continue;
        }
        // TODO: check if nread < 2, proceed to read header
        uint8_t fin = (header[0] & 0x80) >> 7;
        uint8_t opcode = (header[0] & 0x0F);
        uint8_t mask = (header[1] & 0x80) >> 7;
        assert(mask == 0);
        uint8_t payload_len = header[1] & 0x7F;
        srs_trace("recv websocket header: fin %u, opcode %u, payload_len %u", fin, opcode, payload_len);

        uint64_t real_len = payload_len;
        if (0x7E > real_len) {
            real_len = payload_len;
        } else if (0x7E == real_len) {
            if (srs_success != (err = transport->read(header+2, 2, &nread))) {
                return srs_error_wrap(err, "fail to read websocket len");
            }
            real_len = ntohs(*((uint16_t*)(header + 2)));
        } else if (0x7F == real_len) {
            if (srs_success != (err = transport->read(header+2, 8, &nread))) {
                return srs_error_wrap(err, "fail to read websocket len");
            }
            real_len = ntohll(*((uint64_t*)(header+2)));
        }

        srs_trace("recv websocket header: real payload len:%llu", real_len);

        uint64_t rest = real_len;
        uint8_t* p = payload_fix;
        if (fix_size <= real_len) {
                payload_large = new uint8_t[real_len + 8];
                p = payload_large;
        }
        // TODO: FIXME: Use transport->read_fully
        while(rest > 0) {
            nread = 0;
            if (srs_success != (err = transport->read(p, rest, &nread))) {
                return srs_error_wrap(err, "fail to read websocket payload");
            }
            p += nread;
            rest -= nread;
        }
        if (fix_size > real_len) {
            srs_trace("websocket: recv payload - %s", payload_fix);
            if (srs_success != (err = handle_msg(opcode, real_len, payload_fix))) {
                srs_error("fail to process websocket msg. %s", srs_error_desc(err).c_str());   
            }
        } else {
            srs_trace("websocket: recv payload - %s", payload_large);
            if (srs_success != (err = handle_msg(opcode, real_len, payload_large))) {
                srs_error("fail to process websocket msg. %s", srs_error_desc(err).c_str());   
            }
            delete []payload_large;
            payload_large = NULL;
        }
    }

    return err;
}

