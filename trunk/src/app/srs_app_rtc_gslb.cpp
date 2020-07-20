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

#include <srs_app_rtc_gslb.hpp>

#include <openssl/sha.h>
#include <sstream>
using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_app_config.hpp>
#include <srs_app_http_client.hpp>
#include <srs_protocol_json.hpp>
#include <srs_app_utility.hpp>
#include <srs_core_autofree.hpp>
#include <srs_app_http_conn.hpp>
#include <srs_protocol_amf0.hpp>
#include <srs_kernel_utility.hpp>

SrsGSLBHeartbeat::SrsGSLBHeartbeat()
{
    url_ = _srs_config->get_gslb_url();
    api_key_ = _srs_config->get_gslb_api_key();
    timer = new SrsHourGlass(this, 1 * SRS_UTIME_SECONDS);
}

SrsGSLBHeartbeat::~SrsGSLBHeartbeat()
{
}

srs_error_t SrsGSLBHeartbeat::initialize()
{
    srs_error_t err = srs_success;

    if ((err = timer->tick(_srs_config->get_gslb_interval())) != srs_success) {
        return srs_error_wrap(err, "hourglass tick");
    }
    
    if ((err = timer->start()) != srs_success) {
        return srs_error_wrap(err, "start timer");
    }

    srs_trace("Srs GSLB Heartbeat init ok");
    return err;
}

srs_error_t SrsGSLBHeartbeat::heartbeat()
{
    srs_error_t err = srs_success;
    
    std::ostringstream timestamp;
    srs_utime_t now_us = srs_get_system_time();
    timestamp << now_us;

    std::string signature = generate_api_signature(timestamp.str());
    std::string url = url_ + "?timestamp=" + timestamp.str() + "&signature=" + signature;

    SrsHttpUri uri;
    if ((err = uri.initialize(url)) != srs_success) {
        return srs_error_wrap(err, "http uri parse gslb url failed. url=%s", url.c_str());
    }
    
    SrsIPAddress* ip = NULL;
    vector<SrsIPAddress*>& ips = srs_get_local_ips();
    if (!ips.empty()) {
        ip = ips[_srs_config->get_stats_network() % (int)ips.size()];
    }

    std::string hostname = srs_get_system_hostname();
    if (hostname.empty()) {
        return srs_error_wrap(err, "GSLB Heartbeat failed. hostname is empty");
    }

    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);
    
    obj->set("type", SrsJsonAny::str("tfsfu"));
    obj->set("private_ip", SrsJsonAny::str(ip->ip.c_str()));
    obj->set("hostname", SrsJsonAny::str(hostname.c_str()));
    obj->set("load", SrsJsonAny::integer(0));
    
    SrsHttpClient http;
    if ((err = http.initialize(uri.get_host(), uri.get_port())) != srs_success) {
        return srs_error_wrap(err, "init uri=%s", uri.get_url().c_str());
    }
    
    std::string req = obj->dumps();
    ISrsHttpMessage* msg = NULL;
    if ((err = http.post(uri.get_url(), req, &msg)) != srs_success) {
        return srs_error_wrap(err, "http post hartbeart uri failed. url=%s, request=%s", url.c_str(), req.c_str());
    }
    SrsAutoFree(ISrsHttpMessage, msg);
    
    srs_trace("keepalive to gslb, url=%s, req=%s", url.c_str(), req.c_str());
    
    std::string res;
    if ((err = msg->body_read_all(res)) != srs_success) {
        return srs_error_wrap(err, "read body");
    }
    
    return err;
}

#define SHA256_DIGEST_LENGTH    32
std::string SrsGSLBHeartbeat::generate_api_signature(std::string timestamp)
{
    unsigned char sha_result[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, timestamp.c_str(), timestamp.size());
	SHA256_Update(&sha256, api_key_.c_str(), api_key_.size());
	SHA256_Final(sha_result, &sha256);

    char signature[2 * SHA256_DIGEST_LENGTH + 1];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(signature + i * 2, sizeof(signature) - i * 2, "%02x", sha_result[i]);
	}
	signature[2 * SHA256_DIGEST_LENGTH] = 0;

    return std::string(signature);
}

srs_error_t SrsGSLBHeartbeat::notify(int type, srs_utime_t interval, srs_utime_t tick)
{
    srs_error_t err = srs_success;
    
    if ((err = heartbeat())!= srs_success) {
        return srs_error_wrap(err, "timer notify");
    }

    return err;
}