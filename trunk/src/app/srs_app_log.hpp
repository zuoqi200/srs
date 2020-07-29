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

#ifndef SRS_APP_LOG_HPP
#define SRS_APP_LOG_HPP

#include <srs_core.hpp>

#include <string.h>
#include <string>
#include <vector>

#include <srs_app_reload.hpp>
#include <srs_service_log.hpp>
#include <srs_app_rtc_source.hpp>

// Use memory/disk cache and donot flush when write log.
// it's ok to use it without config, which will log to console, and default trace level.
// when you want to use different level, override this classs, set the protected _level.
class SrsFileLog : public ISrsLog, public ISrsReloadHandler
{
private:
    // Defined in SrsLogLevel.
    SrsLogLevel level;
private:
    char* log_data;
    // Log to file if specified srs_log_file
    int fd;
    // Whether log to file tank
    bool log_to_file_tank;
    // Whether use utc time.
    bool utc;
public:
    SrsFileLog();
    virtual ~SrsFileLog();
// Interface ISrsLog
public:
    virtual srs_error_t initialize();
    virtual void reopen();
    virtual void verbose(const char* tag, SrsContextId context_id, const char* fmt, ...);
    virtual void info(const char* tag, SrsContextId context_id, const char* fmt, ...);
    virtual void trace(const char* tag, SrsContextId context_id, const char* fmt, ...);
    virtual void warn(const char* tag, SrsContextId context_id, const char* fmt, ...);
    virtual void error(const char* tag, SrsContextId context_id, const char* fmt, ...);
// Interface ISrsReloadHandler.
public:
    virtual srs_error_t on_reload_utc_time();
    virtual srs_error_t on_reload_log_tank();
    virtual srs_error_t on_reload_log_level();
    virtual srs_error_t on_reload_log_file();
private:
    virtual void write_log(int& fd, char* str_log, int size, int level);
    virtual void open_log_file();
};

// Tenfold module name.
#define SrsModuleName "tenfold"
#define SrsModuleSignaling "signaling"

// Tenfold application detail log in JSON.
class SrsJsonLog : public ISrsLog, public ISrsReloadHandler
{
private:
    // Defined in SrsLogLevel.
    SrsLogLevel level;
private:
    char* log_data;
    // Log to file if specified srs_log_file
    int fd;
    // Whether log to file tank
    bool log_to_file_tank;
    // Whether use utc time.
    bool utc;
public:
    SrsJsonLog();
    virtual ~SrsJsonLog();
// Interface ISrsLog
public:
    virtual srs_error_t initialize();
    virtual void reopen();
    virtual void verbose(const char* tag, SrsContextId context_id, const char* fmt, ...);
    virtual void info(const char* tag, SrsContextId context_id, const char* fmt, ...);
    virtual void trace(const char* tag, SrsContextId context_id, const char* fmt, ...);
    virtual void warn(const char* tag, SrsContextId context_id, const char* fmt, ...);
    virtual void error(const char* tag, SrsContextId context_id, const char* fmt, ...);
// Interface ISrsReloadHandler.
public:
    virtual srs_error_t on_reload_utc_time();
    virtual srs_error_t on_reload_log_tank();
    virtual srs_error_t on_reload_log_level();
    virtual srs_error_t on_reload_log_file();
private:
    virtual void write_log(int& fd, char* str_log, int size, int level, SrsContextId context_id, const char* tag);
    virtual void open_log_file();
};

// Tenfold SLS log writer.
class SrsLogWriter
{
private:
    int fd;
    bool enabled;
    bool log_to_file_tank;
    std::string category_;
public:
    SrsLogWriter(std::string category);
    virtual ~SrsLogWriter();
public:
    virtual srs_error_t initialize();
protected:
    virtual void write_log(const char* str_log, int size);
private:
    virtual void reopen();
    virtual void open_log_file();
};

class SrsRtcCallTraceId;
class SrsRtcConnection;
class SrsRtcCallstackEvent;
class SrsRtcICEMessage
{
public:
    // appID: app id.
    std::string appid_;
    // sessionID: session id.
    std::string sessionid_;
    // channelID: channel id.
    std::string channel_;
    // userID: user id.
    std::string userid_;
    // callID: callid for single pc.
    std::string callid_;

    // sfu: sfu ip.
    std::string sfu_;
    // command: iceDone
    std::string command_;
    // result: dtls result.
    std::string result_;

    // localCandidate: local candidate
    std::string local_candidate_;
    // remoteCandidate: remote candidate
    std::string remote_candidate_;
private:
    SrsRtcCallstackEvent* event_;
public:
    SrsRtcICEMessage(SrsRtcCallTraceId* id, SrsRtcConnection* c);
    ~SrsRtcICEMessage();
public:
    void write_callstack(std::string status, int ecode);
private:
    std::string marshal();
};

class SrsRtcDtlsMessage
{
public:
    // appID: app id.
    std::string appid_;
    // sessionID: session id.
    std::string sessionid_;
    // channelID: channel id.
    std::string channel_;
    // userID: user id.
    std::string userid_;
    // callID: call id.
    std::string callid_;
    // sfu: sfu ip.
    std::string sfu_;
    // command: DTLS
    std::string command_;
    // result: dtls result.
    std::string result_;
private:
    SrsRtcCallstackEvent* event_;
public:
    SrsRtcDtlsMessage(SrsRtcCallTraceId* id, SrsRtcConnection* c);
    ~SrsRtcDtlsMessage();
public:
    void write_callstack(std::string status, int ecode);
private:
    std::string marshal();
};

class SrsRtcSubstreamRelation
{
public:
    // type: audio or video
    std::string type_;
    // trackID: track id.
    std::string trackid_;
    // ssrcSource: publish ssrc.
    uint32_t ssrc_source_;
    // ssrc: subscribe ssrc.
    uint32_t ssrc_;
    // temporalLayer: temporal layer
    int temporal_layer_;
    // status: enable or disable.
    std::string status_;

    SrsRtcSubstreamRelation();
};

class SrsRtcAudioSendTrack;
class SrsRtcVideoSendTrack;
class SrsRtcSubRelationMessage
{
public:
    // appID: app id.
    std::string appid_;
    // sessionID: session id.
    std::string sessionid_;
    // channelID: channel id.
    std::string channel_;
    // userID: user id.
    std::string userid_;
    // callID: call id.
    std::string callid_;
    // sfu: sfu ip.
    std::string sfu_;
    // command: SubstreamRelation
    std::string command_;
    // result: relations.
    std::string result_;
private:
    SrsRtcCallstackEvent* event_;
    std::vector<SrsRtcSubstreamRelation> sub_streams_;
public:
    SrsRtcSubRelationMessage(SrsRtcCallTraceId* id, SrsRtcConnection* c, const std::vector<SrsTrackConfig>& cfgs,
        const std::map<uint32_t, SrsRtcAudioSendTrack*>& ats, const std::map<uint32_t, SrsRtcVideoSendTrack*>& vts
    );
    ~SrsRtcSubRelationMessage();
public:
    void write_callstack(std::string status, int ecode);
private:
    std::string marshal();
};

class SrsRtcMediaUpMessage
{
public:
    // appID: app id.
    std::string appid_;
    // sessionID: session id.
    std::string sessionid_;
    // channelID: channel id.
    std::string channel_;
    // userID: user id.
    std::string userid_;
    // callID: call id.
    std::string callid_;
    // sfu: sfu ip.
    std::string sfu_;
    // command: SubstreamRelation
    std::string command_;
    // result: relations.
    std::string result_;
    // mediaType: media type
    std::string media_type_;
private:
    SrsRtcCallstackEvent* event_;
public:
    SrsRtcMediaUpMessage(SrsRtcCallTraceId* id, SrsRtcConnection* c);
    ~SrsRtcMediaUpMessage();
public:
    void write_callstack(std::string media_type);
private:
    std::string marshal();
};

class SrsRtcCallstackEvent
{
public:
    // stage: Create/Media/Destroy
    std::string stage_;
    // status: enter/leave/flying/notify
    std::string status_;
    // createJanusSession/attachJanusHandle/...
    std::string action_;
    // code: the error code for callstack.
    int error_code_;

    // cid: context_id.
    std::string cid_;
    // appid: app id.
    std::string appid_;
    // channel: channel id.
    std::string channel_;
    // user: user id.
    std::string user_;
    // session: session id.
    std::string session_;
    // call: call id, if have.
    std::string call_;
    // tid: transaction id, if have
    std::string tid_;

    SrsRtcCallstackEvent(std::string stage, std::string action);
};

class SrsLogWriterCallstack : public SrsLogWriter
{
public:
    SrsLogWriterCallstack();
    virtual ~SrsLogWriterCallstack();
public:
    virtual void write(SrsRtcCallstackEvent* e, std::string m);
};

extern SrsLogWriterCallstack* _sls_callstack;

class SrsJanusRelationPublishInfo;
class SrsJanusRelationSubscribeInfo;
class SrsLogWriterRelation : public SrsLogWriter
{
public:
    SrsLogWriterRelation();
    virtual ~SrsLogWriterRelation();
public:
    void write(SrsJanusRelationPublishInfo* pub_info, SrsJanusRelationSubscribeInfo* sub_info);
};

class SrsRtcTrackStatisticLog
{
public:
    // type: audio or video.
    std::string type;
    // trackID: the track id.
    std::string track_id;
    // direction: recv or send.
    std::string direction;
    // turn: turn ip addr.
    std::string turn;
    // ssrc: the ssrc of track.
    uint32_t ssrc;

    // inReplays: in replay packets.
    uint32_t replays;
    // inReplayBytes: in replay bytes.
    uint32_t replay_bytes;
    // inPaddings: in padding packets.
    uint32_t paddings;
    // inPaddingBytes: in padding bytes.
    uint32_t padding_bytes;
    // inPackets: in packets.
    uint32_t packets;
    // inBytes: in bytes.
    uint32_t bytes;

    SrsRtcTrackStatisticLog();

    virtual ~SrsRtcTrackStatisticLog();
};

class SrsRtcTrackStatisticLogRecv : public SrsRtcTrackStatisticLog
{
public:
    // nackSent: the number of send nack.
    uint32_t nack_sent;
    // lost: lost packets.
    uint32_t lost;
    // lostRate: lost rate;
    uint32_t lost_rate;
    // validPacketRate: valid packet rate;
    double valid_packet_rate;
    // twccLossRate: twcc loss rate;
    uint32_t twcc_loss_rate;
    // twccMaxLossRate: twcc max loss Rate;
    uint32_t twcc_max_loss_rate;

    SrsRtcTrackStatisticLogRecv();
};

class SrsRtcTrackStatisticLogSend : public SrsRtcTrackStatisticLog
{
public:
    // nackRecv: the number of send nack.
    uint32_t nack_recv;
    // lostRemote: out lost packets.
    uint32_t lost_remote;
    // lostRateRemote: out lost rate;
    uint32_t lost_rate_remote;
    // validPacketRate: valid packet rate;
    double valid_packet_rate;

    SrsRtcTrackStatisticLogSend();
};

class SrsRtcCallTraceId;
class SrsLogWriteDataStatistic : public SrsLogWriter
{
public:
    SrsLogWriteDataStatistic();
    virtual ~SrsLogWriteDataStatistic();
public:
    virtual void write(SrsRtcCallTraceId* id, SrsRtcTrackStatisticLog* log);
};

extern SrsLogWriteDataStatistic* _sls_data_statistic;

class SrsRtcConnectionDownlinkBweStatistic
{
public:
    // used during caculate average.
	int count;

	int max_bitrate;
	int min_bitrate;
	int avg_bitrate;

	int max_rtt;
	int min_rtt;
	int avg_rtt;

	float max_loss_rate;
	float min_loss_rate;
	float avg_loss_rate;
public:
    SrsRtcConnectionDownlinkBweStatistic();
    virtual ~SrsRtcConnectionDownlinkBweStatistic();
public:
    void reset();
    void update(int bitrate, int rtt, float loss_rate);
};

class SrsRtcConnectionDownlinkBweEvent
{
public:
    // The total count for bwe event in every interval.
	uint64_t total_cnt;
	// The gcc result is congestion's result.
	uint64_t congestion_cnt;
	// Weakness. If our bitrate can't offer the T0 + FEC0 or T0.
	uint64_t weakness_cnt;
	// Queue delay overuse count.
	uint64_t qdelay_overuse_cnt;

	// Region counts.
	uint64_t loss_zero_percent_cnt;
	// (0, 5%]
	uint64_t loss_less_5_percent_cnt;
	// (5%, 10%]
	uint64_t loss_less_10_percent_cnt;
	// (10%, 20%]
	uint64_t loss_less_20_percent_cnt;
	// (20%, 30%]
	uint64_t loss_lenss_30_percent_cnt;
	// higher
	uint64_t loss_higher_30_percent_cnt;

	// (0, 300kb]
	uint64_t bitrate_less_300k;
	// (300k, 500k]
	uint64_t bitrate_less_500k;
	// (500k, 800k]
	uint64_t bitrate_less_800k;
	// (800k, 1200k]
	uint64_t bitrate_less_1200k;
	// higher
	uint64_t bitrate_higher_1200k;
public:
    SrsRtcConnectionDownlinkBweEvent();
    virtual ~SrsRtcConnectionDownlinkBweEvent();
public:
    void reset();
    void update_bwe(int bitrate, int rtt, float loss_rate);
    void update_weakness();
};

class SrsRtcConnectionDownlinkBweStatistic;
class SrsRtcConnectionDownlinkBweEvent;
class SrsLogWriteDownlinkBwe : public SrsLogWriter
{
public:
    SrsLogWriteDownlinkBwe();
    virtual ~SrsLogWriteDownlinkBwe();
public:
    virtual void write(SrsRtcCallTraceId* id, SrsRtcConnectionDownlinkBweStatistic* s, SrsRtcConnectionDownlinkBweEvent* e);
};

extern SrsLogWriteDownlinkBwe* _sls_downlink_bwe;

#endif

