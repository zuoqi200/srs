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

#include <srs_app_reload.hpp>
#include <srs_service_log.hpp>

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

class SrsJanusSession;
class SrsJanusUserConf;
struct SrsJanusMessage;
class SrsLogWriterCallstack : public SrsLogWriter
{
public:
    SrsLogWriterCallstack();
    virtual ~SrsLogWriterCallstack();
public:
    virtual void write(SrsJanusSession* s, SrsJanusUserConf* c, SrsJanusMessage* m);
};

struct SrsJanusRelationPublishInfo;
struct SrsJanusRelationSubscribeInfo;
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

#endif

