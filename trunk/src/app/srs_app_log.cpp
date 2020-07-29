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

#include <srs_app_log.hpp>

#include <stdarg.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
using namespace std;

#include <srs_app_config.hpp>
#include <srs_kernel_error.hpp>
#include <srs_app_utility.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_core_autofree.hpp>
#include <srs_protocol_json.hpp>

#include <srs_app_rtc_source.hpp>
#include <srs_app_rtc_conn.hpp>

// the max size of a line of log.
#define LOG_MAX_SIZE 8192

// the tail append to each log.
#define LOG_TAIL '\n'
// reserved for the end of log data, it must be strlen(LOG_TAIL)
#define LOG_TAIL_SIZE 1

SrsFileLog::SrsFileLog()
{
    level = SrsLogLevelTrace;
    log_data = new char[LOG_MAX_SIZE];
    
    fd = -1;
    log_to_file_tank = false;
    utc = false;
}

SrsFileLog::~SrsFileLog()
{
    srs_freepa(log_data);
    
    if (fd > 0) {
        ::close(fd);
        fd = -1;
    }
    
    if (_srs_config) {
        _srs_config->unsubscribe(this);
    }
}

srs_error_t SrsFileLog::initialize()
{
    if (_srs_config) {
        _srs_config->subscribe(this);
        
        log_to_file_tank = _srs_config->get_log_tank_file();
        level = srs_get_log_level(_srs_config->get_log_level());
        utc = _srs_config->get_utc_time();
    }
    
    return srs_success;
}

void SrsFileLog::reopen()
{
    if (fd > 0) {
        ::close(fd);
    }
    
    if (!log_to_file_tank) {
        return;
    }
    
    open_log_file();
}

void SrsFileLog::verbose(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelVerbose) {
        return;
    }
    
    int size = 0;
    if (!srs_log_header(log_data, LOG_MAX_SIZE, utc, false, tag, context_id, "Verb", &size)) {
        return;
    }
    
    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    size += vsnprintf(log_data + size, LOG_MAX_SIZE - size, fmt, ap);
    va_end(ap);
    
    write_log(fd, log_data, size, SrsLogLevelVerbose);
}

void SrsFileLog::info(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelInfo) {
        return;
    }
    
    int size = 0;
    if (!srs_log_header(log_data, LOG_MAX_SIZE, utc, false, tag, context_id, "Debug", &size)) {
        return;
    }
    
    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    size += vsnprintf(log_data + size, LOG_MAX_SIZE - size, fmt, ap);
    va_end(ap);
    
    write_log(fd, log_data, size, SrsLogLevelInfo);
}

void SrsFileLog::trace(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelTrace) {
        return;
    }
    
    int size = 0;
    if (!srs_log_header(log_data, LOG_MAX_SIZE, utc, false, tag, context_id, "Trace", &size)) {
        return;
    }
    
    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    size += vsnprintf(log_data + size, LOG_MAX_SIZE - size, fmt, ap);
    va_end(ap);
    
    write_log(fd, log_data, size, SrsLogLevelTrace);
}

void SrsFileLog::warn(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelWarn) {
        return;
    }
    
    int size = 0;
    if (!srs_log_header(log_data, LOG_MAX_SIZE, utc, true, tag, context_id, "Warn", &size)) {
        return;
    }
    
    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    size += vsnprintf(log_data + size, LOG_MAX_SIZE - size, fmt, ap);
    va_end(ap);
    
    write_log(fd, log_data, size, SrsLogLevelWarn);
}

void SrsFileLog::error(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelError) {
        return;
    }
    
    int size = 0;
    if (!srs_log_header(log_data, LOG_MAX_SIZE, utc, true, tag, context_id, "Error", &size)) {
        return;
    }
    
    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    size += vsnprintf(log_data + size, LOG_MAX_SIZE - size, fmt, ap);
    va_end(ap);
    
    // add strerror() to error msg.
    // Check size to avoid security issue https://github.com/ossrs/srs/issues/1229
    if (errno != 0 && size < LOG_MAX_SIZE) {
        size += snprintf(log_data + size, LOG_MAX_SIZE - size, "(%s)", strerror(errno));
    }
    
    write_log(fd, log_data, size, SrsLogLevelError);
}

srs_error_t SrsFileLog::on_reload_utc_time()
{
    utc = _srs_config->get_utc_time();
    
    return srs_success;
}

srs_error_t SrsFileLog::on_reload_log_tank()
{
    srs_error_t err = srs_success;
    
    if (!_srs_config) {
        return err;
    }
    
    bool tank = log_to_file_tank;
    log_to_file_tank = _srs_config->get_log_tank_file();
    
    if (tank) {
        return err;
    }
    
    if (!log_to_file_tank) {
        return err;
    }
    
    if (fd > 0) {
        ::close(fd);
    }
    open_log_file();
    
    return err;
}

srs_error_t SrsFileLog::on_reload_log_level()
{
    srs_error_t err = srs_success;
    
    if (!_srs_config) {
        return err;
    }
    
    level = srs_get_log_level(_srs_config->get_log_level());
    
    return err;
}

srs_error_t SrsFileLog::on_reload_log_file()
{
    srs_error_t err = srs_success;
    
    if (!_srs_config) {
        return err;
    }
    
    if (!log_to_file_tank) {
        return err;
    }
    
    if (fd > 0) {
        ::close(fd);
    }
    open_log_file();
    
    return err;
}

void SrsFileLog::write_log(int& fd, char *str_log, int size, int level)
{
    // ensure the tail and EOF of string
    //      LOG_TAIL_SIZE for the TAIL char.
    //      1 for the last char(0).
    size = srs_min(LOG_MAX_SIZE - 1 - LOG_TAIL_SIZE, size);
    
    // add some to the end of char.
    str_log[size++] = LOG_TAIL;
    
    // if not to file, to console and return.
    if (!log_to_file_tank) {
        // if is error msg, then print color msg.
        // \033[31m : red text code in shell
        // \033[32m : green text code in shell
        // \033[33m : yellow text code in shell
        // \033[0m : normal text code
        if (level <= SrsLogLevelTrace) {
            printf("%.*s", size, str_log);
        } else if (level == SrsLogLevelWarn) {
            printf("\033[33m%.*s\033[0m", size, str_log);
        } else{
            printf("\033[31m%.*s\033[0m", size, str_log);
        }
        fflush(stdout);
        
        return;
    }
    
    // open log file. if specified
    if (fd < 0) {
        open_log_file();
    }
    
    // write log to file.
    if (fd > 0) {
        ::write(fd, str_log, size);
    }
}

void SrsFileLog::open_log_file()
{
    if (!_srs_config) {
        return;
    }
    
    std::string filename = _srs_config->get_log_file();
    
    if (filename.empty()) {
        return;
    }

    fd = ::open(filename.c_str(),
        O_RDWR | O_CREAT | O_APPEND,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH
    );
}

SrsJsonLog::SrsJsonLog()
{
    level = SrsLogLevelTrace;
    log_data = new char[LOG_MAX_SIZE];

    fd = -1;
    log_to_file_tank = false;
    utc = false;
}

SrsJsonLog::~SrsJsonLog()
{
    srs_freepa(log_data);

    if (fd > 0) {
        ::close(fd);
        fd = -1;
    }

    if (_srs_config) {
        _srs_config->unsubscribe(this);
    }
}

srs_error_t SrsJsonLog::initialize()
{
    if (_srs_config) {
        _srs_config->subscribe(this);

        log_to_file_tank = _srs_config->get_log_tank_file();
        level = srs_get_log_level(_srs_config->get_log_level());
        utc = _srs_config->get_utc_time();
    }

    return srs_success;
}

void SrsJsonLog::reopen()
{
    if (fd > 0) {
        ::close(fd);
    }

    if (!log_to_file_tank) {
        return;
    }

    open_log_file();
}

void SrsJsonLog::verbose(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelVerbose) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    int size = vsnprintf(log_data, LOG_MAX_SIZE, fmt, ap);
    va_end(ap);

    write_log(fd, log_data, size, SrsLogLevelVerbose, context_id, tag);
}

void SrsJsonLog::info(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelInfo) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    int size = vsnprintf(log_data, LOG_MAX_SIZE, fmt, ap);
    va_end(ap);

    write_log(fd, log_data, size, SrsLogLevelInfo, context_id, tag);
}

void SrsJsonLog::trace(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelTrace) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    int size = vsnprintf(log_data, LOG_MAX_SIZE, fmt, ap);
    va_end(ap);

    write_log(fd, log_data, size, SrsLogLevelTrace, context_id, tag);
}

void SrsJsonLog::warn(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelWarn) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    int size = vsnprintf(log_data, LOG_MAX_SIZE, fmt, ap);
    va_end(ap);

    write_log(fd, log_data, size, SrsLogLevelWarn, context_id, tag);
}

void SrsJsonLog::error(const char* tag, SrsContextId context_id, const char* fmt, ...)
{
    if (level > SrsLogLevelError) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    // we reserved 1 bytes for the new line.
    int size = vsnprintf(log_data, LOG_MAX_SIZE, fmt, ap);
    va_end(ap);

    // add strerror() to error msg.
    // Check size to avoid security issue https://github.com/ossrs/srs/issues/1229
    if (errno != 0 && size > 0 && size < LOG_MAX_SIZE) {
        size += snprintf(log_data + size, LOG_MAX_SIZE - size, "(%s)", strerror(errno));
    }

    write_log(fd, log_data, size, SrsLogLevelError, context_id, tag);
}

srs_error_t SrsJsonLog::on_reload_utc_time()
{
    utc = _srs_config->get_utc_time();

    return srs_success;
}

srs_error_t SrsJsonLog::on_reload_log_tank()
{
    srs_error_t err = srs_success;

    if (!_srs_config) {
        return err;
    }

    bool tank = log_to_file_tank;
    log_to_file_tank = _srs_config->get_log_tank_file();

    if (tank) {
        return err;
    }

    if (!log_to_file_tank) {
        return err;
    }

    if (fd > 0) {
        ::close(fd);
    }
    open_log_file();

    return err;
}

srs_error_t SrsJsonLog::on_reload_log_level()
{
    srs_error_t err = srs_success;

    if (!_srs_config) {
        return err;
    }

    level = srs_get_log_level(_srs_config->get_log_level());

    return err;
}

srs_error_t SrsJsonLog::on_reload_log_file()
{
    srs_error_t err = srs_success;

    if (!_srs_config) {
        return err;
    }

    if (!log_to_file_tank) {
        return err;
    }

    if (fd > 0) {
        ::close(fd);
    }
    open_log_file();

    return err;
}

#define _srs_outout_context(node, kname, vname) \
    if (node) { \
        if (!node->k_.empty()) { \
            log->set(kname, SrsJsonAny::str(node->k_.c_str())); \
        } \
        log->set(vname, SrsJsonAny::str(node->v_.c_str())); \
    }

void SrsJsonLog::write_log(int& fd, char *str_log, int size, int level, SrsContextId context_id, const char* tag)
{
    SrsJsonObject* log = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, log);

    // Build time in JSON.
    #define MAX_LOG_TIME_LEN 32
    static char log_time[MAX_LOG_TIME_LEN];
    if (true) {
        timeval tv;
        if (gettimeofday(&tv, NULL) == -1) {
            return;
        }

        struct tm* tm;
        if (utc) {
            if ((tm = gmtime(&tv.tv_sec)) == NULL) {
                return;
            }
        } else {
            if ((tm = localtime(&tv.tv_sec)) == NULL) {
                return;
            }
        }

        int written = snprintf(log_time, MAX_LOG_TIME_LEN, "%d-%02d-%02d %02d:%02d:%02d.%03d",
            1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(tv.tv_usec / 1000));
        if (written >= MAX_LOG_TIME_LEN) {
            return;
        }
    }
    log->set("d", SrsJsonAny::str(log_time));

    // Build level in JSON.
    static const char* levels[] = {
        NULL, "Verbose", // SrsLogLevelVerbose = 0x01,
        "Info", // SrsLogLevelInfo = 0x02,
        NULL, "Trace", // SrsLogLevelTrace = 0x04,
        NULL, NULL, NULL, "Warn", // SrsLogLevelWarn = 0x08,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, "Error", // SrsLogLevelError = 0x10,
    };
    if (level != SrsLogLevelTrace) {
        log->set("l", SrsJsonAny::str(levels[level]));
    }

    // Build other fields in JSON.
    if (tag) {
        log->set("t", SrsJsonAny::str(tag));
    }
    log->set("p", SrsJsonAny::integer(::getpid()));
    log->set("s", SrsJsonAny::str(SrsModuleName));

    // Context id tree.
    SrsContextId* id0 = &context_id, *id1 = NULL, *id2 = NULL, *id3 = NULL, *id4 = NULL;
    if (context_id.parent_) {
        id1 = id0; id0 = context_id.parent_;
        if (context_id.parent_->parent_) {
            id2 = id1; id1 = id0; id0 = context_id.parent_->parent_;
            if (context_id.parent_->parent_->parent_) {
                id3 = id2; id2 = id1; id1 = id0; id0 = context_id.parent_->parent_->parent_;
                if (context_id.parent_->parent_->parent_->parent_) {
                    id4 = id3; id3 = id2; id2 = id1; id1 = id0; id0 = context_id.parent_->parent_->parent_->parent_;
                }
            }
        }
    }

    _srs_outout_context(id0, "n0", "i0");
    _srs_outout_context(id1, "n1", "i1");
    _srs_outout_context(id2, "n2", "i2");
    _srs_outout_context(id3, "n3", "i3");
    _srs_outout_context(id4, "n4", "i4");

    // Binding context id.
    if (context_id.bind_) {
        if (!context_id.bind_->k_.empty()) {
            log->set("bn0", SrsJsonAny::str(context_id.bind_->k_.c_str()));
        }
        log->set("bi0", SrsJsonAny::str(context_id.bind_->v_.c_str()));
    }

    // Build log message in JSON.
    size = srs_min(LOG_MAX_SIZE - 1, size);
    str_log[size++] = 0;
    std::string s = srs_string_replace(std::string(str_log, size), "\n", "\\n");
    log->set("m", SrsJsonAny::str(s.c_str()));

    // Discovery error code in warning or error message.
    //      1. Log as "xxx, ret=1007"
    //      2. Log as "xxx, ret=1007, yyy"
    //      3. Log as "xxx, ret=1007 zzz"
    // Or error summary or description as:
    //      1. Log as "xxx: code=1007"
    //      2. Log as "xxx: code=1007, yyy"
    //      3. Log as "xxx: code=1007, zzz"
    // As result, the err is 1007.
    int err = 0;
    if (level == SrsLogLevelWarn || level == SrsLogLevelError) {
        size_t pos = s.find(" ret="); int nn_flag = 5;
        if (pos == std::string::npos) {
            pos = s.find(" code="); nn_flag = 6;
        }
        if (pos != std::string::npos) {
            s = s.substr(pos + nn_flag);
            if ((pos = s.find(",")) == std::string::npos) {
                pos = s.find(" ");
            }
            if (pos != std::string::npos) {
                s = s.substr(0, pos);
            }
            if (!s.empty()) {
                err = ::atoi(s.c_str());
            }
        }
    }
    if (err) {
        log->set("e", SrsJsonAny::integer(err));
    }

    std::string json_str = log->dumps();
    json_str += LOG_TAIL;

    // if not to file, to console and return.
    if (!log_to_file_tank) {
        // if is error msg, then print color msg.
        // \033[31m : red text code in shell
        // \033[32m : green text code in shell
        // \033[33m : yellow text code in shell
        // \033[0m : normal text code
        if (level <= SrsLogLevelTrace) {
            printf("%.*s", (int)json_str.length(), json_str.data());
        } else if (level == SrsLogLevelWarn) {
            printf("\033[33m%.*s\033[0m", (int)json_str.length(), json_str.data());
        } else{
            printf("\033[31m%.*s\033[0m", (int)json_str.length(), json_str.data());
        }
        fflush(stdout);

        return;
    }

    // open log file. if specified
    if (fd < 0) {
        open_log_file();
    }

    // write log to file.
    if (fd > 0) {
        ::write(fd, json_str.data(), (int)json_str.length());
    }
}

void SrsJsonLog::open_log_file()
{
    if (!_srs_config) {
        return;
    }

    std::string filename = _srs_config->get_log_file();

    if (filename.empty()) {
        return;
    }

    fd = ::open(filename.c_str(),
        O_RDWR | O_CREAT | O_APPEND,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH
    );
}

SrsLogWriter::SrsLogWriter(string category)
{
    fd = -1;
    enabled = false;
    category_ = category;
    log_to_file_tank = false;
}

SrsLogWriter::~SrsLogWriter()
{
    if (fd > 0) {
        ::close(fd);
        fd = -1;
    }
}

srs_error_t SrsLogWriter::initialize()
{
    srs_error_t err = srs_success;

    enabled = _srs_config->get_rtc_sls_log_enabled(category_);
    string tank = _srs_config->get_rtc_sls_log_tank(category_);
    std::string filename = _srs_config->get_rtc_sls_log_file(category_);
    log_to_file_tank = tank == "file";
    srs_trace("RTC: Log writer enabled=%u, category=%s, tank=%u/%s, file=%s", enabled, category_.c_str(),
        log_to_file_tank, tank.c_str(), filename.c_str());

    return err;
}

void SrsLogWriter::write_log(const char* str_log, int size)
{
    if (!enabled) {
        return;
    }

    // if not to file, to console and return.
    if (!log_to_file_tank) {
        if (size > 0) {
            srs_trace("RTC SLS log: %.*s", size - 1, str_log);
        }
        return;
    }

    // open log file. if specified
    if (fd < 0) {
        open_log_file();
    }

    // write log to file.
    if (fd > 0) {
        ::write(fd, str_log, size);
    }
}

void SrsLogWriter::reopen()
{
    if (fd > 0) {
        ::close(fd);
    }

    if (!log_to_file_tank) {
        return;
    }

    open_log_file();
}

void SrsLogWriter::open_log_file()
{
    std::string filename = _srs_config->get_rtc_sls_log_file(category_);
    if (filename.empty()) {
        return;
    }

    fd = ::open(filename.c_str(),
        O_RDWR | O_CREAT | O_APPEND,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH
    );
}

#include <srs_app_rtc_janus.hpp>

SrsRtcICEMessage::SrsRtcICEMessage(SrsRtcCallTraceId* id, SrsRtcConnection* c)
{
    appid_     = id->appid;
    sessionid_ = id->session;
    channel_   = id->channel;
    userid_    = id->user;
    callid_    = id->call;
    sfu_ = srs_get_public_internet_address(true);

    command_ = "iceDone";
    result_ = "success";

    local_candidate_ = srs_get_public_internet_address(true);

    // TODO: FIXME: we only use first peer addr, actually we need current active peer addr
    vector<SrsUdpMuxSocket*> addrs= c->peer_addresses();
    if (addrs.size() > 0) {
        SrsUdpMuxSocket* addr = addrs.at(0);

        remote_candidate_ = addr->get_peer_ip();
    }

    event_ = new SrsRtcCallstackEvent("Media", "iceDone");

    SrsContextId cid = c->context_id();
    event_->cid_  = cid.k_ + string("-") + cid.v_;

    event_->appid_   = id->appid;
    event_->channel_ = id->channel;
    event_->user_    = id->user;
    event_->session_ = id->session;
    event_->call_    = id->call;
}

SrsRtcICEMessage::~SrsRtcICEMessage()
{
    srs_freep(event_);
}

void SrsRtcICEMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;

    _sls_callstack->write(event_, marshal());
}

std::string SrsRtcICEMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("result",      SrsJsonAny::str(result_.c_str()));
    obj->set("localCandidate", SrsJsonAny::str(local_candidate_.c_str()));
    obj->set("remoteCandidate", SrsJsonAny::str(remote_candidate_.c_str()));

    return obj->dumps();
}

SrsRtcDtlsMessage::SrsRtcDtlsMessage(SrsRtcCallTraceId* id, SrsRtcConnection* c)
{
    appid_     = id->appid;
    sessionid_ = id->session;
    channel_   = id->channel;
    userid_    = id->user;
    callid_    = id->call;
    sfu_ = srs_get_public_internet_address(true);

    command_ = "DTLS";
    result_ = "success";

    event_ = new SrsRtcCallstackEvent("Media", "dtlsDone");

    SrsContextId cid = c->context_id();
    event_->cid_  = cid.k_ + string("-") + cid.v_;

    event_->appid_   = id->appid;
    event_->channel_ = id->channel;
    event_->user_    = id->user;
    event_->session_ = id->session;
    event_->call_    = id->call;
}
SrsRtcDtlsMessage::~SrsRtcDtlsMessage()
{
    srs_freep(event_);
}

void SrsRtcDtlsMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;

    _sls_callstack->write(event_, marshal());
}

std::string SrsRtcDtlsMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("result",      SrsJsonAny::str(result_.c_str()));

    return obj->dumps();
}


SrsRtcSubstreamRelation::SrsRtcSubstreamRelation()
{
    ssrc_source_ = 0;
    ssrc_ = 0;
    temporal_layer_ = 0;
}

SrsRtcSubRelationMessage::SrsRtcSubRelationMessage(
    SrsRtcCallTraceId* id, SrsRtcConnection* c, const std::vector<SrsTrackConfig>& cfgs,
    const std::map<uint32_t, SrsRtcAudioSendTrack*>& ats, const std::map<uint32_t, SrsRtcVideoSendTrack*>& vts
) {
    std::vector<SrsRtcSubstreamRelation> relations;
    for (int i = 0; i < (int)cfgs.size(); ++i) {
        const SrsTrackConfig& cfg = cfgs.at(i);
        if (cfg.type_ == "audio") {
            std::map<uint32_t, SrsRtcAudioSendTrack*>::const_iterator it;
            for (it = ats.cbegin(); it != ats.cend(); ++it) {
                SrsRtcAudioSendTrack* track = it->second;

                bool should_active_track = (track->get_track_id() == cfg.label_);
                if (!should_active_track) {
                    continue;
                }

                SrsRtcSubstreamRelation r;
                r.type_ = cfg.type_;
                r.trackid_ = cfg.label_;
                r.ssrc_source_ = it->first;
                r.ssrc_ = track->get_ssrc();
                r.temporal_layer_ = cfg.temporal_layers_;
                r.status_ = "enable";

                relations.push_back(r);
            }
        }

        if (cfg.type_ == "video") {
            std::map<uint32_t, SrsRtcVideoSendTrack*>::const_iterator it;
            for (it = vts.cbegin(); it != vts.cend(); ++it) {
                SrsRtcVideoSendTrack* track = it->second;

                bool should_active_track = (track->get_track_id() == cfg.label_);
                if (!should_active_track) {
                    continue;
                }

                SrsRtcSubstreamRelation r;
                r.type_ = cfg.type_;
                r.trackid_ = cfg.label_;
                r.ssrc_source_ = it->first;
                r.ssrc_ = track->get_ssrc();
                r.temporal_layer_ = cfg.temporal_layers_;
                r.status_ = "enable";

                relations.push_back(r);
            }
        }
    }

    appid_     = id->appid;
    sessionid_ = id->session;
    channel_   = id->channel;
    userid_    = id->user;
    callid_    = id->call;
    sfu_ = srs_get_public_internet_address(true);

    command_ = "SubstreamRelation";
    result_ = "relations";
    sub_streams_ = relations;

    event_ = new SrsRtcCallstackEvent("Media", "SubstreamRelation");

    SrsContextId cid = c->context_id();
    event_->cid_  = cid.k_ + string("-") + cid.v_;

    event_->appid_   = id->appid;
    event_->channel_ = id->channel;
    event_->user_    = id->user;
    event_->session_ = id->session;
    event_->call_    = id->call;
}

SrsRtcSubRelationMessage::~SrsRtcSubRelationMessage()
{
    srs_freep(event_);
}

void SrsRtcSubRelationMessage::write_callstack(std::string status, int ecode)
{
    event_->status_ = status;
    event_->error_code_ = ecode;

    _sls_callstack->write(event_, marshal());
}

std::string SrsRtcSubRelationMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("result",      SrsJsonAny::str(result_.c_str()));
    
    SrsJsonArray* rs = SrsJsonAny::array();
    obj->set("relations", rs);
    
    for (size_t i = 0; i < sub_streams_.size(); ++i) {
        SrsRtcSubstreamRelation sr = sub_streams_.at(i);

        SrsJsonObject* r = SrsJsonAny::object();
        r->set("type",        SrsJsonAny::str(sr.type_.c_str()));
        r->set("trackID",     SrsJsonAny::str(sr.trackid_.c_str()));
        r->set("ssrcSource",  SrsJsonAny::integer(sr.ssrc_source_));
        r->set("ssrc",        SrsJsonAny::integer(sr.ssrc_));
        r->set("temporalLayer", SrsJsonAny::integer(sr.temporal_layer_));
        r->set("status", SrsJsonAny::str(sr.status_.c_str()));

        rs->append(r);
    }

    return obj->dumps();
}

SrsRtcMediaUpMessage::SrsRtcMediaUpMessage(SrsRtcCallTraceId* id, SrsRtcConnection* c)
{
    appid_     = id->appid;
    sessionid_ = id->session;
    channel_   = id->channel;
    userid_    = id->user;
    callid_    = id->call;
    sfu_ = srs_get_public_internet_address(true);

    command_ = "MediaNotify";
    result_ = "MediaUp";

    event_ = new SrsRtcCallstackEvent("Media", "MediaUp");

    SrsContextId cid = c->context_id();
    event_->cid_  = cid.k_ + string("-") + cid.v_;

    event_->appid_   = id->appid;
    event_->channel_ = id->channel;
    event_->user_    = id->user;
    event_->session_ = id->session;
    event_->call_    = id->call;
    event_->status_ = "notify";
}

SrsRtcMediaUpMessage::~SrsRtcMediaUpMessage()
{
    srs_freep(event_);
}

void SrsRtcMediaUpMessage::write_callstack(std::string media_type)
{
    media_type_  = media_type;
    _sls_callstack->write(event_, marshal());
}

std::string SrsRtcMediaUpMessage::marshal()
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("callID",      SrsJsonAny::str(callid_.c_str()));
    obj->set("appID",       SrsJsonAny::str(appid_.c_str()));
    obj->set("sessionID",   SrsJsonAny::str(sessionid_.c_str()));
    obj->set("channelID",   SrsJsonAny::str(channel_.c_str()));
    obj->set("userID",      SrsJsonAny::str(userid_.c_str()));
    obj->set("sfu",         SrsJsonAny::str(sfu_.c_str()));
    obj->set("command",     SrsJsonAny::str(command_.c_str()));
    obj->set("result",      SrsJsonAny::str(result_.c_str()));
    obj->set("mediaType",   SrsJsonAny::str(media_type_.c_str()));

    return obj->dumps();
}

SrsRtcCallstackEvent::SrsRtcCallstackEvent(std::string stage, std::string action)
{
    stage_ = stage;
    action_ = action;
    error_code_ = 0;
}

SrsLogWriterCallstack::SrsLogWriterCallstack() : SrsLogWriter("callstack")
{
}

SrsLogWriterCallstack::~SrsLogWriterCallstack()
{
}

struct SrsJanusCallstack
{
    // time: write log time
    std::string time;
    // source module
    std::string module;
    // peer_module: the module interactive with tfsfu
    std::string peer;
    // focus: current focus module
    std::string focus;
    // source: source;
    std::string source;
    // stage: Create/Media/Destroy
    std::string stage;
    // status: enter/leave/flying/notify
    std::string status;
    // createJanusSession/attachJanusHandle/.....
    std::string action;
    // message: detail message
    std::string message;
    // code: the error code for this log.
    int error_code;
    // cid: context_id.
    std::string cid;
    // log: the file name for this log.
    std::string log;
    // appid: app id.
    std::string appid;
    // channel: channel id.
    std::string channel;
    // user: user id.
    std::string user;
    // session: session id.
    std::string session;
    // call: call id.
    std::string call;
    // tid: transaction id.
    std::string tid;

    void marshal(SrsJsonObject* obj) {
        obj->set("time",    SrsJsonAny::str(time.c_str()));
        obj->set("module",  SrsJsonAny::str(module.c_str()));
        obj->set("focus",   SrsJsonAny::str(peer.c_str()));
        obj->set("source",  SrsJsonAny::str(source.c_str()));
        obj->set("stage",   SrsJsonAny::str(stage.c_str()));
        obj->set("status",  SrsJsonAny::str(status.c_str()));
        obj->set("action",  SrsJsonAny::str(action.c_str()));
        obj->set("message",  SrsJsonAny::str(message.c_str()));
        obj->set("code",    SrsJsonAny::integer(error_code));
        obj->set("pid",     SrsJsonAny::integer(getpid()));
        obj->set("cid",     SrsJsonAny::str(cid.c_str()));
        obj->set("log",     SrsJsonAny::str(log.c_str()));
        obj->set("appid",   SrsJsonAny::str(appid.c_str()));
        obj->set("channel", SrsJsonAny::str(channel.c_str()));
        obj->set("user",    SrsJsonAny::str(user.c_str()));
        obj->set("session", SrsJsonAny::str(session.c_str()));
        obj->set("call",    SrsJsonAny::str(call.c_str()));
        obj->set("tid",     SrsJsonAny::str(tid.c_str()));
    }
};

string srs_current_time(bool utc)
{
    #define MAX_LOG_TIME_LEN 32
    static char log_time[MAX_LOG_TIME_LEN];
    if (true) {
        timeval tv;
        if (gettimeofday(&tv, NULL) == -1) {
            return "";
        }

        struct tm* tm;
        if (utc) {
            if ((tm = gmtime(&tv.tv_sec)) == NULL) {
                return "";
            }
        } else {
            if ((tm = localtime(&tv.tv_sec)) == NULL) {
                return "";
            }
        }

        int written = snprintf(log_time, MAX_LOG_TIME_LEN, "%d-%02d-%02d %02d:%02d:%02d.%03d",
            1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(tv.tv_usec / 1000));
        if (written >= MAX_LOG_TIME_LEN) {
            return "";
        }
    }

    return string(log_time);
}

void SrsLogWriterCallstack::write(SrsRtcCallstackEvent* e, std::string m)
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    if (true) {
        SrsJanusCallstack callstack;

        callstack.time = srs_current_time(false);
        callstack.source = srs_get_public_internet_address(true);
        callstack.peer = SrsModuleSignaling;
        callstack.module = SrsModuleName;
        callstack.focus = SrsModuleName;

        callstack.stage = e->stage_;
        callstack.status = e->status_;
        callstack.action = e->action_;
        callstack.error_code = e->error_code_;
        callstack.cid = e->cid_;
        callstack.appid = e->appid_;
        callstack.channel = e->channel_;
        callstack.user = e->user_;
        callstack.session = e->session_;
        callstack.tid = e->tid_;
        callstack.call = e->call_;
        
        callstack.message = m;

        callstack.marshal(obj);
    }

    string data = obj->dumps();
    data += LOG_TAIL;
    write_log(data.data(), data.length());
}

SrsLogWriterRelation::SrsLogWriterRelation() : SrsLogWriter("relation")
{
}

SrsLogWriterRelation::~SrsLogWriterRelation()
{
}

struct SrsJanusRelation
{
    // time: write log time
    std::string time;
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

    // subscriber_session_id: subscriber session id.
    std::string subscriber_session_id;
    // subscriber_call_id: subscriber call id.
    std::string subscriber_call_id;
    // subscriber_user_id: subscriber user id.
    std::string subscriber_user_id;
    // subscriber_ssrc: subscriber ssrc.
    uint32_t subscriber_ssrc;

    void marshal(SrsJsonObject* obj) {
        obj->set("time",    SrsJsonAny::str(time.c_str()));
        obj->set("appid",   SrsJsonAny::str(appid.c_str()));
        obj->set("channelid", SrsJsonAny::str(channel.c_str()));
        obj->set("trackID",  SrsJsonAny::str(track_id.c_str()));

        obj->set("publisher_session_id", SrsJsonAny::str(publisher_session_id.c_str()));
        obj->set("publisher_call_id",    SrsJsonAny::str(publisher_call_id.c_str()));
        obj->set("publisher_user_id",    SrsJsonAny::str(publisher_user_id.c_str()));
        obj->set("publisher_ssrc",       SrsJsonAny::integer(publisher_ssrc));

        obj->set("subscriber_session_id", SrsJsonAny::str(subscriber_session_id.c_str()));
        obj->set("subscriber_call_id",    SrsJsonAny::str(subscriber_call_id.c_str()));
        obj->set("subscriber_user_id",    SrsJsonAny::str(subscriber_user_id.c_str()));
        obj->set("subscriber_ssrc",       SrsJsonAny::integer(subscriber_ssrc));
    }
};

void SrsLogWriterRelation::write(SrsJanusRelationPublishInfo* pub_info, SrsJanusRelationSubscribeInfo* sub_info)
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    if (true) {
        SrsJanusRelation relation;

        relation.time = srs_current_time(false);

        relation.appid = pub_info->appid;
        relation.channel = pub_info->channel;
        relation.track_id = pub_info->track_id;

        relation.publisher_session_id = pub_info->publisher_session_id;
        relation.publisher_call_id = pub_info->publisher_call_id;
        relation.publisher_user_id = pub_info->publisher_user_id;
        relation.publisher_ssrc = pub_info->publisher_ssrc;

        relation.subscriber_session_id = sub_info->subscriber_session_id;
        relation.subscriber_call_id = sub_info->subscriber_call_id;
        relation.subscriber_user_id = sub_info->subscriber_user_id;
        relation.subscriber_ssrc = sub_info->subscriber_ssrc;

        relation.marshal(obj);
    }

    string data = obj->dumps();
    data += LOG_TAIL;
    write_log(data.data(), data.length());
}

SrsRtcTrackStatisticLog::SrsRtcTrackStatisticLog()
{
    ssrc = 0;

    replays = 0;
    replay_bytes = 0;
    paddings = 0;
    padding_bytes = 0;
    packets = 0;
    bytes = 0;
}

SrsRtcTrackStatisticLog::~SrsRtcTrackStatisticLog()
{
}

SrsRtcTrackStatisticLogRecv::SrsRtcTrackStatisticLogRecv()
{
    nack_sent = 0;
    lost = 0;
    lost_rate = 0;
    twcc_loss_rate = 0;
    twcc_max_loss_rate = 0;
    valid_packet_rate = 0;
}

SrsRtcTrackStatisticLogSend::SrsRtcTrackStatisticLogSend()
{
    nack_recv = 0;
    lost_remote = 0;
    lost_rate_remote = 0;
    valid_packet_rate = 0;
}

struct SrsJanusTrackDataStatistic
{
    // time: write log time
    std::string time;
    // appid: app id.
    std::string appid;
    // channelID: channel id.
    std::string channel;
    // userID: user id.
    std::string user;
    // sessionID: session id.
    std::string session;
    // callID: call id.
    std::string call;

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
    uint32_t in_replays;
    // inReplayBytes: in replay bytes.
    uint32_t in_replay_bytes;
    // inPaddings: in padding packets.
    uint32_t in_paddings;
    // inPaddingBytes: in padding bytes.
    uint32_t in_padding_bytes;
    // inPackets: in packets.
    uint32_t in_packets;
    // inBytes: in bytes.
    uint32_t in_bytes;
    // nackSent: the number of send nack.
    uint32_t nack_sent;
    // lost: lost packets.
    uint32_t lost;
    // lostRate: lost rate;
    uint32_t lost_rate;
    // twccLossRate: twcc loss rate;
    uint32_t twcc_loss_rate;
    // twccMaxLossRate: twcc max loss Rate;
    uint32_t twcc_max_loss_rate;

    // outReplays: out replay packets.
    uint32_t out_replays;
    // outReplayBytes: out replay bytes.
    uint32_t out_replay_bytes;
    // outPaddings: out padding packets.
    uint32_t out_paddings;
    // outPaddingBytes: out padding bytes.
    uint32_t out_padding_bytes;
    // outPackets: out packets.
    uint32_t out_packets;
    // outBytes: out bytes.
    uint32_t out_bytes;
    // nackRecv: the number of send nack.
    uint32_t nack_recv;
    // lostRemote: out lost packets.
    uint32_t lost_remote;
    // lostRateRemote: out lost rate;
    uint32_t lost_rate_remote;

    // validPacketRate: valid packet rate.
    double valid_packet_rate;

    SrsJanusTrackDataStatistic()
    {
        ssrc = 0;
        in_replays = 0;
        in_replay_bytes = 0;
        in_paddings = 0;
        in_padding_bytes = 0;
        in_packets = 0;
        in_bytes = 0;
        nack_sent = 0;
        lost = 0;
        lost_rate = 0;
        twcc_loss_rate = 0;
        twcc_max_loss_rate = 0;

        out_replays = 0;
        out_replay_bytes = 0;
        out_paddings = 0;
        out_padding_bytes = 0;
        out_packets = 0;
        out_bytes = 0;
        nack_recv = 0;
        lost_remote = 0;
        lost_rate_remote = 0;

        valid_packet_rate = 0;
    };

    void marshal(SrsJsonObject* obj) {
        obj->set("time",        SrsJsonAny::str(time.c_str()));
        obj->set("appid",       SrsJsonAny::str(appid.c_str()));
        obj->set("channelID",   SrsJsonAny::str(channel.c_str()));
        obj->set("userID",      SrsJsonAny::str(user.c_str()));
        obj->set("sessionID",   SrsJsonAny::str(session.c_str()));
        obj->set("callID",      SrsJsonAny::str(call.c_str()));

        obj->set("type",        SrsJsonAny::str(type.c_str()));
        obj->set("trackID",     SrsJsonAny::str(track_id.c_str()));
        obj->set("direction",   SrsJsonAny::str(direction.c_str()));
        obj->set("turn",        SrsJsonAny::str(turn.c_str()));
        obj->set("ssrc",        SrsJsonAny::integer(ssrc));

        obj->set("inReplays",      SrsJsonAny::integer(in_replays));
        obj->set("inReplayBytes",  SrsJsonAny::integer(in_replay_bytes));
        obj->set("inPaddings",     SrsJsonAny::integer(in_paddings));
        obj->set("inPaddingBytes", SrsJsonAny::integer(in_padding_bytes));
        obj->set("inPackets",      SrsJsonAny::integer(in_packets));
        obj->set("inBytes",        SrsJsonAny::integer(in_bytes));
        obj->set("nackSent",       SrsJsonAny::integer(nack_sent));
        obj->set("lost",           SrsJsonAny::integer(lost));
        obj->set("lostRate",       SrsJsonAny::integer(lost_rate));
        obj->set("twccLossRate",   SrsJsonAny::integer(twcc_loss_rate));
        obj->set("twccMaxLossRate",SrsJsonAny::integer(twcc_max_loss_rate));

        obj->set("outReplays",      SrsJsonAny::integer(out_replays));
        obj->set("outReplayBytes",  SrsJsonAny::integer(out_replay_bytes));
        obj->set("outPaddings",     SrsJsonAny::integer(out_paddings));
        obj->set("outPaddingBytes", SrsJsonAny::integer(out_padding_bytes));
        obj->set("outPackets",      SrsJsonAny::integer(out_packets));
        obj->set("outBytes",        SrsJsonAny::integer(out_bytes));
        obj->set("nackRecv",        SrsJsonAny::integer(nack_recv));
        obj->set("lostRemote",      SrsJsonAny::integer(lost_remote));
        obj->set("lostRateRemote",  SrsJsonAny::integer(lost_rate_remote));

        obj->set("validPacketRate", SrsJsonAny::number(valid_packet_rate));
    }
};

SrsLogWriteDataStatistic::SrsLogWriteDataStatistic() : SrsLogWriter("data_statistic")
{
}

SrsLogWriteDataStatistic::~SrsLogWriteDataStatistic()
{
}

void SrsLogWriteDataStatistic::write(SrsRtcCallTraceId* id, SrsRtcTrackStatisticLog* log)
{
    SrsRtcTrackStatisticLogRecv* r = dynamic_cast<SrsRtcTrackStatisticLogRecv*>(log);
    SrsRtcTrackStatisticLogSend* s = dynamic_cast<SrsRtcTrackStatisticLogSend*>(log);
    srs_assert (r || s);

    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    if (true) {
        SrsJanusTrackDataStatistic stat;

        stat.time = srs_current_time(false);

        stat.appid    = id->appid;
        stat.channel  = id->channel;
        stat.user     = id->user;
        stat.session  = id->session;
        stat.call     = id->call;

        if (r) {
            stat.type = r->type;
            stat.track_id = r->track_id;
            stat.direction = r->direction;
            stat.turn = r->turn;

            stat.ssrc = r->ssrc;
            stat.in_replays = r->replays;
            stat.in_replay_bytes = r->replay_bytes;
            stat.in_paddings = r->paddings;
            stat.in_padding_bytes = r->padding_bytes;
            stat.in_packets = r->packets;
            stat.in_bytes = r->bytes;
            stat.nack_sent = r->nack_sent;
            stat.lost = r->lost;
            stat.lost_rate = r->lost_rate;
            stat.valid_packet_rate = r->valid_packet_rate;
            stat.twcc_loss_rate = r->twcc_loss_rate;
            stat.twcc_max_loss_rate = r->twcc_max_loss_rate;

        } else if (s) {
            stat.type = s->type;
            stat.track_id = s->track_id;
            stat.direction = s->direction;
            stat.turn = s->turn;

            stat.ssrc = s->ssrc;
            stat.out_replays = s->replays;
            stat.out_replay_bytes = s->replay_bytes;
            stat.out_paddings = s->paddings;
            stat.out_padding_bytes = s->padding_bytes;
            stat.out_packets = s->packets;
            stat.out_bytes = s->bytes;
            stat.nack_recv = s->nack_recv;
            stat.lost_remote = s->lost_remote;
            stat.lost_rate_remote = s->lost_rate_remote;
            stat.valid_packet_rate = s->valid_packet_rate;

        }

        stat.marshal(obj);
    }

    string data = obj->dumps();
    data += LOG_TAIL;
    write_log(data.data(), data.length());
}

SrsRtcConnectionDownlinkBweStatistic::SrsRtcConnectionDownlinkBweStatistic()
{
    reset();
}

SrsRtcConnectionDownlinkBweStatistic::~SrsRtcConnectionDownlinkBweStatistic()
{
}

void SrsRtcConnectionDownlinkBweStatistic::reset()
{
    count = 0;
    max_rtt = 0;
    min_rtt = 0;
    avg_rtt = 0;
    max_bitrate = 0;
    min_bitrate = 0;
    avg_bitrate = 0;

    max_loss_rate = 0.0;
    min_loss_rate = 0.0;
    avg_loss_rate = 0.0;
}

void SrsRtcConnectionDownlinkBweStatistic::update(int bitrate, int rtt, float loss_rate)
{
    count++;
	if(count == 1) {
		max_bitrate = bitrate;
		min_bitrate = bitrate;
		avg_bitrate = bitrate;

		max_rtt = rtt;
		min_rtt = rtt;
		avg_rtt = rtt;

		max_loss_rate = loss_rate;
		min_loss_rate = loss_rate;
		avg_loss_rate = loss_rate;
	} else {
		avg_bitrate = ((avg_bitrate * (count - 1)) + bitrate) / count;
		if(bitrate > max_bitrate) {
			max_bitrate = bitrate;
		}
		if(bitrate < min_bitrate) {
			min_bitrate = bitrate;
		}

		avg_rtt = ((avg_rtt * (count - 1) + rtt)) / count;
		if(rtt > max_rtt) {
			max_rtt = rtt;
		}
		if(rtt < min_rtt) {
			min_rtt = rtt;
		}

		avg_loss_rate = ((avg_loss_rate * (count - 1)) + loss_rate) / count;
		if(loss_rate > max_loss_rate) {
			max_loss_rate = loss_rate;
		}
		if(loss_rate < min_loss_rate) {
			min_loss_rate = loss_rate;
		}
	}
}

SrsRtcConnectionDownlinkBweEvent::SrsRtcConnectionDownlinkBweEvent()
{
    reset();
}

SrsRtcConnectionDownlinkBweEvent::~SrsRtcConnectionDownlinkBweEvent()
{
}

void SrsRtcConnectionDownlinkBweEvent::reset()
{
    total_cnt = 0;
	congestion_cnt = 0;
	qdelay_overuse_cnt = 0;
	weakness_cnt = 0;
	loss_zero_percent_cnt = 0;
	loss_less_5_percent_cnt = 0;
	loss_less_10_percent_cnt = 0;
	loss_less_20_percent_cnt = 0;
	loss_lenss_30_percent_cnt = 0;
	loss_higher_30_percent_cnt = 0;
	bitrate_less_300k = 0;
	bitrate_less_500k = 0;
	bitrate_less_800k = 0;
	bitrate_less_1200k = 0;
	bitrate_higher_1200k = 0;
}

void SrsRtcConnectionDownlinkBweEvent::update_bwe(int bitrate, int rtt, float loss_rate)
{
	total_cnt++;

    // TODO: FIXME: add congestion and qdelay_overuse count.
	if(bitrate <= 300 * 1000) {
		bitrate_less_300k++;
	} else if(bitrate <= 500 * 1000) {
		bitrate_less_500k++;
	} else if(bitrate <= 800 * 1000) {
		bitrate_less_800k++;
	} else if(bitrate <= 1200 * 1000) {
		bitrate_less_1200k++;
	} else {
		bitrate_higher_1200k++;
	}

	if(loss_rate == 0.0f) {
		loss_zero_percent_cnt++;
	} else if(loss_rate <= 0.05f) {
		loss_less_5_percent_cnt++;
	} else if(loss_rate <= 0.10f) {
		loss_less_10_percent_cnt++;
	} else if(loss_rate <= 0.20f) {
		loss_less_20_percent_cnt++;
	} else if(loss_rate <= 0.30f) {
		loss_lenss_30_percent_cnt++;
	} else {
		loss_higher_30_percent_cnt++;
	}
}

void SrsRtcConnectionDownlinkBweEvent::update_weakness()
{
    weakness_cnt++;
}

SrsLogWriteDownlinkBwe::SrsLogWriteDownlinkBwe() : SrsLogWriter("downlink_bwe")
{
}

SrsLogWriteDownlinkBwe::~SrsLogWriteDownlinkBwe()
{
}

struct SrsJanusDownlinkBwe
{
    // time: write log time
    std::string time;
    // appid: app id.
    std::string appid;
    // channelID: channel id.
    std::string channel;
    // userID: user id.
    std::string user;
    // sessionID: session id.
    std::string session;
    // callID: call id.
    std::string call;

    // maxRTT: max rtt.
    int max_rtt;
    // minRTT: min rtt.
	int min_rtt;
    // avgRTT: average rtt.
	int avg_rtt;
    
    // maxBitrate: max bitrate.
    int max_bitrate;
    // minBitrate: min bitrate.
	int min_bitrate;
    // avgBitrate: average bitrate.
	int avg_bitrate;

    // maxLossRate: max loss rate.
	float max_loss_rate;
    // minLossRate: min loss rate.
	float min_loss_rate;
    // avgLossRate: average loss rate.
	float avg_loss_rate;

    // totalBWECount: The total count for bwe event in every interval.
	uint64_t total_cnt;
	// totalBWECongestion: The gcc result is congestion's result.
	uint64_t congestion_cnt;
	// totalBWEWeakness: Weakness. If our bitrate can't offer the T0 + FEC0 or T0.
	uint64_t weakness_cnt;
	// totalQueueDelayOverusing: Queue delay overuse count.
	uint64_t qdelay_overuse_cnt;

	// lossZero:  zero loss.
	uint64_t loss_zero_percent_cnt;
	// lossLess5p: (0, 5%]
	uint64_t loss_less_5_percent_cnt;
	// lossLess10p: (5%, 10%]
	uint64_t loss_less_10_percent_cnt;
	// lossLess20p: (10%, 20%]
	uint64_t loss_less_20_percent_cnt;
	// lossLess30p: (20%, 30%]
	uint64_t loss_lenss_30_percent_cnt;
	// lossHigher: higher
	uint64_t loss_higher_30_percent_cnt;

	// bitrateLess300k: (0, 300kb]
	uint64_t bitrate_less_300k;
	// bitrateLess500k: (300k, 500k]
	uint64_t bitrate_less_500k;
	// bitrateLess800k: (500k, 800k]
	uint64_t bitrate_less_800k;
	// bitrateLess1200k: (800k, 1200k]
	uint64_t bitrate_less_1200k;
	// bitrateHigher: higher
	uint64_t bitrate_higher_1200k;

    SrsJanusDownlinkBwe()
    {
        max_rtt = 0;
        min_rtt = 0;
        avg_rtt = 0;
        max_bitrate = 0;
        min_bitrate = 0;
        avg_bitrate = 0;

        max_loss_rate = 0.0;
        min_loss_rate = 0.0;
        avg_loss_rate = 0.0;

        total_cnt = 0;
        congestion_cnt = 0;
        weakness_cnt = 0;
        qdelay_overuse_cnt = 0;

        loss_zero_percent_cnt = 0;
        loss_less_5_percent_cnt = 0;
        loss_less_10_percent_cnt = 0;
        loss_less_20_percent_cnt = 0;
        loss_lenss_30_percent_cnt = 0;
        loss_higher_30_percent_cnt = 0;

        bitrate_less_300k = 0;
        bitrate_less_500k = 0;
        bitrate_less_800k = 0;
        bitrate_less_1200k = 0;
        bitrate_higher_1200k = 0;
    };

    void marshal(SrsJsonObject* obj) {
        obj->set("time",        SrsJsonAny::str(time.c_str()));
        obj->set("appid",       SrsJsonAny::str(appid.c_str()));
        obj->set("channelID",   SrsJsonAny::str(channel.c_str()));
        obj->set("userID",      SrsJsonAny::str(user.c_str()));
        obj->set("sessionID",   SrsJsonAny::str(session.c_str()));
        obj->set("callID",      SrsJsonAny::str(call.c_str()));

        obj->set("maxRTT", SrsJsonAny::integer(max_rtt));
        obj->set("minRTT", SrsJsonAny::integer(min_rtt));
        obj->set("avgRTT", SrsJsonAny::integer(avg_rtt));

        obj->set("maxBitrate", SrsJsonAny::integer(max_bitrate));
        obj->set("minBitrate", SrsJsonAny::integer(min_bitrate));
        obj->set("avgBitrate", SrsJsonAny::integer(avg_bitrate));

        obj->set("maxLossRate", SrsJsonAny::number(max_loss_rate));
        obj->set("minLossRate", SrsJsonAny::number(min_loss_rate));
        obj->set("avgLossRate", SrsJsonAny::number(avg_loss_rate));

        obj->set("totalBWECount", SrsJsonAny::integer(total_cnt));
        obj->set("totalBWECongestion", SrsJsonAny::integer(congestion_cnt));
        obj->set("totalBWEWeakness", SrsJsonAny::integer(weakness_cnt));
        obj->set("totalQueueDelayOverusing", SrsJsonAny::integer(qdelay_overuse_cnt));

        obj->set("lossZero", SrsJsonAny::integer(loss_zero_percent_cnt));
        obj->set("lossLess5p", SrsJsonAny::integer(loss_less_5_percent_cnt));
        obj->set("lossLess10p", SrsJsonAny::integer(loss_less_10_percent_cnt));
        obj->set("lossLess20p", SrsJsonAny::integer(loss_less_20_percent_cnt));
        obj->set("lossLess30p", SrsJsonAny::integer(loss_lenss_30_percent_cnt));
        obj->set("lossHigher", SrsJsonAny::integer(loss_higher_30_percent_cnt));

        obj->set("bitrateLess300k", SrsJsonAny::integer(bitrate_less_300k));
        obj->set("bitrateLess500k", SrsJsonAny::integer(bitrate_less_500k));
        obj->set("bitrateLess800k", SrsJsonAny::integer(bitrate_less_800k));
        obj->set("bitrateLess1200k", SrsJsonAny::integer(bitrate_less_1200k));
        obj->set("bitrateHigher", SrsJsonAny::integer(bitrate_higher_1200k));
    }
};

void SrsLogWriteDownlinkBwe::write(SrsRtcCallTraceId* id, SrsRtcConnectionDownlinkBweStatistic* s, SrsRtcConnectionDownlinkBweEvent* e)
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    if (true) {
        SrsJanusDownlinkBwe bwe;

        bwe.time = srs_current_time(false);

        bwe.appid    = id->appid;
        bwe.channel  = id->channel;
        bwe.user     = id->user;
        bwe.session  = id->session;
        bwe.call     = id->call;

        bwe.max_rtt = s->max_rtt;
        bwe.min_rtt = s->min_rtt;
        bwe.avg_rtt = s->avg_rtt;
        bwe.max_bitrate = s->max_bitrate;
        bwe.min_bitrate = s->min_bitrate;
        bwe.avg_bitrate = s->avg_bitrate;
        bwe.max_loss_rate = s->max_loss_rate;
        bwe.min_loss_rate = s->min_loss_rate;
        bwe.avg_loss_rate = s->avg_loss_rate;

        bwe.total_cnt = e->total_cnt;
        bwe.congestion_cnt = e->congestion_cnt;
        bwe.weakness_cnt = e->weakness_cnt;
        bwe.qdelay_overuse_cnt = e->qdelay_overuse_cnt;
        bwe.loss_zero_percent_cnt = e->loss_zero_percent_cnt;
        bwe.loss_less_5_percent_cnt = e->loss_less_5_percent_cnt;
        bwe.loss_less_10_percent_cnt = e->loss_less_10_percent_cnt;
        bwe.loss_less_20_percent_cnt = e->loss_less_20_percent_cnt;
        bwe.loss_lenss_30_percent_cnt = e->loss_lenss_30_percent_cnt;
        bwe.loss_higher_30_percent_cnt = e->loss_higher_30_percent_cnt;
        bwe.bitrate_less_300k = e->bitrate_less_300k;
        bwe.bitrate_less_500k = e->bitrate_less_500k;
        bwe.bitrate_less_800k = e->bitrate_less_800k;
        bwe.bitrate_less_1200k = e->bitrate_less_1200k;
        bwe.bitrate_higher_1200k = e->bitrate_higher_1200k;

        bwe.marshal(obj);
    }

    string data = obj->dumps();
    data += LOG_TAIL;
    write_log(data.data(), data.length());
}