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
    if (!enabled) {
        return;
    }

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

void SrsLogWriterCallstack::write(SrsJanusSession* s, SrsJanusUserConf* c, SrsJanusMessage* m)
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
        callstack.stage = "create";
        callstack.status = "enter";
        callstack.action = "createJanusSession";
        callstack.error_code = 0;
        callstack.cid = s->cid_.k_ + string("-") + s->cid_.v_;
        callstack.appid = s->appid_;
        callstack.channel = s->channel_;
        callstack.user = s->userid_;
        callstack.session = s->sessionid_;
        callstack.tid = m->transaction;

        if (true) {
            SrsJsonObject* message = SrsJsonAny::object();
            SrsAutoFree(SrsJsonObject, message);

            message->set("appID", SrsJsonAny::str(s->appid_.c_str()));
            message->set("sessionID", SrsJsonAny::str(s->sessionid_.c_str()));
            message->set("channelID", SrsJsonAny::str(s->channel_.c_str()));
            message->set("userID", SrsJsonAny::str(s->userid_.c_str()));
            message->set("command", SrsJsonAny::str("createJanusSession"));
            message->set("transaction", SrsJsonAny::str(m->transaction.c_str()));
            message->set("DownlinkStreamMerge", SrsJsonArray::boolean(c->stream_merge));
            message->set("1v1TccForwardEnable", SrsJsonArray::boolean(c->enable_forward_twcc));
            message->set("NeedSDPUnified", SrsJsonArray::boolean(c->need_unified_plan));
            message->set("WebSDK", SrsJsonArray::str(c->web_sdk.c_str()));
            message->set("EnableBWEStatusReport", SrsJsonArray::boolean(c->enable_bwe_status_report));
            message->set("NoExtraConfig", SrsJsonArray::boolean(c->no_extra_config_when_join));
            message->set("IsMPU", SrsJsonArray::boolean(c->is_mpu_client));
            message->set("sfu", SrsJsonArray::str(callstack.source.c_str()));
            message->set("signaling", SrsJsonArray::str(m->client_ip.c_str()));

            callstack.message = message->dumps();
        }

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

SrsLogWriteDataStatistic::SrsLogWriteDataStatistic() : SrsLogWriter("data_statistic")
{
}

SrsLogWriteDataStatistic::~SrsLogWriteDataStatistic()
{
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

void SrsLogWriteDataStatistic::write(SrsRtcParticipantID* p, SrsRtcTrackRecvDataStatistic* r, SrsRtcTrackSendDataStatistic* s)
{
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    if (true) {
        SrsJanusTrackDataStatistic data_statistic;

        data_statistic.time = srs_current_time(false);

        data_statistic.appid    = p->appid;
        data_statistic.channel  = p->channel;
        data_statistic.user     = p->user;
        data_statistic.session  = p->session;
        data_statistic.call     = p->call;

        if (r) {
            data_statistic.type = r->type;
            data_statistic.track_id = r->track_id;
            data_statistic.direction = r->direction;
            data_statistic.turn = r->turn;

            data_statistic.ssrc = r->ssrc;
            data_statistic.in_replays = r->replays;
            data_statistic.in_replay_bytes = r->replay_bytes;
            data_statistic.in_paddings = r->paddings;
            data_statistic.in_padding_bytes = r->padding_bytes;
            data_statistic.in_packets = r->packets;
            data_statistic.in_bytes = r->bytes;
            data_statistic.nack_sent = r->nack_sent;
            data_statistic.lost = r->lost;
            data_statistic.lost_rate = r->lost_rate;
            data_statistic.valid_packet_rate = r->valid_packet_rate;
            data_statistic.twcc_loss_rate = r->twcc_loss_rate;
            data_statistic.twcc_max_loss_rate = r->twcc_max_loss_rate;

        } else if (s) {
            data_statistic.type = s->type;
            data_statistic.track_id = s->track_id;
            data_statistic.direction = s->direction;
            data_statistic.turn = s->turn;

            data_statistic.ssrc = s->ssrc;
            data_statistic.out_replays = s->replays;
            data_statistic.out_replay_bytes = s->replay_bytes;
            data_statistic.out_paddings = s->paddings;
            data_statistic.out_padding_bytes = s->padding_bytes;
            data_statistic.out_packets = s->packets;
            data_statistic.out_bytes = s->bytes;
            data_statistic.nack_recv = s->nack_recv;
            data_statistic.lost_remote = s->lost_remote;
            data_statistic.lost_rate_remote = s->lost_rate_remote;
            data_statistic.valid_packet_rate = s->valid_packet_rate;

        }

        data_statistic.marshal(obj);
    }

    string data = obj->dumps();
    data += LOG_TAIL;
    write_log(data.data(), data.length());
}

