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

#include <srs_app_config.hpp>
#include <srs_kernel_error.hpp>
#include <srs_app_utility.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_core_autofree.hpp>
#include <srs_protocol_json.hpp>

// the max size of a line of log.
#define LOG_MAX_SIZE 4096

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

    write_log(fd, log_data, size, SrsLogLevelVerbose, tag);
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

    write_log(fd, log_data, size, SrsLogLevelInfo, tag);
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

    write_log(fd, log_data, size, SrsLogLevelTrace, tag);
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

    write_log(fd, log_data, size, SrsLogLevelWarn, tag);
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

    write_log(fd, log_data, size, SrsLogLevelError, tag);
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

void SrsJsonLog::write_log(int& fd, char *str_log, int size, int level, const char* tag)
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
    log->set("c", SrsJsonAny::str(_srs_context->get_id().c_str()));

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

