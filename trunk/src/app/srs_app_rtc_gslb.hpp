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

#ifndef SRS_APP_GSLB_HPP
#define SRS_APP_GSLB_HPP

#include <srs_core.hpp>
#include <srs_app_hourglass.hpp>

#include <string>

class SrsHourGlass;
class ISrsHourGlass;

// The http heartbeat to GSLB to notice GSLB that the information of tfsfu.
class SrsGSLBHeartbeat : virtual public ISrsHourGlass
{
private:
    std::string url_;
    std::string api_key_;
    SrsHourGlass* timer;
public:
    SrsGSLBHeartbeat();
    virtual ~SrsGSLBHeartbeat();
public:
    srs_error_t initialize();
private:
    srs_error_t heartbeat();
private:
    std::string generate_api_signature(std::string timestamp);
// interface ISrsHourGlass
public:
    virtual srs_error_t notify(int type, srs_utime_t interval, srs_utime_t tick);
};

#endif // SRS_APP_GSLB_HPP