
#ifndef SRS_WEBRTC_LOG_HPP
#define SRS_WEBRTC_LOG_HPP

#include "srs_core.hpp"

#include "rtc_base/logging.h"


srs_error_t register_webrtc_log();
srs_error_t unregister_webrtc_log();

class SrsWebRTCLogSink : public rtc::LogSink
{
public:
    SrsWebRTCLogSink();
    virtual ~SrsWebRTCLogSink();

    virtual void OnLogMessage(const std::string& message,
                            rtc::LoggingSeverity severity) override;
    virtual void OnLogMessage(const std::string& message) override;
};

#endif

