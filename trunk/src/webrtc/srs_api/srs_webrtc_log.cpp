
#include "srs_webrtc_log.hpp"

#include "srs_kernel_error.hpp"
#include "srs_kernel_log.hpp"


static SrsWebRTCLogSink *webrtc_log_sink = NULL;

SrsWebRTCLogSink::SrsWebRTCLogSink()
{
}

SrsWebRTCLogSink::~SrsWebRTCLogSink()
{
}

void SrsWebRTCLogSink::OnLogMessage(const std::string& message,
                            rtc::LoggingSeverity severity)
{
    switch (severity) {
    case rtc::LS_VERBOSE:
        srs_verbose("webrtc: %s", message.c_str());
        break;
    case rtc::LS_INFO:
        srs_trace("webrtc: %s", message.c_str());
        break;
    case rtc::LS_WARNING:
        srs_warn("webrtc: %s", message.c_str());
        break;
    case rtc::LS_ERROR:
        srs_error("webrtc: %s", message.c_str());
        break;
    case rtc::LS_NONE:
    default:    
        break;
    }
}

void SrsWebRTCLogSink::OnLogMessage(const std::string& message)
{
    srs_info("webrtc: %s", message.c_str());
}

srs_error_t register_webrtc_log()
{
#ifdef SRS_CXX14
    if(NULL == webrtc_log_sink) {
        webrtc_log_sink = new SrsWebRTCLogSink();
        //TODO: FIXME: set webrtc log level as srs log level
        rtc::LogMessage::AddLogToStream(webrtc_log_sink, rtc::LS_VERBOSE);
    }
#endif
    return srs_success;
}

srs_error_t unregister_webrtc_log()
{
#ifdef SRS_CXX14
    if(NULL != webrtc_log_sink) {
        rtc::LogMessage::RemoveLogToStream(webrtc_log_sink);
        delete webrtc_log_sink;
        webrtc_log_sink = NULL;
    }
#endif
    return srs_success;
}

