
#include "srs_api/srs_webrtc_api.hpp"
#include <srs_kernel_error.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_core_time.hpp>
#include <srs_kernel_log.hpp>
#include "modules/congestion_controller/goog_cc/goog_cc_network_control.h"
#include "rtc_base/network/sent_packet.h"
#include "modules/rtp_rtcp/source/rtcp_packet/common_header.h"
#include "modules/rtp_rtcp/source/rtcp_packet/transport_feedback.h"
#include "system_wrappers/include/field_trial.h"



#include <memory>

static webrtc::RtcEventLogNull event_log_null;

void initial_webrtc() 
{
    const char webrtc_config[] = "WebRTC-Bwe-LossBasedControl/Enabled/";
    webrtc::field_trial::InitFieldTrialsFromString(webrtc_config);
}


SrsWebRtcTwcc::SrsWebRtcTwcc(): twcc_high_sn_(0), twcc_sn_(0)
{
}

SrsWebRtcTwcc::~SrsWebRtcTwcc()
{
}

srs_error_t SrsWebRtcTwcc::initialize()
{
#ifdef SRS_CXX14
    webrtc::NetworkControllerConfig config;
    config.event_log = &event_log_null;
    config.constraints.starting_rate = webrtc::DataRate::bps(2 * 1000 * 1000);
    config.constraints.min_data_rate = webrtc::DataRate::bps(200 * 1000 );
    config.constraints.max_data_rate = webrtc::DataRate::bps(6 * 1000 * 1000);
    config.constraints.at_time = webrtc::Timestamp::ms(srsu2ms(srs_update_system_time()));
    webrtc::GoogCcConfig goog_cc_config;
    goog_cc_config.feedback_only = true;

    twcc_handler_ = std::make_unique<webrtc::GoogCcNetworkController>(config, std::move(goog_cc_config));
    if(nullptr == twcc_handler_) {
        return srs_error_new(ERROR_RTC_WEBRTC_CREATE_GCC, "create twcc handler");
    }
#endif
    return srs_success;
}

uint16_t SrsWebRtcTwcc::allocate_twcc_sn()
{
    if(0xFFFF == twcc_sn_) {
        twcc_high_sn_++;
    }
    return ++twcc_sn_;
}

srs_error_t SrsWebRtcTwcc::on_pre_send_packet(uint32_t ssrc, uint16_t rtp_sn, uint16_t twcc_sn, size_t rtp_len)
{
#ifdef SRS_CXX14
    webrtc::RtpPacketSendInfo pkt_info;
    pkt_info.ssrc = ssrc;
    pkt_info.has_rtp_sequence_number = true;
    pkt_info.rtp_sequence_number = rtp_sn;
    pkt_info.transport_sequence_number = twcc_sn;
    pkt_info.length = rtp_len;
    //TODO: maybe need to implement clock time by inhereted clock class
    adapter_.AddPacket(pkt_info, 0, webrtc::Timestamp::ms(srsu2ms(srs_update_system_time())));
#endif
    return srs_success;
}

srs_error_t SrsWebRtcTwcc::on_sent_packet(uint16_t twcc_sn)
{
#ifdef SRS_CXX14
    rtc::SentPacket pkt;
    pkt.packet_id = (twcc_high_sn_<<16) | twcc_sn;
    pkt.send_time_ms = srsu2ms(srs_update_system_time());
    absl::optional<webrtc::SentPacket> packet_msg = adapter_.ProcessSentPacket(pkt);
    if (packet_msg) {
        if (twcc_handler_)
            twcc_handler_->OnSentPacket(*packet_msg);
    }
#endif
    return srs_success;
}

srs_error_t SrsWebRtcTwcc::on_received_rtcp(const uint8_t* buffer, size_t size_bytes)
{
#ifdef SRS_CXX14
    webrtc::rtcp::TransportFeedback transport_feedback;
    // parse twcc rtcp feedback packet
    const uint8_t *packet_begin = buffer;
    const uint8_t *packet_end = buffer + size_bytes;
    webrtc::rtcp::CommonHeader rtcp_block;
    for (const uint8_t* next_block = packet_begin; next_block != packet_end; next_block = rtcp_block.NextPacket()) {
        ptrdiff_t remaining_blocks_size = packet_end - next_block;
        RTC_DCHECK_GT(remaining_blocks_size, 0);
        if (!rtcp_block.Parse(next_block, remaining_blocks_size)) {
            if (next_block == packet_begin) {
                // Failed to parse 1st header, nothing was extracted from this packet.
                return srs_error_new(ERROR_RTC_PARSE_TWCC_FEEDBACK, "Incoming invalid RTCP packet");
            }
            break;
        }

        if((webrtc::rtcp::Rtpfb::kPacketType == rtcp_block.type()) && 
            (webrtc::rtcp::TransportFeedback::kFeedbackMessageType == rtcp_block.fmt())) {
            if (!transport_feedback.Parse(rtcp_block)) {
                return srs_error_new(ERROR_RTC_PARSE_TWCC_FEEDBACK, "fail to parse twcc rtcp packet");
            }
            break;
        }
    }

    // put rtcp into twcc estimator
    absl::optional<webrtc::TransportPacketsFeedback> feedback_msg = adapter_.ProcessTransportFeedback(
          transport_feedback, webrtc::Timestamp::ms(srsu2ms(srs_update_system_time())));
    if (feedback_msg) {
        if (twcc_handler_)
            network_status_ = twcc_handler_->OnTransportPacketsFeedback(*feedback_msg);
    }
#endif
    return srs_success;
}

srs_error_t SrsWebRtcTwcc::get_network_status(float& lossrate, int& bitrate_bps, int& delay_bitrate_bps, int& rtt)
{
#ifdef SRS_CXX14
    if(twcc_handler_) {
        webrtc::GoogCcNetworkController* gcc = dynamic_cast<webrtc::GoogCcNetworkController*>(twcc_handler_.get());
        if(NULL == gcc) {
            return srs_error_new(ERROR_RTC_WEBRTC_GET_GCC, "get gcc handler");
        }
        webrtc::NetworkControlUpdate stat = gcc->GetNetworkState(webrtc::Timestamp::ms(srsu2ms(srs_update_system_time())));
        lossrate = stat.target_rate->network_estimate.loss_rate_ratio;
        if(webrtc::DataRate::Infinity() != stat.target_rate->target_rate) {
            bitrate_bps = stat.target_rate->target_rate.bps();
        }
        if(webrtc::DataRate::Infinity() != stat.target_rate->stable_target_rate) {
            delay_bitrate_bps = stat.target_rate->stable_target_rate.bps();
        }
        if(webrtc::TimeDelta::PlusInfinity() != stat.target_rate->network_estimate.round_trip_time) {
            rtt = stat.target_rate->network_estimate.round_trip_time.ms();
        }
    }
#endif
    return srs_success;
}
