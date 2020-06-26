
#ifndef SRS_WEBRTC_API_HPP
#define SRS_WEBRTC_API_HPP

#include "api/transport/network_control.h"
#include "modules/congestion_controller/rtp/transport_feedback_adapter.h"


void initial_webrtc();

class SrsWebRtcTwcc
{
private:
    std::unique_ptr<webrtc::NetworkControllerInterface> twcc_handler_;
    webrtc::TransportFeedbackAdapter adapter_;
    webrtc::NetworkControlUpdate network_status_;

    int64_t twcc_high_sn_;
    uint16_t twcc_sn_;

public:
    SrsWebRtcTwcc();
    virtual ~SrsWebRtcTwcc();

    srs_error_t initialize();
    uint16_t allocate_twcc_sn();
    srs_error_t on_pre_send_packet(uint32_t ssrc, uint16_t rtp_sn, uint16_t twcc_sn, size_t rtp_len);
    srs_error_t on_sent_packet(uint16_t twcc_sn);
    srs_error_t on_received_rtcp(const uint8_t* buffer, size_t size_bytes);
    srs_error_t get_network_status(float& lossrate, int& bitrate_bps, int& delay_bitrate_bps, int& rtt);//, enum SS_TRANSPORT_QUEUE_DELAY_STATE& qdelay_state);
};

#endif
