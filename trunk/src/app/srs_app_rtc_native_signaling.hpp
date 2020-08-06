
#ifndef _SRS_APP_RTC_NATIVE_SIGNALING_HPP_
#define _SRS_APP_RTC_NATIVE_SIGNALING_HPP_

#include <srs_core.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_rtc_rtcp.hpp>

#include <vector>

/*
    @doc https://tools.ietf.org/html/rfc3550#section-6.7
	RTCP private native protocol
	0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P| subtype |   PT=APP=204  |             length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         SSRC of sender                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          name (ASCII)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   application-dependent data                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    @doc https://yuque.antfin-inc.com/nf441k/ma1uf9/ekpd93#e07c5fc7
   application-dependent data content(TLV format)
	0                   1                  2                    3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       V(p)    |V(tlv)|Msg-Type|            Msg-ID             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            TLV(...)                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

enum SrsRTCNativeSubType {
    SrsRTCNativeSubTypeConnect = 0,
    SrsRTCNativeSubTypePublish = 1,
    SrsRTCNativeSubTypeSubscribe = 2,
    SrsRTCNativeSubTypePublishUpadte = 3,
    SrsRTCNativeSubTypeSubscribeUpdate = 4,
    SrsRTCNativeSubTypeStop = 5,
    SrsRTCNativeSubTypeDisconnect = 6,
    SrsRTCNativeSubTypeHeartbeat = 7,
    SrsRTCNativeSubTypeMTUDetect = 8,
    SrsRTCNativeSubTypeMTUDetectPacketEnd = 9,
    SrsRTCNativeSubTypeMediaControl = 10,
    SrsRTCNativeSubTypeNotify = 11,
    SrsRTCNativeSubTypeSwitchMSID = 12,
    SrsRTCNativeSubTypeWanSwitched = 13,
};

// native message type for Msg-Type field
enum SrsRTCNativeMsgType {
    SrsRTCNativeMsgType_request    = 0,
    SrsRTCNativeMsgType_final_resp = 1,
    SrsRTCNativeMsgType_temp_resp  = 2,
    SrsRTCNativeMsgType_final_ack  = 3,
    SrsRTCNativeMsgType_notify     = 4,
};

// native first level TLV type definition
enum SrsRTCNativeType {
    SrsRTCNativeType_code                  =       1,
    SrsRTCNativeType_msg                   =       2,
    SrsRTCNativeType_url                   =       3,
    SrsRTCNativeType_minisdp               =       4,
    SrsRTCNativeType_msid_cmd              =       5,
    SrsRTCNativeType_traceid               =       6,
    SrsRTCNativeType_mtu_value             =       10,
    SrsRTCNativeType_mtu_packet_num        =       11,
    SrsRTCNativeType_mode                  =       12,
    SrsRTCNativeType_pub_config            =       14,
    SrsRTCNativeType_play_config           =       15,
    SrsRTCNativeType_sequenceid            =       18,
    SrsRTCNativeType_notify_type           =       19,
    SrsRTCNativeType_need_resp             =       20,
    SrsRTCNativeType_notify_info           =       21,
    SrsRTCNativeType_msid                  =       22,
    SrsRTCNativeType_session_param         =       23,
    SrsRTCNativeType_hold_mode             =       24,
    SrsRTCNativeType_notify_recvSSRC       =       25,
    SrsRTCNativeType_new_msid              =       26,
    SrsRTCNativeType_is_mobility           =       27,
    SrsRTCNativeType_tenfold_config        =       99,
};

// rtp ext id
enum SrsRTCNativeRtpExtType {
    SrsRTCNativeRtpExtType_twcc                = 1, /* http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01 */
    SrsRTCNativeRtpExtType_cts                 = 2,
    SrsRTCNativeRtpExtType_frame_start         = 3,
    SrsRTCNativeRtpExtType_audio_level         = 4,               /* urn:ietf:params:rtp-hdrext:ssrc-audio-level */
    SrsRTCNativeRtpExtType_abs_send_time       = 5,        /* http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time */
    SrsRTCNativeRtpExtType_abs_capture_time    = 6,          /* http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time */
    SrsRTCNativeRtpExtType_picture_id          = 7,
    SrsRTCNativeRtpExtType_svc_info            = 8,
    SrsRTCNativeRtpExtType_audio_ranking_level = 9,       /* http://www.alibaba.com/experiments/rtp-hdrext/audio_ranking_level_id */
    SrsRTCNativeRtpExtType_max_count           = 32
};



inline uint8_t get_msg_type(uint8_t* payload)
{
    return payload[1] & 0x0F;
}

class SrsRtcNativeHeader : public ISrsCodec
{
protected:
    uint8_t version_;
    uint8_t tlv_ver_;
    uint8_t msg_type_;
    uint16_t msg_id_;
    uint8_t sub_type_;
    std::string name_;

protected:
    srs_error_t decode_native_header(SrsBuffer *buffer);
    srs_error_t encode_native_header(SrsBuffer *buffer);

public:
    SrsRtcNativeHeader();
    virtual ~SrsRtcNativeHeader();

    const uint8_t get_version() const;
    const uint8_t get_tlv_version() const;
    const uint8_t get_msg_type() const;
    const uint16_t get_msg_id() const;

    srs_error_t set_version(uint8_t v);
    srs_error_t set_tlv_version(uint8_t v);
    srs_error_t set_msg_type(uint8_t type);
    srs_error_t set_msg_id(uint16_t id);

    srs_error_t set_subtype(uint8_t sub_type);
    srs_error_t set_name(const std::string &name);
    
    virtual uint8_t get_subtype();
    virtual std::string get_name();

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
};

class SrsTLV : public ISrsCodec
{
private:
    uint8_t type_;
    uint16_t len_;
    uint8_t* value_;

public:
    SrsTLV();
    virtual ~SrsTLV();

    const uint8_t get_type() const;
    const uint16_t get_len() const;
    uint8_t* get_value();

    srs_error_t set_type(uint8_t type);
    srs_error_t set_value(uint16_t len, uint8_t* value);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
};


class SrsRtcNativeTempResponse : public SrsRtcNativeHeader
{
private:
    std::string trace_id_;
public:
    SrsRtcNativeTempResponse();
    virtual ~SrsRtcNativeTempResponse();

    const std::string& get_trace_id() const;
    void set_trace_id(std::string id);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);

};

class SrsRtcNativeFinalAck : public SrsRtcNativeHeader
{
public:
    SrsRtcNativeFinalAck();
    virtual ~SrsRtcNativeFinalAck();
};


class SrsRtcNativeAudioMediaParam : public ISrsCodec
{
public:
    enum SrsRTCNativeTLVType {
        SrsRTCNativeType_payload_type      = 1,
        SrsRTCNativeType_msid              = 2,
        SrsRTCNativeType_SSRC              = 3,
        SrsRTCNativeType_audio_config      = 4,
        SrsRTCNativeType_AAC_config        = 5,
        SrsRTCNativeType_opus_config       = 6,
        SrsRTCNativeType_trans_config      = 7,
        SrsRTCNativeType_FEC_type          = 8,
        SrsRTCNativeType_RTX               = 9,
        SrsRTCNativeType_flexFEC           = 10,
        SrsRTCNativeType_RED               = 11,
    };

    struct SrsRtcNativeAudioConfig
    {
        uint8_t codec;
        uint32_t sample;
        uint8_t channel;
    };

    struct SrsRtcNativeOpusConfig
    {
        uint8_t inband_fec;
        uint8_t dtx;
    };

    struct SrsRtcNativeTransConfig
    {
        uint8_t direction;
        uint8_t nack;
        uint8_t rtx;
        uint8_t fec;
        uint8_t red;
    };

    struct SrsRtcNativeRTX
    {
        uint8_t pt;
        uint8_t apt;
        uint32_t rtx_ssrc;
    };

    struct SrsRtcNativeFlexFec
    {
        uint8_t type;
        uint8_t pt;
        uint32_t prime_ssrc;
        uint32_t fec_ssrc;
    };

    struct SrsRtcNativeRed
    {
        uint8_t type;
        uint8_t pt;
    };

    uint8_t pt_;
    std::string msid_;
    uint32_t ssrc_;
    struct SrsRtcNativeAudioConfig audio_config_;
    struct SrsRtcNativeOpusConfig* opus_config_;
    struct SrsRtcNativeTransConfig trans_config_;
    uint8_t* fec_type_;
    struct SrsRtcNativeRTX* rtx_config_;
    struct SrsRtcNativeFlexFec* flex_fec_;
    struct SrsRtcNativeRed* red_;

public:
    SrsRtcNativeAudioMediaParam();
    virtual ~SrsRtcNativeAudioMediaParam();

    const uint8_t get_pt() const;
    const std::string& get_msid() const;
    const uint32_t get_ssrc() const;
    const uint8_t get_codec() const;
    const uint32_t get_sample() const;
    const uint8_t get_channel() const;
    const srs_error_t get_opus_config(uint8_t& inband_fec, uint8_t& dtx) const;
    const uint8_t get_direction() const;
    const bool nack_enabled() const;
    const bool rtx_enabled() const;
    const bool fec_enabled() const;
    const bool red_enabled() const;
    const srs_error_t get_fec_type(uint8_t& type) const;
    const srs_error_t get_rtx_config(uint8_t& pt, uint8_t& apt, uint32_t& ssrc) const;
    const srs_error_t get_flex_fec(uint8_t& type, uint8_t& pt, uint32_t& prime_ssrc, uint32_t& fec_ssrc) const;
    const srs_error_t get_red_config(uint8_t& type, uint8_t pt) const;

    void set_pt(const uint8_t pt);
    void set_msid(const std::string& msid);
    void set_ssrc(const uint32_t ssrc);
    void set_codec(const uint8_t codec);
    void set_sample(const uint32_t sample);
    void set_channel(const uint8_t channel);
    void set_opus_config(const uint8_t inband_fec, const uint8_t dtx);
    void set_direction(uint8_t direction);
    void enable_nack();
    void enable_rtx();
    void enable_fec();
    void enable_red();
    void set_fec_type(const uint8_t type);
    void set_rtx_config(const uint8_t pt, const uint8_t apt, const uint32_t ssrc);
    void set_flex_fec(const uint8_t type, const uint8_t pt, const uint32_t prime_ssrc, const uint32_t fec_ssrc);
    void set_red_config(const uint8_t type, const uint8_t pt);
    
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
};

class SrsRtcNativeVideoMediaParam: public ISrsCodec
{
public:
    enum SrsRTCNativeTLVType {
        SrsRTCNativeType_payload_type      = 1,
        SrsRTCNativeType_msid              = 2,
        SrsRTCNativeType_SSRC              = 3,
        SrsRTCNativeType_codec             = 4,
        SrsRTCNativeType_trans_config      = 5,
        SrsRTCNativeType_FEC_type          = 6,
        SrsRTCNativeType_RTX               = 7,
        SrsRTCNativeType_flexFEC           = 11,
        SrsRTCNativeType_RED               = 12,
        SrsRTCNativeType_correlative_msid  = 13,
    };

    struct SrsRtcNativeTransConfig
    {
        uint8_t direction;
        uint8_t nack;
        uint8_t rtx;
        uint8_t fec;
        uint8_t red;
    };
     struct SrsRtcNativeRTX
    {
        uint8_t pt;
        uint8_t apt;
        uint32_t rtx_ssrc;
    };

    struct SrsRtcNativeFlexFec
    {
        uint8_t type;
        uint8_t pt;
        uint32_t prime_ssrc;
        uint32_t fec_ssrc;
    };

    struct SrsRtcNativeRed
    {
        uint8_t type;
        uint8_t pt;
    };


    uint8_t pt_;
    std::string msid_;
    uint32_t ssrc_;
    uint8_t codec_;
    struct SrsRtcNativeTransConfig trans_config_;
    uint8_t* fec_type_;
    struct SrsRtcNativeRTX* rtx_config_;
    struct SrsRtcNativeFlexFec* flex_fec_;
    struct SrsRtcNativeRed* red_;
    std::string correlative_msid_;

public:
    SrsRtcNativeVideoMediaParam();
    virtual ~SrsRtcNativeVideoMediaParam();

    const uint8_t get_pt() const;
    const std::string& get_msid() const;
    const uint32_t& get_ssrc() const;
    const uint8_t get_codec() const;
    // trans config
    const uint8_t get_direction() const;
    const bool nack_enabled() const;
    const bool rtx_enabled() const;
    const bool fec_enabled() const;
    const bool red_enabled() const;
    
    const srs_error_t get_fec_type(uint8_t& type) const;
    const srs_error_t get_rtx_config(uint8_t& pt, uint8_t& apt, uint32_t& ssrc) const;
    const srs_error_t get_flex_fec(uint8_t& type, uint8_t& pt, uint32_t& prime_ssrc, uint32_t& fec_ssrc) const;
    const srs_error_t get_red_config(uint8_t& type, uint8_t pt) const;
    const std::string get_correlative_msid() const;

    void set_pt(const uint8_t pt);
    void set_msid(const std::string& msid);
    void set_ssrc(const uint32_t ssrc);
    void set_codec(const uint8_t codec);
    void set_direction(uint8_t direction);
    void enable_nack();
    void enable_rtx();
    void enable_fec();
    void enable_red();
    void set_fec_type(const uint8_t type);
    void set_rtx_config(const uint8_t pt, const uint8_t apt, const uint32_t ssrc);
    void set_flex_fec(const uint8_t type, const uint8_t pt, const uint32_t prime_ssrc, const uint32_t fec_ssrc);
    void set_red_config(const uint8_t type, const uint8_t pt);
    void set_correlative_msid(std::string msid);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);   
};

class SrsRtcNativeMiniSDP : public ISrsCodec
{
public:
    enum SrsRTCNativeTLVType {
        SrsRTCNativeType_audio_media = 2,
        SrsRTCNativeType_video_media = 3,
    };
    std::vector<SrsRtcNativeAudioMediaParam*> audio_medias_;
    std::vector<SrsRtcNativeVideoMediaParam*> video_medias_;

private:
    virtual void clear();

public:
    SrsRtcNativeMiniSDP();
    virtual ~SrsRtcNativeMiniSDP();

    SrsRtcNativeAudioMediaParam* apply_audio_media();
    SrsRtcNativeVideoMediaParam* apply_video_media();

    std::vector<SrsRtcNativeAudioMediaParam*>& get_audio_medias();
    std::vector<SrsRtcNativeVideoMediaParam*>& get_video_medias();

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
};

class SrsRtcNativeCommonMediaParam : public ISrsCodec
{
public:
    enum SrsRtcNativeRTPExtType {
        SrsRtcNativeRTPExtType_twcc = 1,
        SrsRtcNativeRTPExtType_cts = 2,
        SrsRtcNativeRTPExtType_frame_start_flag = 3,
        SrsRtcNativeRTPExtType_audio_level = 4,
        SrsRtcNativeRTPExtType_abs_send_time = 5,
        SrsRtcNativeRTPExtType_abs_capture_time = 6,
        SrsRtcNativeRTPExtType_pictureid = 7,
        SrsRtcNativeRTPExtType_svc_info = 8,
    };
    enum SrsRTCNativeTLVType {
        SrsRTCNativeType_version = 1,
        SrsRTCNativeType_extension = 2,
        SrsRTCNativeType_srtp_param = 3,
        SrsRTCNativeType_rtx_padding = 5,
    };
    struct SrsRtcNativeRTPExtension
    {
        uint8_t type;
        uint8_t id;
    };

    struct SrsRtcNativeRTXPadding
    {
        uint8_t pt;
        uint32_t ssrc;
    };

    uint8_t sdp_version_;
    std::vector<struct SrsRtcNativeRTPExtension> rtp_extension_;
    struct SrsRtcNativeRTXPadding* rtx_;
private:
    // default false, not part of rtcp app
    bool cascade_media_;
public:
    SrsRtcNativeCommonMediaParam();
    virtual ~SrsRtcNativeCommonMediaParam();

    const uint8_t get_sdp_version() const;
    std::vector<struct SrsRtcNativeRTPExtension>& get_rtp_extension();
    const srs_error_t get_rtx_padding(uint8_t& pt, uint32_t& ssrc) const;
    bool is_cascade_media() const { return cascade_media_; };

    void set_sdp_version(const uint8_t ver);
    void add_rtp_extension(const uint8_t type, const uint8_t id);
    void set_rtx(const uint8_t pt, const uint32_t ssrc);
    void set_cascade_media(bool v) { cascade_media_ = v; }

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);

};

class SrsRtcNativeSessionParam : public ISrsCodec
{
public:
    enum SrsRTCNativeTLVType {
        SrsRTCNativeType_cookie                = 1,
        SrsRTCNativeType_sdk_version           = 3,
        SrsRTCNativeType_302_ip                = 4,
        SrsRTCNativeType_302_port              = 5,
        SrsRTCNativeType_302_url               = 6,
        SrsRTCNativeType_common_media_param    = 7,
    };
    std::string cookie_;
    uint32_t sdk_version_;
    std::string ip_302_;
    uint16_t port_302_;
    std::string url_302_;
    SrsRtcNativeCommonMediaParam* media_param_;

public:
    SrsRtcNativeSessionParam();
    virtual ~SrsRtcNativeSessionParam();

    const std::string& get_cookie() const;
    const uint32_t get_sdk_version() const;
    const std::string& get_302_ip() const;
    const uint16_t get_302_port() const;
    const std::string& get_302_url() const;
    SrsRtcNativeCommonMediaParam *get_media_param();

    void set_cookie(const std::string& cookie);
    void set_sdk_version(const uint32_t ver);
    void set_302_ip(const std::string& ip);
    void set_302_port(const uint16_t port);
    void set_302_url(const std::string& url);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
};

class SrsRtcNativeCascadePath : public ISrsCodec
{
public:
    uint8_t                         idx_;
    uint16_t                        port_;
    std::string                     ip_;
    std::string                     region_;
    std::vector<std::string>        vips_;
private:
    enum SrsRTCNativeTLVType {
        SrsRTCNativeType_idx                   = 1,
        SrsRTCNativeType_ip                    = 2,
        SrsRTCNativeType_port                  = 3,
        SrsRTCNativeType_vip                   = 4,
        SrsRTCNativeType_region                = 5,
    };
public:
    SrsRtcNativeCascadePath();
    virtual ~SrsRtcNativeCascadePath();
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);  
};

class SrsRtcNativeTenfoldConfig : public ISrsCodec
{
public:
    enum {
        MODE_NONE                              = 0,
        MODE_CASCADE                           = 1, 
    };
private:
    enum SrsRTCNativeTLVType {
        SrsRTCNativeType_mode                  = 1,
        SrsRTCNativeType_cascade_path          = 2,
    };
    uint8_t                                    mode_;
    std::vector<SrsRtcNativeCascadePath*>      paths_;
public:
    SrsRtcNativeTenfoldConfig();
    virtual ~SrsRtcNativeTenfoldConfig();
public:
    uint8_t get_mode()  const { return mode_; }
    const std::vector<SrsRtcNativeCascadePath*>& get_paths() const;

    void set_mode(uint8_t mode) { mode_ = mode; }
    void append_path(SrsRtcNativeCascadePath * cascade_path);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);   
};

class SrsRtcNativePublishRequest : public SrsRtcNativeHeader
{
private:
    std::string url_;
    SrsRtcNativeMiniSDP* mini_sdp_;
    uint8_t mode_;
    SrsRtcNativeSessionParam *session_param_;
public:
    SrsRtcNativePublishRequest();
    virtual ~SrsRtcNativePublishRequest();

    const std::string& get_url() const;
    const uint8_t get_mode() const;
    SrsRtcNativeMiniSDP* get_sdp();
    SrsRtcNativeSessionParam* get_session_param();

    void set_url(std::string url);
    void set_mode(uint8_t mode);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypePublish; }
    virtual std::string get_name() { return "PUB"; }
};

class SrsRtcNativePublishResponse : public SrsRtcNativeHeader
{
private:
    uint16_t code_;
    std::string msg_;
    SrsRtcNativeMiniSDP* mini_sdp_;
    std::string pub_config_;
    std::string trace_id_;
    SrsRtcNativeSessionParam* session_param_;
public:
    SrsRtcNativePublishResponse();
    virtual ~SrsRtcNativePublishResponse();

    SrsRtcNativeMiniSDP* get_sdp();
    SrsRtcNativeSessionParam* get_session_param();
    const uint16_t get_code() const;
    const std::string& get_msg() const;
    const std::string& get_pub_config() const;
    const std::string& get_trace_id() const;

    void set_code(uint16_t code);
    void set_msg(std::string& msg);
    void set_pub_config(std::string& config);
    void set_trace_id(std::string& id);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypePublish; }
    virtual std::string get_name() { return "PUB"; }
};

class SrsRtcNativeSubscribeRequest : public SrsRtcNativeHeader
{
private:
    std::string url_;
    std::vector<std::string> msids_;
    SrsRtcNativeMiniSDP* mini_sdp_;
    uint8_t mode_;
    SrsRtcNativeSessionParam *session_param_;
    SrsRtcNativeTenfoldConfig *tenfold_config_;
public:
    SrsRtcNativeSubscribeRequest();
    virtual ~SrsRtcNativeSubscribeRequest();

    const std::string& get_url() const;
    const std::vector<std::string>& get_msid() const;
    const uint8_t get_mode() const;
    SrsRtcNativeMiniSDP* get_sdp();
    SrsRtcNativeSessionParam* get_session_param();
    SrsRtcNativeTenfoldConfig* get_tenfold_config();

    void set_url(const std::string& url);
    void add_msid(const std::string& msid);
    void set_mode(uint8_t mode);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeSubscribe; }
    virtual std::string get_name() { return "SUB"; }
};


class SrsRtcNativeSubscribeResponse : public SrsRtcNativeHeader
{
private:
    SrsRtcNativeMiniSDP* mini_sdp_;
    uint16_t code_;
    std::string msg_;
    std::string play_config_;
    std::string trace_id_;
    SrsRtcNativeSessionParam* session_param_;
public:
    SrsRtcNativeSubscribeResponse();
    virtual ~SrsRtcNativeSubscribeResponse();

    SrsRtcNativeMiniSDP* get_sdp();
    SrsRtcNativeSessionParam* get_session_param();
    const uint16_t get_code() const;
    const std::string& get_msg() const;
    const std::string& get_play_config() const;
    const std::string& get_trace_id() const;

    void set_code(uint16_t code);
    void set_msg(std::string& msg);
    void set_play_config(std::string& config);
    void set_trace_id(std::string& id);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeSubscribe; }
    virtual std::string get_name() { return "SUB"; }
};

struct SrsRtcNativeMsidCMD
{
    uint8_t cmd;
    std::string msid;
};

class SrsRtcNativePublishUpdateRequest : public SrsRtcNativeHeader
{
private:
    std::string url_;
    std::vector<SrsRtcNativeMsidCMD> msid_cmd_;
    SrsRtcNativeMiniSDP *sdp_;

public:
    SrsRtcNativePublishUpdateRequest();
    virtual ~SrsRtcNativePublishUpdateRequest();
    
    std::string& get_url();
    std::vector<SrsRtcNativeMsidCMD>& get_msid_cmd();
    SrsRtcNativeMiniSDP* get_sdp();

    void set_url(std::string url);
    void add_msid_cmd(SrsRtcNativeMsidCMD& cmd);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypePublishUpadte; }
    virtual std::string get_name() { return "PUBU"; }   
};

class SrsRtcNativePublishUpdateResponse : public SrsRtcNativeHeader
{
private:
    SrsRtcNativeMiniSDP* mini_sdp_;
    std::vector<std::string> msids_;
    uint16_t code_;
    std::string msg_;
public:
    SrsRtcNativePublishUpdateResponse();
    virtual ~SrsRtcNativePublishUpdateResponse();

    SrsRtcNativeMiniSDP* get_sdp();
    const uint16_t get_code() const;
    const std::string& get_msg() const;
    std::vector<std::string>& get_msid();
    
    void set_code(uint16_t code);
    void set_msg(std::string& msg);
    void add_msid(std::string& msid);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypePublishUpadte; }
    virtual std::string get_name() { return "PUBU"; }
};

class SrsRtcNativeSubscribeUpdateRequest : public SrsRtcNativeHeader
{
private:
    std::string url_;
    std::vector<SrsRtcNativeMsidCMD> msid_cmd_;
    SrsRtcNativeMiniSDP *sdp_;

public:
    SrsRtcNativeSubscribeUpdateRequest();
    virtual ~SrsRtcNativeSubscribeUpdateRequest();

    std::string& get_url();
    std::vector<SrsRtcNativeMsidCMD>& get_msid_cmd();
    SrsRtcNativeMiniSDP* get_sdp();

    void set_url(std::string url);
    void add_msid_cmd(SrsRtcNativeMsidCMD& cmd);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);

public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeSubscribeUpdate; }
    virtual std::string get_name() { return "SUBU"; }
};

class SrsRtcNativeSubscribeUpdateResponse : public SrsRtcNativeHeader
{
private:
    SrsRtcNativeMiniSDP* mini_sdp_;
    std::vector<std::string> msids_;
    uint16_t code_;
    std::string msg_;
public:
    SrsRtcNativeSubscribeUpdateResponse();
    virtual ~SrsRtcNativeSubscribeUpdateResponse();

    SrsRtcNativeMiniSDP* get_sdp();
    const uint16_t get_code() const;
    const std::string& get_msg() const;
    std::vector<std::string>& get_msid();
    
    void set_code(uint16_t code);
    void set_msg(std::string& msg);
    void add_msid(std::string& msid);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer);
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypePublishUpadte; }
    virtual std::string get_name() { return "SUBU"; }
};

class SrsRtcNativeCommonResponse : public SrsRtcNativeHeader
{
protected:
    uint16_t code_;
    std::string msg_;
public:
    SrsRtcNativeCommonResponse();
    virtual ~SrsRtcNativeCommonResponse();

    const uint16_t get_code() const;
    const std::string& get_msg() const;
    void set_code(uint16_t code);
    void set_msg(const std::string& msg);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer); 
};

class SrsRtcNativeStopRequest : public SrsRtcNativeHeader
{
private:
    std::string url_;
    uint16_t code_;
    std::string msg_;
public:
    SrsRtcNativeStopRequest();
    virtual ~SrsRtcNativeStopRequest();

    const std::string& get_url() const;
    const uint16_t get_code() const;
    const std::string& get_msg() const;
    void set_url(std::string url);
    void set_code(uint16_t code);
    void set_msg(std::string msg);
    
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer); 

public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeStop; }
    virtual std::string get_name() { return "STOP"; }
};

class SrsRtcNativeStopResponse : public SrsRtcNativeCommonResponse
{
public:
    SrsRtcNativeStopResponse();
    virtual ~SrsRtcNativeStopResponse();

public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeStop; }
    virtual std::string get_name() { return "STOP"; }
};

class SrsRtcNativeConnectRequest : public SrsRtcNativeHeader
{
private:
    std::string url_;
    SrsRtcNativeSessionParam *session_param_;
public:
    SrsRtcNativeConnectRequest();
    ~SrsRtcNativeConnectRequest();
public:
    SrsRtcNativeSessionParam* get_session_param();
    const std::string& get_url() const;

    void set_url(std::string url);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer); 
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeConnect; }
    virtual std::string get_name() { return "CON"; }
};

class SrsRtcNativeConnectResponse : public SrsRtcNativeHeader
{
private:
    uint16_t code_;
    std::string msg_;
    std::string trace_id_;
    SrsRtcNativeSessionParam* session_param_;
public:
    SrsRtcNativeConnectResponse();
    virtual ~SrsRtcNativeConnectResponse();
public:
    SrsRtcNativeSessionParam* get_session_param();
    
    const uint16_t get_code() const;
    const std::string& get_msg() const;
    const std::string& get_trace_id() const;

    void set_code(uint16_t code);
    void set_msg(std::string& msg);
    void set_trace_id(std::string& id);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer); 
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeConnect; }
    virtual std::string get_name() { return "CON"; }
};

class SrsRtcNativeDisconnectRequest : public SrsRtcNativeCommonResponse
{
public:
    SrsRtcNativeDisconnectRequest();
    virtual ~SrsRtcNativeDisconnectRequest();
    
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeDisconnect; }
    virtual std::string get_name() { return "DISC"; }
};

class SrsRtcNativeDisconnectResponse : public SrsRtcNativeCommonResponse
{
public:
    SrsRtcNativeDisconnectResponse();
    virtual ~SrsRtcNativeDisconnectResponse();

public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeDisconnect; }
    virtual std::string get_name() { return "DISC"; }
};

class SrsRtcNativeHeartbeatRequest : public SrsRtcNativeHeader
{
public:
    SrsRtcNativeHeartbeatRequest();
    virtual ~SrsRtcNativeHeartbeatRequest();
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeHeartbeat; }
    virtual std::string get_name() { return "HEBT"; }
};

class SrsRtcNativeHeartbeatResponse : public SrsRtcNativeCommonResponse
{
public:
    SrsRtcNativeHeartbeatResponse();
    virtual ~SrsRtcNativeHeartbeatResponse();
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeHeartbeat; }
    virtual std::string get_name() { return "HEBT"; }   
};

class SrsRtcNativeMediaControlRequest : public SrsRtcNativeHeader
{
private:
    std::string url_;
    std::vector<std::string> msids_;
    uint32_t sequence_;
public:
    SrsRtcNativeMediaControlRequest();
    virtual ~SrsRtcNativeMediaControlRequest();

    const std::string& get_url() const;
    std::vector<std::string>& get_msid();
    const uint32_t get_sequence() const;

    void set_url(std::string& url);
    void add_msid(std::string& id);
    void set_sequence(uint32_t sn);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer); 

public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeMediaControl; }
    virtual std::string get_name() { return "CTRL"; }
};

class SrsRtcNativeMediaControlReponse : public SrsRtcNativeCommonResponse
{

public:
    SrsRtcNativeMediaControlReponse();
    virtual ~SrsRtcNativeMediaControlReponse();

public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeMediaControl; }
    virtual std::string get_name() { return "CTRL"; }   
};

class SrsRtcNativeNotifyRequest : public SrsRtcNativeHeader
{
private:
    uint8_t type_;
    uint8_t need_response_;
    std::string info_;
    uint32_t recv_ssrc_;
public:
    SrsRtcNativeNotifyRequest();
    virtual ~SrsRtcNativeNotifyRequest();

    const uint8_t get_type() const;
    const bool need_response() const;
    const std::string& get_info() const;
    const uint32_t get_recv_ssrc() const;

    void set_type(uint8_t type);
    void need_response(bool enable);
    void set_info(std::string& info);
    void set_recv_ssrc(uint32_t ssrc);

public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer); 

public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeNotify; }
    virtual std::string get_name() { return "NOTI"; }
};

class SrsRtcNativeNotifyResponse : public SrsRtcNativeCommonResponse
{
public:
    SrsRtcNativeNotifyResponse();
    virtual ~SrsRtcNativeNotifyResponse();
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeNotify; }
    virtual std::string get_name() { return "NOTI"; }   
};

class SrsRtcNativeSwitchMsidRequest : public SrsRtcNativeHeader
{
private:
    std::string url_;
    std::string old_msid_;
    std::string new_msid_;

public:
    SrsRtcNativeSwitchMsidRequest();
    virtual ~SrsRtcNativeSwitchMsidRequest();

    const std::string& get_url() const;
    const std::string& get_old_msid() const;
    const std::string& get_new_msid() const;

    void set_url(std::string& url);
    void set_old_msid(std::string& msid);
    void set_new_msid(std::string& msid);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer *buffer);
    virtual int nb_bytes();
    virtual srs_error_t encode(SrsBuffer *buffer); 

public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeSwitchMSID; }
    virtual std::string get_name() { return "SWTC"; }
};

class SrsRtcNativeSwitchMsidResponse : public SrsRtcNativeCommonResponse
{
public:
    SrsRtcNativeSwitchMsidResponse();
    virtual ~SrsRtcNativeSwitchMsidResponse();
public:
    //SrsRtcNativeHeader
    virtual uint8_t get_subtype() { return SrsRTCNativeSubTypeSwitchMSID; }
    virtual std::string get_name() { return "SWTC"; } 
};

#endif
