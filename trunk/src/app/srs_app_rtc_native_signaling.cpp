
#include <srs_app_rtc_native_signaling.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_core_autofree.hpp>

#include <arpa/inet.h>

using namespace std;

SrsRtcNativeHeader::SrsRtcNativeHeader(): version_(2), tlv_ver_(0)
{
}

SrsRtcNativeHeader::~SrsRtcNativeHeader()
{
}

const uint8_t SrsRtcNativeHeader::get_version() const
{
    return version_;
}

const uint8_t SrsRtcNativeHeader::get_tlv_version() const
{
    return tlv_ver_;
}

const uint8_t SrsRtcNativeHeader::get_msg_type() const
{
    return msg_type_;
}

const uint16_t SrsRtcNativeHeader::get_msg_id() const
{
    return msg_id_;
}

srs_error_t SrsRtcNativeHeader::set_version(uint8_t v)
{
    if(2 != v && 3 != v){
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "invalid version - %d", v);
    }
    version_ = v;
    return srs_success;
}

srs_error_t SrsRtcNativeHeader::set_tlv_version(uint8_t v)
{
    if(0 != v){
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "invalid tlv version - %d", v);
    }
    tlv_ver_ = v;
    return srs_success;
}

srs_error_t SrsRtcNativeHeader::set_msg_type(uint8_t type)
{
    if(0 != type && 1 != type && 2 != type && 3 != type && 4 != type) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "valid msg type - %d", type);
    }
    msg_type_ = type;
    return srs_success;
}

srs_error_t SrsRtcNativeHeader::set_msg_id(uint16_t id)
{
    msg_id_ = id;
    return srs_success;
}

srs_error_t SrsRtcNativeHeader::set_subtype(uint8_t sub_type)
{
    sub_type_ = sub_type;
    return srs_success;
}

srs_error_t SrsRtcNativeHeader::set_name(const std::string &name)
{
    name_ = name;
    return srs_success;
}

uint8_t SrsRtcNativeHeader::get_subtype()
{
    return sub_type_;
}

std::string SrsRtcNativeHeader::get_name()
{
    return name_;
}

srs_error_t SrsRtcNativeHeader::decode_native_header(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(4)) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "required %d bytes", 4);
    }
    version_ = buffer->read_1bytes();
    if(2 != version_ && 3 != version_) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "invalid version - %d", version_);
    }

    uint8_t type = buffer->read_1bytes();
    tlv_ver_ = (type & 0xF0) >> 4;
    if(0 != tlv_ver_) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "invalid tlv version - %d", tlv_ver_);
    }
    msg_type_ = type & 0x0F;
    if(4 < msg_type_) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "invalid msg type - %d", msg_type_);
    }
    msg_id_ = buffer->read_2bytes();
    return err;
}

srs_error_t SrsRtcNativeHeader::encode_native_header(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }
    buffer->write_1bytes(version_);
    buffer->write_1bytes(((tlv_ver_ << 4) & 0xF0) | (msg_type_ & 0x0F));
    buffer->write_2bytes(msg_id_);

    return err;
}

srs_error_t SrsRtcNativeHeader::decode(SrsBuffer *buffer)
{
    return decode_native_header(buffer);
}

int SrsRtcNativeHeader::nb_bytes()
{
    return 4;
}

srs_error_t SrsRtcNativeHeader::encode(SrsBuffer *buffer)
{
    return encode_native_header(buffer);
}

SrsTLV::SrsTLV()
{
}

SrsTLV::~SrsTLV()
{
}

const uint8_t SrsTLV::get_type() const
{
    return type_;
}

const uint16_t SrsTLV::get_len() const
{
    return len_;
}

uint8_t* SrsTLV::get_value()
{
    return value_;
}

srs_error_t SrsTLV::set_type(uint8_t type)
{
    type_ = type;
    return srs_success;
}

srs_error_t SrsTLV::set_value(uint16_t len, uint8_t* value)
{
    if(kRtcpPacketSize <= len) {
        return srs_error_new(ERROR_RTC_NATIVE_INVALID_PARAM, "tlv len is more than %d. len:%d", kRtcpPacketSize, len);
    }
    len_ = len;
    value_ = value;

    return srs_success;
}

srs_error_t SrsTLV::decode(SrsBuffer *buffer)
{
    if(!buffer->require(1)) {
        return srs_error_new(ERROR_RTC_NATIVE_TLV_FORMAT, "required 1 byte");
    }
    type_ = buffer->read_1bytes();
    if(0 == type_) {
        return srs_error_new(ERROR_RTC_NATIVE_TLV_TYPE_0, "ignore 0 type");
    }

    if(!buffer->require(2)){
        return srs_error_new(ERROR_RTC_NATIVE_TLV_FORMAT, "buffer length is less than 2. len:%d", buffer->left());
    }
    len_ = buffer->read_2bytes();
    if(!buffer->require(len_)) {
        return srs_error_new(ERROR_RTC_NATIVE_TLV_FORMAT, "required %d bytes", len_);
    }
    value_ = (uint8_t*)buffer->head();
    buffer->skip(len_);

    return srs_success;
}

int SrsTLV::nb_bytes()
{
    return sizeof(type_) + sizeof(len_) + len_;
}

srs_error_t SrsTLV::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }
    buffer->write_1bytes(type_);
    buffer->write_2bytes(len_);
    buffer->write_bytes((char*)value_, len_);

    return err;
}

SrsRtcNativeTempResponse::SrsRtcNativeTempResponse()
{
    msg_type_ = SrsRTCNativeMsgType_temp_resp;
}

SrsRtcNativeTempResponse::~SrsRtcNativeTempResponse()
{
}

const string& SrsRtcNativeTempResponse::get_trace_id() const
{
    return trace_id_;
}

void SrsRtcNativeTempResponse::set_trace_id(std::string id)
{
    trace_id_ = id;
}

srs_error_t SrsRtcNativeTempResponse::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "fail to decode header");
    }
    if(!buffer->require(3)) {
        return srs_success;
    }
    // decode trace id
    SrsTLV tlv;
    if((err = tlv.decode(buffer)) != srs_success) {
        return srs_error_wrap(err, "fail to decode tlv");
    }

    trace_id_ = std::string((char*)tlv.get_value(), tlv.get_len());

    return err;
}
int SrsRtcNativeTempResponse::nb_bytes()
{
    return SrsRtcNativeHeader::nb_bytes() + 3 + trace_id_.length();
}
srs_error_t SrsRtcNativeTempResponse::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    // encode trace id
    SrsTLV tlv;
    tlv.set_type(SrsRTCNativeType_traceid);
    tlv.set_value(trace_id_.length(), (uint8_t *)trace_id_.c_str());
    if((err = tlv.encode(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode tlv. trace id %s", trace_id_.c_str());
    }
    return err;
}

SrsRtcNativeFinalAck::SrsRtcNativeFinalAck()
{
    msg_type_ = SrsRTCNativeMsgType_final_ack;
}

SrsRtcNativeFinalAck::~SrsRtcNativeFinalAck()
{
}

SrsRtcNativeAudioMediaParam::SrsRtcNativeAudioMediaParam(): pt_(0), ssrc_(0), opus_config_(NULL), fec_type_(NULL), rtx_config_(NULL),
        flex_fec_(NULL), red_(NULL)
{
    memset(&audio_config_, 0, sizeof(struct SrsRtcNativeAudioConfig));
    memset(&trans_config_, 0, sizeof(struct SrsRtcNativeTransConfig));
}

SrsRtcNativeAudioMediaParam::~SrsRtcNativeAudioMediaParam()
{
    if(NULL != opus_config_) {
        delete opus_config_;
        opus_config_ = NULL;
    }
    if(NULL != fec_type_) {
        delete fec_type_;
        fec_type_ = NULL;
    }

    if(NULL != rtx_config_) {
        delete rtx_config_;
        rtx_config_ = NULL;
    }
    if(NULL != flex_fec_) {
        delete flex_fec_;
        flex_fec_ = NULL;
    }
    if(NULL != red_) {
        delete red_;
        red_ = NULL;
    }
}

const uint8_t SrsRtcNativeAudioMediaParam::get_pt() const
{
    return pt_;
}

const string& SrsRtcNativeAudioMediaParam::get_msid() const
{
    return msid_;
}
    
const uint32_t SrsRtcNativeAudioMediaParam::get_ssrc() const
{
    return ssrc_;
}

const uint8_t SrsRtcNativeAudioMediaParam::get_codec() const
{
    return audio_config_.codec;
}

const uint32_t SrsRtcNativeAudioMediaParam::get_sample() const
{
    return audio_config_.sample;
}

const uint8_t SrsRtcNativeAudioMediaParam::get_channel() const
{
    return audio_config_.channel;
}

const srs_error_t SrsRtcNativeAudioMediaParam::get_opus_config(uint8_t& inband_fec, uint8_t& dtx) const
{
    if(NULL == opus_config_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no opus config");
    }
    inband_fec = opus_config_->inband_fec;
    dtx = opus_config_->dtx;
    return srs_success;
}

const uint8_t SrsRtcNativeAudioMediaParam::get_direction() const
{
    return trans_config_.direction;
}

const bool SrsRtcNativeAudioMediaParam::nack_enabled() const
{
    return trans_config_.nack == 1;
}

const bool SrsRtcNativeAudioMediaParam::rtx_enabled() const
{
    return trans_config_.rtx == 1 && rtx_config_ != NULL;
}

const bool SrsRtcNativeAudioMediaParam::fec_enabled() const
{
    return trans_config_.fec == 1 && fec_type_ != NULL;
}

const bool SrsRtcNativeAudioMediaParam::red_enabled() const
{
    return trans_config_.red == 1 && red_ != NULL;
}

const srs_error_t  SrsRtcNativeAudioMediaParam::get_fec_type(uint8_t& type) const
{
    if(NULL == fec_type_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no fec type");
    }
    type = *fec_type_;
    return srs_success;
}

const srs_error_t SrsRtcNativeAudioMediaParam::get_rtx_config(uint8_t& pt, uint8_t& apt, uint32_t& ssrc) const
{
    if(NULL == rtx_config_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no rtx config");
    }
    
    pt = rtx_config_->pt;
    apt = rtx_config_->apt;
    ssrc = rtx_config_->rtx_ssrc;

    return srs_success;
}

const srs_error_t SrsRtcNativeAudioMediaParam::get_flex_fec(uint8_t& type, uint8_t& pt, uint32_t& prime_ssrc, uint32_t& fec_ssrc) const
{
    if(NULL == flex_fec_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no flex fec config");
    }

    type = flex_fec_->type;
    pt = flex_fec_->pt;
    prime_ssrc = flex_fec_->prime_ssrc;
    fec_ssrc = flex_fec_->fec_ssrc;

    return srs_success;
}

const srs_error_t SrsRtcNativeAudioMediaParam::get_red_config(uint8_t& type, uint8_t pt) const
{
    if(NULL == red_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no red config");
    }

    type = red_->type;
    pt = red_->pt;

    return srs_success;
}

void SrsRtcNativeAudioMediaParam::set_pt(const uint8_t pt)
{
    pt_ = pt;
}

void SrsRtcNativeAudioMediaParam::set_msid(const std::string& msid)
{
    msid_ = msid;
}

void SrsRtcNativeAudioMediaParam::set_ssrc(const uint32_t ssrc)
{
    ssrc_ = ssrc;
}

void SrsRtcNativeAudioMediaParam::set_codec(const uint8_t codec)
{
    audio_config_.codec = codec;
}

void SrsRtcNativeAudioMediaParam::set_sample(const uint32_t sample)
{
    audio_config_.channel = sample;
}

void SrsRtcNativeAudioMediaParam::set_channel(const uint8_t channel)
{
    audio_config_.channel = channel;
}

void SrsRtcNativeAudioMediaParam::set_opus_config(const uint8_t inband_fec, const uint8_t dtx)
{
    if(NULL == opus_config_) {
        opus_config_ = new SrsRtcNativeAudioMediaParam::SrsRtcNativeOpusConfig;
    }
    opus_config_->inband_fec = inband_fec;
    opus_config_->dtx = dtx;
}

void SrsRtcNativeAudioMediaParam::set_direction(uint8_t direction)
{
    trans_config_.direction = direction;
}

void SrsRtcNativeAudioMediaParam::enable_nack()
{
    trans_config_.nack = 1;
}

void SrsRtcNativeAudioMediaParam::enable_rtx()
{
    trans_config_.rtx = 1;
}

void SrsRtcNativeAudioMediaParam::enable_fec()
{
    trans_config_.fec = 1;
}

void SrsRtcNativeAudioMediaParam::enable_red()
{
    trans_config_.red = 1;
}

void SrsRtcNativeAudioMediaParam::set_fec_type(const uint8_t type)
{
    if(NULL == fec_type_) {
        fec_type_ = new uint8_t;
    }
    *fec_type_ = type;
}

void SrsRtcNativeAudioMediaParam::set_rtx_config(const uint8_t pt, const uint8_t apt, const uint32_t ssrc)
{
    if(NULL == rtx_config_) {
        rtx_config_ = new SrsRtcNativeAudioMediaParam::SrsRtcNativeRTX;
    }
    rtx_config_->pt = pt;
    rtx_config_->apt = apt;
    rtx_config_->rtx_ssrc = ssrc;
}

void SrsRtcNativeAudioMediaParam::set_flex_fec(const uint8_t type, const uint8_t pt, const uint32_t prime_ssrc, const uint32_t fec_ssrc)
{
    if(NULL == flex_fec_) {
        flex_fec_ = new SrsRtcNativeAudioMediaParam::SrsRtcNativeFlexFec;
    }
    flex_fec_->type = type;
    flex_fec_->pt = pt;
    flex_fec_->prime_ssrc = prime_ssrc;
    flex_fec_->fec_ssrc = fec_ssrc;
}

void SrsRtcNativeAudioMediaParam::set_red_config(const uint8_t type, const uint8_t pt)
{
    if(NULL == red_) {
        red_ = new SrsRtcNativeAudioMediaParam::SrsRtcNativeRed;
    }
    red_->pt = pt;
    red_->type = type;
}
    
srs_error_t SrsRtcNativeAudioMediaParam::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_payload_type == tlv.get_type()) {
            pt_ = *tlv.get_value();
            srs_info("decode audio param - pt %d", pt_);
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_msid == tlv.get_type()) {
            msid_ = std::string((char*)tlv.get_value(), tlv.get_len());
            srs_info("decode audio param - msid %s", msid_.c_str());
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_SSRC == tlv.get_type()) {
            ssrc_ = *((uint32_t*)tlv.get_value());
            ssrc_ = ntohl(ssrc_);
            srs_info("decode audio param - ssrc %d", ssrc_);
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_audio_config == tlv.get_type()) {
            uint8_t *p = tlv.get_value();
            audio_config_.codec = *p++;
            audio_config_.sample = *((uint32_t*)p);
            audio_config_.sample = ntohl(audio_config_.sample);
            p += 4;
            audio_config_.channel = *p;
            srs_info("decode audio param - audio config: codec %d, sample %d, channel %d", 
                audio_config_.codec, audio_config_.sample, audio_config_.channel);
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_AAC_config == tlv.get_type()) {
            srs_warn("not support aac config in audio media param");
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_opus_config == tlv.get_type()) {
            uint8_t *p = tlv.get_value();
            if(NULL == opus_config_) {
                opus_config_ = new SrsRtcNativeAudioMediaParam::SrsRtcNativeOpusConfig;
            }
            opus_config_->inband_fec = (*p >>6) & 0x03;
            opus_config_->dtx = (*p >> 4) & 0x03;
            srs_info("decode audio param - opus config: inband_fec %d, dtx %d", 
                opus_config_->inband_fec, opus_config_->dtx);
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_trans_config == tlv.get_type()) {
            uint8_t* p = tlv.get_value();
            trans_config_.direction = (*p >> 6) & 0x03;
            trans_config_.nack = (*p >> 4) & 0x03;
            trans_config_.rtx = (*p >> 2) & 0x03;
            trans_config_.fec = *p & 0x03;
            p++;
            trans_config_.red = (*p >> 6) & 0x03;
            srs_info("decode audio param - trans_config: direction %d, nack %d, rtx %d, fec %d, red %d", 
                trans_config_.direction, trans_config_.nack, trans_config_.rtx, trans_config_.fec, trans_config_.red);
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_FEC_type == tlv.get_type()) {
            if(NULL == fec_type_) {
                fec_type_ = new uint8_t;
            }
            *fec_type_ = *tlv.get_value();
            srs_info("decode audio param - fec type %d", *fec_type_);
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_RTX == tlv.get_type()) {
            uint8_t *p = tlv.get_value();
            if(NULL == rtx_config_) {
                rtx_config_ = new SrsRtcNativeAudioMediaParam::SrsRtcNativeRTX;
            }
            rtx_config_->pt = *p++;
            rtx_config_->apt = *p++;
            rtx_config_->rtx_ssrc= *((uint32_t *)p);
            rtx_config_->rtx_ssrc = ntohl(rtx_config_->rtx_ssrc);
            srs_info("decode audio param - rtx: pt %d, apt %d, ssrc %d",
                rtx_config_->pt, rtx_config_->apt, rtx_config_->rtx_ssrc);
        } else if (SrsRtcNativeAudioMediaParam::SrsRTCNativeType_flexFEC == tlv.get_type()) {
            uint8_t *p = tlv.get_value();
            if(NULL == flex_fec_) {
                flex_fec_ = new SrsRtcNativeAudioMediaParam::SrsRtcNativeFlexFec;
            }
            flex_fec_->type = *p++;
            flex_fec_->pt = *p++;
            flex_fec_->prime_ssrc = *((uint32_t *)p);
            flex_fec_->prime_ssrc = ntohl(flex_fec_->prime_ssrc);
            p += 4;
            flex_fec_->fec_ssrc = *((uint32_t *)p);
            flex_fec_->fec_ssrc = ntohl(flex_fec_->fec_ssrc);
            srs_info("decode audio param - flex fec: type %d, pt %d, prime ssrc %d, fec ssrc %d",
                flex_fec_->type, flex_fec_->pt, flex_fec_->prime_ssrc, flex_fec_->fec_ssrc);
        } else if(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_RED == tlv.get_type()) {
            uint8_t* p = tlv.get_value();
            if(NULL == red_) {
                red_ = new SrsRtcNativeAudioMediaParam::SrsRtcNativeRed;
            }
            red_->type = *p++;
            red_->pt = *p;
            srs_info("decode audio param - red: type %d, pt %d", red_->type, red_->pt);
        } else {
            srs_warn("unkown type:%d", tlv.get_value());
        }
    }
    return err;
}

int SrsRtcNativeAudioMediaParam::nb_bytes()
{
    //include tlv
    int len = 3+sizeof(pt_);
    len += 3 + msid_.length();
    len += 3 + sizeof(ssrc_);
    len += 3 + sizeof(struct SrsRtcNativeAudioMediaParam::SrsRtcNativeAudioConfig);
    len += 3 +  2/*TransConfig*/;
    if(NULL != opus_config_) {
        len += 3 + 1;
    }
    if(NULL != fec_type_) {
        len += 3 + 1;
    }
    if(NULL != rtx_config_) {
        len += 3 + sizeof(struct SrsRtcNativeAudioMediaParam::SrsRtcNativeRTX);
    }
    if(NULL != flex_fec_) {
        len += 3 + sizeof(struct SrsRtcNativeAudioMediaParam::SrsRtcNativeFlexFec);
    }
    if(NULL != red_) {
        len += 3 + sizeof(struct SrsRtcNativeAudioMediaParam::SrsRtcNativeRed);
    }
    return len;
}

srs_error_t SrsRtcNativeAudioMediaParam::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_BUF_SIZE, "invalid buffer size %d", buffer->left());
    }

    uint8_t tmp[64];
    uint32_t net32;
    SrsTLV tlv;

    // encode pt
    tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_payload_type);
    tlv.set_value(sizeof(pt_), &pt_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode pt: %d", pt_);
    }

    // encode msid
    tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_msid);
    tlv.set_value(msid_.length(), (uint8_t*)msid_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode msid: %s", msid_.c_str());
    }

    // encode ssrc
    tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_SSRC);
    net32 = htonl(ssrc_);
    tlv.set_value(sizeof(ssrc_), (uint8_t*)(&net32));
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode ssrc: %d", ssrc_);
    }

    // encode audio config
    tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_audio_config);
    memset(tmp, 0, sizeof(tmp));
    memcpy(tmp, &audio_config_.codec, sizeof(audio_config_.codec));
    net32 = htonl(audio_config_.sample);
    memcpy(tmp + sizeof(audio_config_.codec), (uint8_t*)(&net32), sizeof(net32));
    memcpy(tmp + sizeof(audio_config_.codec) + sizeof(net32), &audio_config_.channel, sizeof(audio_config_.channel));
    tlv.set_value(sizeof(audio_config_.codec) + sizeof(net32) + sizeof(audio_config_.channel), tmp);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode audio config. codec: %d, sample: %d, channel: %d",
            audio_config_.codec, audio_config_.sample, audio_config_.channel);
    }

    // encode opus config
    if(NULL != opus_config_) {
        tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_opus_config);
        tmp[0] = (opus_config_->inband_fec & 0x03) << 6 | (opus_config_->dtx & 0x03) << 4;
        tlv.set_value(1, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode opus config: inband_fec: %d, dtx: %d",
                opus_config_->inband_fec, opus_config_->dtx);
        }
    }

    // encode trans config
    tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_trans_config);
    tmp[0] = (trans_config_.direction & 0x03) << 6 | (trans_config_.nack & 0x03) << 4 | (trans_config_.rtx & 0x03) << 2 |
                (trans_config_.fec & 0x03);
    tmp[1] = (trans_config_.red & 0x03)<<6 | 0x00;
    tlv.set_value(2, tmp);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode trans config. direction: %d, nack: %d, rtx: %d, fec: %d, red: %d",
            trans_config_.direction, trans_config_.nack, trans_config_.rtx, trans_config_.fec);
    }

    // encode fec type
    if(NULL != fec_type_) {
        tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_FEC_type);
        tlv.set_value(1, fec_type_);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode fec type: %d", *fec_type_);
        }
    }

    // encode rtx
    if(NULL != rtx_config_) {
        tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_RTX);
        tmp[0] = rtx_config_->pt;
        tmp[1] = rtx_config_->apt;
        net32 = htonl(rtx_config_->rtx_ssrc);
        memcpy(tmp+2, (uint8_t*)(&net32), sizeof(net32));
        tlv.set_value(2+4, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode rtx config. pt: %d, apt: %d, rtx_ssrc:%d",
                rtx_config_->pt, rtx_config_->apt, rtx_config_->rtx_ssrc);
        }
    }

    // encode flex fec
    if(NULL != flex_fec_) {
        tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_flexFEC);
        tmp[0] = flex_fec_->type;
        tmp[1] = flex_fec_->pt;
        net32 = htonl(flex_fec_->prime_ssrc);
        memcpy(tmp + 2, (uint8_t*)(&net32), 4);
        net32 = htonl(flex_fec_->fec_ssrc);
        memcpy(tmp + 6, (uint8_t*)(&net32), 4);
        tlv.set_value(1 + 1 + 4 + 4, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode flex fec config. type: %d, pt: %d, prime_ssrc: %d, fec_ssrc: %d",
                flex_fec_->type, flex_fec_->pt, flex_fec_->prime_ssrc, flex_fec_->fec_ssrc);
        }
    }

    // encode red
    if(NULL != red_) {
        tlv.set_type(SrsRtcNativeAudioMediaParam::SrsRTCNativeType_RED);
        tmp[0] = red_->type;
        tmp[1] = red_->pt;
        tlv.set_value(2, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode red config. type: %d, pt: %d",
                red_->type, red_->pt);
        }
    }

    return err;
}

SrsRtcNativeVideoMediaParam::SrsRtcNativeVideoMediaParam(): pt_(0), ssrc_(0), codec_(0), fec_type_(NULL), rtx_config_(NULL),
    flex_fec_(NULL), red_(NULL)
{
    memset(&trans_config_, 0, sizeof(trans_config_));
}

SrsRtcNativeVideoMediaParam::~SrsRtcNativeVideoMediaParam()
{
    if(NULL != fec_type_) {
        delete fec_type_;
        fec_type_ = NULL;
    }
    if(NULL != rtx_config_) {
        delete rtx_config_;
        rtx_config_ = NULL;
    }
    if(NULL != flex_fec_) {
        delete flex_fec_;
        flex_fec_ = NULL;
    }
    if(NULL != red_) {
        delete red_;
        red_ = NULL;
    }
}

const uint8_t SrsRtcNativeVideoMediaParam::get_pt() const
{
    return pt_;
}

const string& SrsRtcNativeVideoMediaParam::get_msid() const
{
    return msid_;
}

const uint32_t& SrsRtcNativeVideoMediaParam::get_ssrc() const
{
    return ssrc_;
}

const uint8_t SrsRtcNativeVideoMediaParam::get_codec() const
{
    return codec_;
}

// trans config
const uint8_t SrsRtcNativeVideoMediaParam::get_direction() const
{
    return trans_config_.direction;
}

const bool SrsRtcNativeVideoMediaParam::nack_enabled() const
{
    return trans_config_.nack == 1;
}

const bool SrsRtcNativeVideoMediaParam::rtx_enabled() const
{
    return trans_config_.rtx == 1 && rtx_config_ != NULL;
}

const bool SrsRtcNativeVideoMediaParam::fec_enabled() const
{
    return trans_config_.fec == 1 && fec_type_ != NULL;
}

const bool SrsRtcNativeVideoMediaParam::red_enabled() const
{
    return trans_config_.red == 1 && red_ != NULL;
}
    
const srs_error_t SrsRtcNativeVideoMediaParam::get_fec_type(uint8_t& type) const
{
    if(NULL == fec_type_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no fec_type");
    }
    type = *fec_type_;
    return srs_success;
}

const srs_error_t SrsRtcNativeVideoMediaParam::get_rtx_config(uint8_t& pt, uint8_t& apt, uint32_t& ssrc) const
{
    if(NULL == rtx_config_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no rtx config");
    }
    pt = rtx_config_->pt;
    apt = rtx_config_->apt;
    ssrc = rtx_config_->rtx_ssrc;
    return srs_success;
}

const srs_error_t SrsRtcNativeVideoMediaParam::get_flex_fec(uint8_t& type, uint8_t& pt, uint32_t& prime_ssrc, uint32_t& fec_ssrc) const
{
    if(NULL == flex_fec_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no flex fec");
    }
    type = flex_fec_->type;
    pt = flex_fec_->pt;
    prime_ssrc = flex_fec_->prime_ssrc;
    fec_ssrc = flex_fec_->fec_ssrc;
    return srs_success;
}

const srs_error_t SrsRtcNativeVideoMediaParam::get_red_config(uint8_t& type, uint8_t pt) const
{
    if(NULL == red_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no red");
    }
    type = red_->type;
    pt = red_->pt;
    return srs_success;
}

const string SrsRtcNativeVideoMediaParam::get_correlative_msid() const
{
    return correlative_msid_;
}

void SrsRtcNativeVideoMediaParam::set_pt(const uint8_t pt)
{
    pt_ = pt;
}

void SrsRtcNativeVideoMediaParam::set_msid(const std::string& msid)
{
    msid_ = msid;
}

void SrsRtcNativeVideoMediaParam::set_ssrc(const uint32_t ssrc)
{
    ssrc_ = ssrc;
}

void SrsRtcNativeVideoMediaParam::set_codec(const uint8_t codec)
{
    codec_ = codec;
}

void SrsRtcNativeVideoMediaParam::set_direction(uint8_t direction)
{
    trans_config_.direction = direction;
}

void SrsRtcNativeVideoMediaParam::enable_nack()
{
    trans_config_.nack = 1;
}

void SrsRtcNativeVideoMediaParam::enable_rtx()
{
    trans_config_.rtx = 1;
}

void SrsRtcNativeVideoMediaParam::enable_fec()
{
    trans_config_.fec = 1;
}

void SrsRtcNativeVideoMediaParam::enable_red()
{
    trans_config_.red = 1;
}

void SrsRtcNativeVideoMediaParam::set_fec_type(const uint8_t type)
{
    if(NULL == fec_type_) {
        fec_type_ = new uint8_t;
    }
    *fec_type_ = type;
}

void SrsRtcNativeVideoMediaParam::set_rtx_config(const uint8_t pt, const uint8_t apt, const uint32_t ssrc)
{
    if(NULL == rtx_config_) {
        rtx_config_ = new SrsRtcNativeVideoMediaParam::SrsRtcNativeRTX;
    }
    rtx_config_->pt = pt;
    rtx_config_->apt = apt;
    rtx_config_->rtx_ssrc = ssrc;
}

void SrsRtcNativeVideoMediaParam::set_flex_fec(const uint8_t type, const uint8_t pt, const uint32_t prime_ssrc, const uint32_t fec_ssrc)
{
    if(NULL == flex_fec_) {
        flex_fec_ = new SrsRtcNativeVideoMediaParam::SrsRtcNativeFlexFec;
    }
    flex_fec_->type = type;
    flex_fec_->pt = pt;
    flex_fec_->prime_ssrc = prime_ssrc;
    flex_fec_->fec_ssrc = fec_ssrc;
}

void SrsRtcNativeVideoMediaParam::set_red_config(const uint8_t type, const uint8_t pt)
{
    if(NULL == red_) {
        red_ = new SrsRtcNativeVideoMediaParam::SrsRtcNativeRed;
    }
    red_->type = type;
    red_->pt = pt;
}

void SrsRtcNativeVideoMediaParam::set_correlative_msid(std::string msid)
{
    correlative_msid_ = msid;
}

    // ISrsCodec
srs_error_t SrsRtcNativeVideoMediaParam::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_payload_type == tlv.get_type()) {
            pt_ = *tlv.get_value();
            srs_info("decode video param - pt %d", pt_);
        } else if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_msid == tlv.get_type()) {
            msid_ = std::string((char*)tlv.get_value(), tlv.get_len());
            srs_info("decode video param - msid %s", msid_.c_str());
        } else if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_SSRC == tlv.get_type()) {
            ssrc_ = *((uint32_t*)tlv.get_value());
            ssrc_ = ntohl(ssrc_);
            srs_info("decode video param - ssrc %d", ssrc_);
        } else if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_codec == tlv.get_type()) {
            codec_ = *tlv.get_value();
            srs_info("decode video param - codec %d", codec_);
        } else if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_trans_config == tlv.get_type()) {
            uint8_t* p = tlv.get_value();
            trans_config_.direction = (*p >> 6) & 0x03;
            trans_config_.nack = (*p >> 4) & 0x03;
            trans_config_.rtx = (*p >> 2) & 0x03;
            trans_config_.fec = *p & 0x03;
            p++;
            trans_config_.red = (*p >> 6) & 0x03;
            srs_info("decode video param - trans_config: direction %d, nack %d, rtx %d, fec %d, red %d", 
                trans_config_.direction, trans_config_.nack, trans_config_.rtx, trans_config_.fec, trans_config_.red);
        } else if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_FEC_type == tlv.get_type()) {
            if(NULL == fec_type_) {
                fec_type_ = new uint8_t;
            }
            *fec_type_ = *tlv.get_value();
            srs_info("decode video param - fec type %d", *fec_type_);
        } else if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_RTX == tlv.get_type()) {
            uint8_t *p = tlv.get_value();
            if(NULL == rtx_config_) {
                rtx_config_ = new SrsRtcNativeVideoMediaParam::SrsRtcNativeRTX;
            }
            rtx_config_->pt = *p++;
            rtx_config_->apt = *p++;
            rtx_config_->rtx_ssrc= *((uint32_t *)p);
            rtx_config_->rtx_ssrc = ntohl(rtx_config_->rtx_ssrc);
            srs_info("decode video param - rtx: pt %d, apt %d, ssrc %d",
                rtx_config_->pt, rtx_config_->apt, rtx_config_->rtx_ssrc);
        } else if (SrsRtcNativeVideoMediaParam::SrsRTCNativeType_flexFEC == tlv.get_type()) {
            uint8_t *p = tlv.get_value();
            if(NULL == flex_fec_) {
                flex_fec_ = new SrsRtcNativeVideoMediaParam::SrsRtcNativeFlexFec;
            }
            flex_fec_->type = *p++;
            flex_fec_->pt = *p++;
            flex_fec_->prime_ssrc = *((uint32_t *)p);
            flex_fec_->prime_ssrc = ntohl(flex_fec_->prime_ssrc);
            p += 4;
            flex_fec_->fec_ssrc = *((uint32_t *)p);
            flex_fec_->fec_ssrc = ntohl(flex_fec_->fec_ssrc);
            srs_info("decode video param - flex fec: type %d, pt %d, prime ssrc %d, fec ssrc %d",
                flex_fec_->type, flex_fec_->pt, flex_fec_->prime_ssrc, flex_fec_->fec_ssrc);
        } else if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_RED == tlv.get_type()) {
            uint8_t* p = tlv.get_value();
            if(NULL == red_) {
                red_ = new SrsRtcNativeVideoMediaParam::SrsRtcNativeRed;
            }
            red_->type = *p++;
            red_->pt = *p;
            srs_info("decode video param - red: type %d, pt %d", red_->type, red_->pt);
        } else if(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_correlative_msid == tlv.get_type()) {
            correlative_msid_ = std::string((char*)tlv.get_value(), tlv.get_len());
            srs_info("decode video param - correlative msid %s", correlative_msid_.c_str());
        } else {
            srs_warn("unkown type:%d", tlv.get_value());
        }
    }
    return err;
}

int SrsRtcNativeVideoMediaParam::nb_bytes()
{
    int len = 3 + sizeof(pt_);
    len += 3 + msid_.length();
    len += 3 + sizeof(codec_);
    len += 3 + 2 /*trans config*/;
    if(NULL != fec_type_) {
        len += 3 + 1;
    }
    if(NULL != rtx_config_) {
        len += 3 + sizeof(struct SrsRtcNativeVideoMediaParam::SrsRtcNativeRTX);
    }
    if(NULL != flex_fec_) {
        len += 3 + sizeof(struct SrsRtcNativeVideoMediaParam::SrsRtcNativeFlexFec);
    }
    if(NULL != red_) {
        len += 3 + sizeof(struct SrsRtcNativeVideoMediaParam::SrsRtcNativeRed);
    }
    if(0 != correlative_msid_.length()) {
        len += 3 + correlative_msid_.length();
    }
    return len;
}

srs_error_t SrsRtcNativeVideoMediaParam::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_BUF_SIZE, "invalid buffer size %d", buffer->left());
    }

    uint8_t tmp[64];
    uint32_t net32;
    SrsTLV tlv;

    // encode pt
    tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_payload_type);
    tlv.set_value(sizeof(pt_), &pt_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode pt: %d", pt_);
    }

    // encode msid
    tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_msid);
    tlv.set_value(msid_.length(), (uint8_t*)msid_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode msid: %s", msid_.c_str());
    }

    // encode ssrc
    tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_SSRC);
    net32 = htonl(ssrc_);
    tlv.set_value(sizeof(ssrc_), (uint8_t*)(&net32));
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode ssrc: %d", ssrc_);
    }

    // encode codec config
    tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_codec);
    tlv.set_value(sizeof(codec_), &codec_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode codec: %d", codec_);
    }

    // encode trans config
    tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_trans_config);
    tmp[0] = (trans_config_.direction & 0x03) << 6 | (trans_config_.nack & 0x03) << 4 | (trans_config_.rtx & 0x03) << 2 |
                (trans_config_.fec & 0x03);
    tmp[1] = (trans_config_.red & 0x03)<<6 | 0x00;
    tlv.set_value(2, tmp);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode trans config. direction: %d, nack: %d, rtx: %d, fec: %d, red: %d",
            trans_config_.direction, trans_config_.nack, trans_config_.rtx, trans_config_.fec, trans_config_.red);
    }

    // encode fec type
    if(NULL != fec_type_) {
        tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_FEC_type);
        tlv.set_value(1, fec_type_);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode fec type: %d", *fec_type_);
        }
    }

    // encode rtx
    if(NULL != rtx_config_) {
        tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_RTX);
        tmp[0] = rtx_config_->pt;
        tmp[1] = rtx_config_->apt;
        net32 = htonl(rtx_config_->rtx_ssrc);
        memcpy(tmp+2, (uint8_t*)(&net32), sizeof(net32));
        tlv.set_value(2+4, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode rtx config. pt: %d, apt: %d, rtx_ssrc: %d",
                rtx_config_->pt, rtx_config_->apt, rtx_config_->rtx_ssrc);
        }
    }

    // encode flex fec
    if(NULL != flex_fec_) {
        tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_flexFEC);
        tmp[0] = flex_fec_->type;
        tmp[1] = flex_fec_->pt;
        net32 = htonl(flex_fec_->prime_ssrc);
        memcpy(tmp + 2, (uint8_t*)(&net32), 4);
        net32 = htonl(flex_fec_->fec_ssrc);
        memcpy(tmp + 6, (uint8_t*)(&net32), 4);
        tlv.set_value(1 + 1 + 4 + 4, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode flex fec config. type: %d, pt: %d, prime_ssrc: %d, fec_ssrc: %d",
                flex_fec_->type, flex_fec_->pt, flex_fec_->prime_ssrc, flex_fec_->fec_ssrc);
        }
    }

    // encode red
    if(NULL != red_) {
        tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_RED);
        tmp[0] = red_->type;
        tmp[1] = red_->pt;
        tlv.set_value(2, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode red config. type: %d, pt: %d", 
                red_->type, red_->pt);
        }
    }

    // encode correlative msid
    if(!correlative_msid_.empty()) {
        tlv.set_type(SrsRtcNativeVideoMediaParam::SrsRTCNativeType_correlative_msid);
        tlv.set_value(correlative_msid_.length(), (uint8_t*)correlative_msid_.c_str());
    }

    return err;
}

SrsRtcNativeMiniSDP::SrsRtcNativeMiniSDP()
{
}

SrsRtcNativeMiniSDP::~SrsRtcNativeMiniSDP()
{
    clear();
}

void SrsRtcNativeMiniSDP::clear()
{
    for(vector<SrsRtcNativeAudioMediaParam*>::iterator it = audio_medias_.begin(); it != audio_medias_.end(); ++it) {
        SrsRtcNativeAudioMediaParam* audio = *it;
        delete audio;
        audio = NULL;
    }
    audio_medias_.clear();

    for(vector<SrsRtcNativeVideoMediaParam*>::iterator it = video_medias_.begin(); it != video_medias_.end(); ++it) {
        SrsRtcNativeVideoMediaParam* video = *it;
        delete video;
        video = NULL;
    }
    video_medias_.clear();
}

SrsRtcNativeAudioMediaParam* SrsRtcNativeMiniSDP::apply_audio_media()
{
    SrsRtcNativeAudioMediaParam* audio = new SrsRtcNativeAudioMediaParam;
    audio_medias_.push_back(audio);
    return audio;
}

SrsRtcNativeVideoMediaParam* SrsRtcNativeMiniSDP::apply_video_media()
{
    SrsRtcNativeVideoMediaParam* video = new SrsRtcNativeVideoMediaParam;
    video_medias_.push_back(video);
    return video;
}

vector<SrsRtcNativeAudioMediaParam*>& SrsRtcNativeMiniSDP::get_audio_medias()
{
    return audio_medias_;
}

vector<SrsRtcNativeVideoMediaParam*>& SrsRtcNativeMiniSDP::get_video_medias()
{
    return video_medias_;
}

srs_error_t SrsRtcNativeMiniSDP::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;

    clear();
    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRtcNativeMiniSDP::SrsRTCNativeType_audio_media == tlv.get_type()) {
            SrsBuffer audioBuf((char*)tlv.get_value(), tlv.get_len());
           
            SrsRtcNativeAudioMediaParam* audio = new SrsRtcNativeAudioMediaParam;
            if(srs_success != (err = audio->decode(&audioBuf))) {
                return srs_error_wrap(err, "decode audio media");
            }
            audio_medias_.push_back(audio);
        } else if(SrsRtcNativeMiniSDP::SrsRTCNativeType_video_media == tlv.get_type()) {
            SrsBuffer videoBuf((char*)tlv.get_value(), tlv.get_len());
           
            SrsRtcNativeVideoMediaParam* video = new SrsRtcNativeVideoMediaParam;
            if(srs_success != (err = video->decode(&videoBuf))) {
                return srs_error_wrap(err, "decode video media");
            }
            video_medias_.push_back(video);
        } else {
            srs_warn("in mini sdp, unkonw type:%d", tlv.get_type());
        }
    }
    return err;
}

int SrsRtcNativeMiniSDP::nb_bytes()
{
    int len = 0;
    for(vector<SrsRtcNativeAudioMediaParam*>::iterator it = audio_medias_.begin(); it != audio_medias_.end(); ++it) {
        SrsRtcNativeAudioMediaParam* audio = *it;
        len += 3 + audio->nb_bytes();
    }
    for(vector<SrsRtcNativeVideoMediaParam*>::iterator it = video_medias_.begin(); it != video_medias_.end(); ++it) {
        SrsRtcNativeVideoMediaParam* video = *it;
        len += 3 + video->nb_bytes();
    }
    return len;
}

srs_error_t SrsRtcNativeMiniSDP::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_BUF_SIZE, "invalid buffer size %d", buffer->left());
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode audio media
    for(vector<SrsRtcNativeAudioMediaParam*>::iterator it = audio_medias_.begin(); it != audio_medias_.end(); ++it) {
        SrsRtcNativeAudioMediaParam* audio = *it;
        tlv.set_type(SrsRtcNativeMiniSDP::SrsRTCNativeType_audio_media);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer audioBuffer((char*)tmp, sizeof(tmp));
        if(srs_success != (err = audio->encode(&audioBuffer))) {
            return srs_error_wrap(err, "encode audio media");
        }
        tlv.set_value(audioBuffer.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode audio media tlv format");
        }
    }

    // encode video media
    for(vector<SrsRtcNativeVideoMediaParam*>::iterator it = video_medias_.begin(); it != video_medias_.end(); ++it) {
        SrsRtcNativeVideoMediaParam* video = *it;
        tlv.set_type(SrsRtcNativeMiniSDP::SrsRTCNativeType_video_media);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer videoBuffer((char*)tmp, sizeof(tmp));
        if(srs_success != (err = video->encode(&videoBuffer))) {
            return srs_error_wrap(err, "encode video media");
        }
        tlv.set_value(videoBuffer.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode video media tlv format");
        }
    }
    return err;
}

SrsRtcNativeCommonMediaParam::SrsRtcNativeCommonMediaParam(): sdp_version_(1), rtx_(NULL), cascade_media_(false)
{
}

SrsRtcNativeCommonMediaParam::~SrsRtcNativeCommonMediaParam()
{
    if(NULL != rtx_) {
        delete rtx_;
        rtx_ = NULL;
    }
}

const uint8_t SrsRtcNativeCommonMediaParam::get_sdp_version() const
{
    return sdp_version_;
}

vector<struct SrsRtcNativeCommonMediaParam::SrsRtcNativeRTPExtension>& SrsRtcNativeCommonMediaParam::get_rtp_extension()
{
    return rtp_extension_;
}

const srs_error_t SrsRtcNativeCommonMediaParam::get_rtx_padding(uint8_t& pt, uint32_t& ssrc) const
{
    if(NULL == rtx_) {
        return srs_error_new(ERROR_RTC_NATIVE_NO_PARAM, "no rtx");
    }
    pt = rtx_->pt;
    ssrc = rtx_->ssrc;
    return srs_success;
}

void SrsRtcNativeCommonMediaParam::set_sdp_version(const uint8_t ver)
{
    sdp_version_ = ver;
}

void SrsRtcNativeCommonMediaParam::add_rtp_extension(const uint8_t type, const uint8_t id)
{
    SrsRtcNativeCommonMediaParam::SrsRtcNativeRTPExtension ext;
    ext.type = type;
    ext.id = id;
    rtp_extension_.push_back(ext);
}
 
void SrsRtcNativeCommonMediaParam::set_rtx(const uint8_t pt, const uint32_t ssrc)
{
    if(NULL == rtx_) {
        rtx_ = new SrsRtcNativeCommonMediaParam::SrsRtcNativeRTXPadding;
    }
    rtx_->pt = pt;
    rtx_->ssrc = ssrc;
}

srs_error_t SrsRtcNativeCommonMediaParam::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    
    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRtcNativeCommonMediaParam::SrsRTCNativeType_version == tlv.get_type()) {
            sdp_version_ = *tlv.get_value();
        } else if(SrsRtcNativeCommonMediaParam::SrsRTCNativeType_extension == tlv.get_type()) {
            uint8_t* p = tlv.get_value();
            int ext_count = tlv.get_len() / 2;
            for(int i = 0; i < ext_count; ++i) {
                struct SrsRtcNativeCommonMediaParam::SrsRtcNativeRTPExtension ext;
                ext.type = *p++;
                ext.id = *p++;
                rtp_extension_.push_back(ext);
            }
        } else if(SrsRtcNativeCommonMediaParam::SrsRTCNativeType_srtp_param == tlv.get_type()) {
            srs_warn("not support srtp param");
        } else if(SrsRtcNativeCommonMediaParam::SrsRTCNativeType_rtx_padding == tlv.get_type()) {
            if(NULL == rtx_) {
                rtx_ = new SrsRtcNativeCommonMediaParam::SrsRtcNativeRTXPadding;
            }
            uint8_t* p = tlv.get_value();
            rtx_->pt = *p++;
            rtx_->ssrc = *((uint32_t*)p);
        } else {
            srs_warn("CommonMediaParam, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeCommonMediaParam::nb_bytes()
{
    int len = 0;
    len += 3 + sizeof(sdp_version_);
    
    if(!rtp_extension_.empty()) {
        len += 3 + rtp_extension_.size() * sizeof(struct SrsRtcNativeCommonMediaParam::SrsRtcNativeRTPExtension);
    }

    if(NULL != rtx_) {
        len += 3 + sizeof(struct SrsRtcNativeCommonMediaParam::SrsRtcNativeRTXPadding);
    }

    return len;
}

srs_error_t SrsRtcNativeCommonMediaParam::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_BUF_SIZE, "invalid buffer size %d", buffer->left());
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // sdp version
    tlv.set_type(SrsRtcNativeCommonMediaParam::SrsRTCNativeType_version);
    tlv.set_value(sizeof(sdp_version_), &sdp_version_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode sdp version");
    }

    // rtp extension
    if(!rtp_extension_.empty()) {
        tlv.set_type(SrsRtcNativeCommonMediaParam::SrsRTCNativeType_extension);
        memset(tmp, 0, sizeof(tmp));
        uint8_t* p = tmp;
        for(vector<SrsRtcNativeCommonMediaParam::SrsRtcNativeRTPExtension>::iterator it = rtp_extension_.begin(); 
            it != rtp_extension_.end(); ++it) {
            *p++ = it->type;
            *p++ = it->id;
        }
        tlv.set_value(rtp_extension_.size() * 2, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode rtp extension");
        }
    }

    // rtx padding
    if(NULL != rtx_) {
        tlv.set_type(SrsRtcNativeCommonMediaParam::SrsRTCNativeType_rtx_padding);
        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, &rtx_->pt, sizeof(rtx_->pt));
        uint32_t ssrc = htonl(rtx_->ssrc);
        memcpy(tmp+1, &ssrc, sizeof(ssrc));
        tlv.set_value(sizeof(SrsRtcNativeCommonMediaParam::SrsRtcNativeRTXPadding), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode rtx padding. pt: %d, ssrc: %d", rtx_->pt, rtx_->ssrc);
        }
    }

    return err;
}

SrsRtcNativeSessionParam::SrsRtcNativeSessionParam(): sdk_version_(0), port_302_(0), media_param_(NULL)
{
}

SrsRtcNativeSessionParam::~SrsRtcNativeSessionParam()
{
    if(NULL != media_param_) {
        delete media_param_;
        media_param_ = NULL;
    }
}

const string& SrsRtcNativeSessionParam::get_cookie() const
{
    return cookie_;
}

const uint32_t SrsRtcNativeSessionParam::get_sdk_version() const
{
    return sdk_version_;
}

const string& SrsRtcNativeSessionParam::get_302_ip() const
{
    return ip_302_;
}

const uint16_t SrsRtcNativeSessionParam::get_302_port() const
{
    return port_302_;
}

const string& SrsRtcNativeSessionParam::get_302_url() const
{
    return url_302_;
}

SrsRtcNativeCommonMediaParam *SrsRtcNativeSessionParam::get_media_param()
{
    if(NULL == media_param_) {
        media_param_ = new SrsRtcNativeCommonMediaParam();
    }

    return media_param_;
}

void SrsRtcNativeSessionParam::set_cookie(const std::string& cookie)
{
    cookie_ = cookie;
}

void SrsRtcNativeSessionParam::set_sdk_version(const uint32_t ver)
{
    sdk_version_ = ver;
}

void SrsRtcNativeSessionParam::set_302_ip(const std::string& ip)
{
    ip_302_ = ip;
}

void SrsRtcNativeSessionParam::set_302_port(const uint16_t port)
{
    port_302_ = port;
}

void SrsRtcNativeSessionParam::set_302_url(const std::string& url)
{
    url_302_ = url;
}

srs_error_t SrsRtcNativeSessionParam::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    
    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRtcNativeSessionParam::SrsRTCNativeType_sdk_version == tlv.get_type()) {
            sdk_version_ = ntohl(*((uint32_t*)tlv.get_value()));
        } else if(SrsRtcNativeSessionParam::SrsRTCNativeType_cookie == tlv.get_type()) {
            cookie_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRtcNativeSessionParam::SrsRTCNativeType_302_ip == tlv.get_type()) {
            ip_302_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRtcNativeSessionParam::SrsRTCNativeType_302_port == tlv.get_type()) {
            port_302_ = ntohs(*((uint16_t*)tlv.get_value()));
        } else if(SrsRtcNativeSessionParam::SrsRTCNativeType_302_url == tlv.get_type()) {
            url_302_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRtcNativeSessionParam::SrsRTCNativeType_common_media_param == tlv.get_type()) {
            if(NULL == media_param_) {
                media_param_ = new SrsRtcNativeCommonMediaParam();
            }
            SrsBuffer mediaBuf((char*)tlv.get_value(), tlv.get_len());
            if(srs_success != (err = media_param_->decode(&mediaBuf))) {
                return srs_error_wrap(err, "decode common media param");
            }
        } else {
            srs_warn("in session param, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeSessionParam::nb_bytes()
{
    int len = 0;
    len += 3 + sizeof(sdk_version_);
    if(!cookie_.empty()) {
        len += 3 + cookie_.length();
    }
    if(!ip_302_.empty()) {
        len += 3 + ip_302_.length();
    }
    if(0 != port_302_) {
        len += 3 + sizeof(port_302_);
    }
    if(!url_302_.empty()) {
        len += 3 + url_302_.length();
    }
    if(NULL != media_param_) {
        len += 3 + media_param_->nb_bytes();
    }

    return len;
}

srs_error_t SrsRtcNativeSessionParam::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_BUF_SIZE, "invalid buffer size %d", buffer->left());
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // sdk version
    tlv.set_type(SrsRtcNativeSessionParam::SrsRTCNativeType_sdk_version);
    uint32_t ver = htonl(sdk_version_);
    tlv.set_value(sizeof(sdk_version_), (uint8_t*)(&ver));
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode sdk version");
    }

    // cookie
    if(!cookie_.empty()) {
        tlv.set_type(SrsRtcNativeSessionParam::SrsRTCNativeType_cookie);
        tlv.set_value(cookie_.length(), (uint8_t*)cookie_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode cookie: %s", cookie_.c_str());
        }
    }

    // 302 IP
    if(!ip_302_.empty()) {
        tlv.set_type(SrsRtcNativeSessionParam::SrsRTCNativeType_302_ip);
        tlv.set_value(ip_302_.length(), (uint8_t*)ip_302_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode 302 ip: %s", ip_302_.c_str());
        }
    }

    // 302 Port
    if(0 != port_302_) {
        tlv.set_type(SrsRtcNativeSessionParam::SrsRTCNativeType_302_port);
        uint16_t port = htons(port_302_);
        tlv.set_value(sizeof(port_302_), (uint8_t*)(&port));
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode 302 port: %d", port_302_);
        }
    }

    // 302 URL
    if(!url_302_.empty()) {
        tlv.set_type(SrsRtcNativeSessionParam::SrsRTCNativeType_302_url);
        tlv.set_value(url_302_.length(), (uint8_t*)url_302_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode 302 url: %s", url_302_.c_str());
        }
    }

    if(NULL != media_param_) {
        SrsBuffer mediaBuff((char*)tmp, sizeof(tmp));
        if(srs_success != (err = media_param_->encode(&mediaBuff))) {
            return srs_error_wrap(err, "encode common media param");
        }
        tlv.set_type(SrsRtcNativeSessionParam::SrsRTCNativeType_common_media_param);
        tlv.set_value(mediaBuff.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "common media param tlv");
        }
    }

    return err;
}

SrsRtcNativeCascadePath::SrsRtcNativeCascadePath()
        : idx_(0),port_(0)
{
}

SrsRtcNativeCascadePath::~SrsRtcNativeCascadePath()
{
}

srs_error_t SrsRtcNativeCascadePath::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    
    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRtcNativeCascadePath::SrsRTCNativeType_idx == tlv.get_type()) {
            idx_ = *(tlv.get_value());
        } else if(SrsRtcNativeCascadePath::SrsRTCNativeType_ip == tlv.get_type()) {
            ip_ = std::string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRtcNativeCascadePath::SrsRTCNativeType_port == tlv.get_type()) {
            port_ = ntohs(*((uint16_t*)tlv.get_value()));
        } else if(SrsRtcNativeCascadePath::SrsRTCNativeType_vip == tlv.get_type()) {
            std::string vip = std::string((char*)tlv.get_value(), tlv.get_len());
            vips_.push_back(vip);
        } else if(SrsRtcNativeCascadePath::SrsRTCNativeType_region == tlv.get_type()) {
            region_ = std::string((char*)tlv.get_value(), tlv.get_len());
        } else {
            srs_warn("in session param, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeCascadePath::nb_bytes()
{
    int len = 0;
    len += 3 + sizeof(idx_);
    if(0 != port_) {
        len += 3 + sizeof(port_);
    }
    if(!ip_.empty()) {
        len += 3 + ip_.length();
    }
    if(!region_.empty()) {
        len += 3 + region_.length();
    }

    for (std::vector<std::string>::iterator it= vips_.begin(); it != vips_.end(); ++it) {
        len += 3 + (*it).length();
    }

    return len;
}

srs_error_t SrsRtcNativeCascadePath::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_BUF_SIZE, "invalid buffer size %d", buffer->left());
    }

    SrsTLV tlv;

    // path index
    tlv.set_type(SrsRtcNativeCascadePath::SrsRTCNativeType_idx);
    tlv.set_value(sizeof(idx_), &idx_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode path index");
    }

    // ip_
    if(!ip_.empty()) {
        tlv.set_type(SrsRtcNativeCascadePath::SrsRTCNativeType_ip);
        tlv.set_value(ip_.length(), (uint8_t*)ip_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode ip: %s", ip_.c_str());
        }
    }

    // port_
    if(0 != port_) {
        tlv.set_type(SrsRtcNativeCascadePath::SrsRTCNativeType_port);
        uint16_t port = htons(port_);
        tlv.set_value(sizeof(port), (uint8_t*)(&port));
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode port: %u", port_);
        }
    }

    // region_
    if(!region_.empty()) {
        tlv.set_type(SrsRtcNativeCascadePath::SrsRTCNativeType_region);
        tlv.set_value(region_.length(), (uint8_t*)region_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode region: %s", region_.c_str());
        }
    }

    // vips_
    for (std::vector<std::string>::iterator it= vips_.begin(); it != vips_.end(); ++it) {
        std::string vip = *it;
        tlv.set_type(SrsRtcNativeCascadePath::SrsRTCNativeType_vip);
        tlv.set_value(vip.length(), (uint8_t*)vip.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode vip : %s", vip.c_str());
        }
    }

    return err;
}

SrsRtcNativeTenfoldConfig::SrsRtcNativeTenfoldConfig(): mode_(0)
{
}

SrsRtcNativeTenfoldConfig::~SrsRtcNativeTenfoldConfig()
{
    std::vector<SrsRtcNativeCascadePath*>::iterator it;
    for (it = paths_.begin(); it != paths_.end(); ++it) {
        srs_freep(*it);
    }
    paths_.clear();
}

const std::vector<SrsRtcNativeCascadePath*>& SrsRtcNativeTenfoldConfig::get_paths() const
{
    return paths_;
}

void SrsRtcNativeTenfoldConfig::append_path(SrsRtcNativeCascadePath * cascade_path)
{
    if (cascade_path) {
        paths_.push_back(cascade_path);
    }
}

srs_error_t SrsRtcNativeTenfoldConfig::decode(SrsBuffer *buffer)
{
     srs_error_t err = srs_success;
    
    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRtcNativeTenfoldConfig::SrsRTCNativeType_mode == tlv.get_type()) {
            mode_ = *(tlv.get_value());
        } else if(SrsRtcNativeTenfoldConfig::SrsRTCNativeType_cascade_path == tlv.get_type()) {
            SrsBuffer path_buf((char*)tlv.get_value(), tlv.get_len());
            SrsRtcNativeCascadePath *path = new SrsRtcNativeCascadePath();
            if(srs_success != (err = path->decode(&path_buf))) {
                srs_freep(path);
                return srs_error_wrap(err, "decode cascade path");
            }
            paths_.push_back(path);
        } else {
            srs_warn("tenfold config, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeTenfoldConfig::nb_bytes()
{
    int len = 0;
    len += 3 + sizeof(mode_);

    std::vector<SrsRtcNativeCascadePath*>::iterator it;
    for (it = paths_.begin(); it != paths_.end(); ++it) {
        len += 3 + (*it)->nb_bytes();
    }

    return len;
}

srs_error_t SrsRtcNativeTenfoldConfig::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_BUF_SIZE, "invalid buffer size %d", buffer->left());
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // mode_
    tlv.set_type(SrsRtcNativeTenfoldConfig::SrsRTCNativeType_mode);
    tlv.set_value(sizeof(mode_), &mode_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode mode");
    }

    std::vector<SrsRtcNativeCascadePath*>::iterator it;
    for (it = paths_.begin(); it != paths_.end(); ++it) {
        SrsRtcNativeCascadePath *path = *it;
        SrsBuffer path_buf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = path->encode(&path_buf))) {
            return srs_error_wrap(err, "encode cascade path");
        }
        tlv.set_type(SrsRtcNativeTenfoldConfig::SrsRTCNativeType_cascade_path);
        tlv.set_value(path_buf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode cascade path");
        }
    }

    return err;
}

SrsRtcNativePublishRequest::SrsRtcNativePublishRequest(): mini_sdp_(NULL), mode_(0), session_param_(NULL)
{
    msg_type_ = SrsRTCNativeMsgType_request;
}

SrsRtcNativePublishRequest::~SrsRtcNativePublishRequest()
{
    if(NULL != mini_sdp_) {
        delete mini_sdp_;
        mini_sdp_ = NULL;
    }
    if(NULL != session_param_) {
        delete session_param_;
        session_param_ = NULL;
    }
}

const string& SrsRtcNativePublishRequest::get_url() const
{
    return url_;
}

SrsRtcNativeMiniSDP* SrsRtcNativePublishRequest::get_sdp()
{
    if(NULL == mini_sdp_) {
        mini_sdp_ = new SrsRtcNativeMiniSDP();
    }
    return mini_sdp_;
}

const uint8_t SrsRtcNativePublishRequest::get_mode() const
{
    return mode_;
}

SrsRtcNativeSessionParam* SrsRtcNativePublishRequest::get_session_param()
{
    if(NULL == session_param_) {
        session_param_ = new SrsRtcNativeSessionParam();
    }
    return session_param_;
}

void SrsRtcNativePublishRequest::set_url(std::string url)
{
    url_ = url;
}

void SrsRtcNativePublishRequest::set_mode(uint8_t mode)
{
    mode_ = mode;
}

srs_error_t SrsRtcNativePublishRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {   
        return srs_error_wrap(err, "fail to decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_url == tlv.get_type()) {
            url_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_minisdp == tlv.get_type()) {
            SrsBuffer miniBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == mini_sdp_) {
                mini_sdp_ = new SrsRtcNativeMiniSDP();
            }
            if(srs_success != (err = mini_sdp_->decode(&miniBuf))) {
                return srs_error_wrap(err, "decode mini sdp");
            }
        } else if(SrsRTCNativeType_mode == tlv.get_type()) {
            mode_ = *tlv.get_value();
        } else if(SrsRTCNativeType_session_param == tlv.get_type()) {
          SrsBuffer sessionBuf((char*)tlv.get_value(), tlv.get_len());
          if(NULL == session_param_) {
              session_param_ = new SrsRtcNativeSessionParam();
          }  
          if(srs_success != (err = session_param_->decode(&sessionBuf))) {
              return srs_error_wrap(err, "decode session param");
          }
        } else {
            srs_warn("Publish request, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativePublishRequest::nb_bytes()
{
    int len  = 0;
    len += SrsRtcNativeHeader::nb_bytes();
    len += 3 + url_.length();
    if(NULL != mini_sdp_) {
        len += 3 + mini_sdp_->nb_bytes();
    }
    len += 3 + sizeof(mode_);
    if(NULL != session_param_) {
        len += 3 + session_param_->nb_bytes();
    }
    return len;
}

srs_error_t SrsRtcNativePublishRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode url
    tlv.set_type(SrsRTCNativeType_url);
    tlv.set_value(url_.length(), (uint8_t*)url_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode url: %s", url_.c_str());
    }

    // mode
    tlv.set_type(SrsRTCNativeType_mode);
    tlv.set_value(sizeof(mode_), &mode_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode mode: %d", mode_);
    }
    

    // miniSDP
    if(NULL != mini_sdp_) {
        tlv.set_type(SrsRTCNativeType_minisdp);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sdpBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = mini_sdp_->encode(&sdpBuf))) {
            return srs_error_wrap(err, "encode mini sdp");
        }
        tlv.set_value(sdpBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode mini sdp tlv");
        }
    }

    // session param
    if(NULL != session_param_) {
        tlv.set_type(SrsRTCNativeType_session_param);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sessionBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = session_param_->encode(&sessionBuf))) {
            return srs_error_wrap(err, "encode session param");
        }
        tlv.set_value(sessionBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode session param tlv");
        }
    }

    return err;
}

SrsRtcNativePublishResponse::SrsRtcNativePublishResponse(): code_(0), mini_sdp_(NULL), session_param_(NULL)
{
    msg_type_ = SrsRTCNativeMsgType_final_resp;
}

SrsRtcNativePublishResponse::~SrsRtcNativePublishResponse()
{
    if(NULL != mini_sdp_) {
        delete mini_sdp_;
        mini_sdp_ = NULL;
    }
    if(NULL != session_param_) {
        delete session_param_;
        session_param_ = NULL;
    }
}

SrsRtcNativeMiniSDP* SrsRtcNativePublishResponse::get_sdp()
{
    if(NULL == mini_sdp_) {
        mini_sdp_ = new SrsRtcNativeMiniSDP();
    }
    return mini_sdp_;
}

SrsRtcNativeSessionParam* SrsRtcNativePublishResponse::get_session_param()
{
    if(NULL == session_param_) {
        session_param_ = new SrsRtcNativeSessionParam();
    }
    return session_param_;
}

const uint16_t SrsRtcNativePublishResponse::get_code() const
{
    return code_;
}

const string& SrsRtcNativePublishResponse::get_msg() const
{
    return msg_;
}

const string& SrsRtcNativePublishResponse::get_pub_config() const
{
    return pub_config_;
}

const string& SrsRtcNativePublishResponse::get_trace_id() const
{
    return trace_id_;
}

void SrsRtcNativePublishResponse::set_code(uint16_t code)
{
    code_ = code;
}

void SrsRtcNativePublishResponse::set_msg(std::string& msg)
{
    msg_ = msg;
}

void SrsRtcNativePublishResponse::set_pub_config(std::string& config)
{
    pub_config_ = config;
}

void SrsRtcNativePublishResponse::set_trace_id(std::string& id)
{
    trace_id_ = id;
}

srs_error_t SrsRtcNativePublishResponse::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_code == tlv.get_type()) {
            code_ = ntohs(*((uint16_t*)tlv.get_value()));
            srs_info("pub response: code %d", code_);
        } else if(SrsRTCNativeType_minisdp == tlv.get_type()) {
            SrsBuffer miniBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == mini_sdp_) {
                mini_sdp_ = new SrsRtcNativeMiniSDP();
            }
            if(srs_success != (err = mini_sdp_->decode(&miniBuf))) {
                return srs_error_wrap(err, "decode mini sdp");
            }
            srs_info("pub response: minisdp");
        } else if(SrsRTCNativeType_msg == tlv.get_type()) {
            msg_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_session_param == tlv.get_type()) {
            SrsBuffer sessionBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == session_param_) {
                session_param_ = new SrsRtcNativeSessionParam();
            }  
            if(srs_success != (err = session_param_->decode(&sessionBuf))) {
                return srs_error_wrap(err, "decode session param");
            }
        } else if(SrsRTCNativeType_traceid == tlv.get_type()) {
            trace_id_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_pub_config == tlv.get_type()) {
            pub_config_ = string((char*)tlv.get_value(), tlv.get_len());
        } else {
            srs_warn("publish response, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativePublishResponse::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(code_);
    if(NULL != mini_sdp_) {
        len += 3 + mini_sdp_->nb_bytes();
    }
    if(!msg_.empty()) {
        len += 3 + msg_.length();
    }
    if(NULL != session_param_) {
        len += 3 + session_param_->nb_bytes();
    }
    if(!trace_id_.empty()) {
        len += 3 + trace_id_.length();
    }
    if(!pub_config_.empty()) {
        len += 3 + pub_config_.length();
    }
    return len;
}

srs_error_t SrsRtcNativePublishResponse::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode code
    tlv.set_type(SrsRTCNativeType_code);
    uint16_t code = htons(code_);
    tlv.set_value(sizeof(code_), (uint8_t*)&code);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode code: %d", code_);
    }

    if(!msg_.empty()) {
        // encode msg
        tlv.set_type(SrsRTCNativeType_msg);
        tlv.set_value(msg_.length(), (uint8_t*)msg_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msg: %s", msg_.c_str());
        }
    }

    // miniSDP
    if(NULL != mini_sdp_) {
        tlv.set_type(SrsRTCNativeType_minisdp);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sdpBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = mini_sdp_->encode(&sdpBuf))) {
            return srs_error_wrap(err, "encode mini sdp");
        }
        tlv.set_value(sdpBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode mini sdp tlv");
        }
    }

    // session param
    if(NULL != session_param_) {
        tlv.set_type(SrsRTCNativeType_session_param);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sessionBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = session_param_->encode(&sessionBuf))) {
            return srs_error_wrap(err, "encode session param");
        }
        tlv.set_value(sessionBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode session param tlv");
        }
    }

    if(!trace_id_.empty()) {
        tlv.set_type(SrsRTCNativeType_traceid);
        tlv.set_value(trace_id_.length(), (uint8_t*)trace_id_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode trace id tlv : %s", trace_id_.c_str());
        }
    }

    if(!pub_config_.empty()) {
        tlv.set_type(SrsRTCNativeType_pub_config);
        tlv.set_value(pub_config_.length(), (uint8_t*)pub_config_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode pub config tlv: %s", pub_config_.c_str());
        }
    }

    return err;
}

SrsRtcNativeSubscribeRequest::SrsRtcNativeSubscribeRequest():mini_sdp_(0), mode_(0), session_param_(NULL)
{
    msg_type_ = SrsRTCNativeMsgType_request;
    tenfold_config_ = NULL;
}

SrsRtcNativeSubscribeRequest::~SrsRtcNativeSubscribeRequest()
{
    if(NULL != mini_sdp_) {
        delete mini_sdp_;
        mini_sdp_ = NULL;
    }
    if(NULL != session_param_) {
        delete session_param_;
        session_param_ = NULL;
    }
}

const string& SrsRtcNativeSubscribeRequest::get_url() const
{
    return url_;
}

const vector<string>& SrsRtcNativeSubscribeRequest::get_msid() const
{
    return msids_;
}

SrsRtcNativeMiniSDP* SrsRtcNativeSubscribeRequest::get_sdp()
{
    if(NULL == mini_sdp_) {
        mini_sdp_ = new SrsRtcNativeMiniSDP();
    }
    return mini_sdp_;
}

const uint8_t SrsRtcNativeSubscribeRequest::get_mode() const
{
    return mode_;
}

SrsRtcNativeSessionParam* SrsRtcNativeSubscribeRequest::get_session_param()
{
    if(NULL == session_param_) {
        session_param_ = new SrsRtcNativeSessionParam();
    }
    return session_param_;
}

SrsRtcNativeTenfoldConfig* SrsRtcNativeSubscribeRequest::get_tenfold_config()
{
    if (!tenfold_config_) {
        tenfold_config_ = new SrsRtcNativeTenfoldConfig();
    }
    return tenfold_config_;
}


void SrsRtcNativeSubscribeRequest::set_url(const std::string& url)
{
    url_ = url;
}

void SrsRtcNativeSubscribeRequest::add_msid(const std::string& msid)
{
    //TODO: need to filter duplication msid
    msids_.push_back(msid);
}

void SrsRtcNativeSubscribeRequest::set_mode(uint8_t mode)
{
    mode_ = mode;
}

srs_error_t SrsRtcNativeSubscribeRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_url == tlv.get_type()) {
            url_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_minisdp == tlv.get_type()) {
            SrsBuffer miniBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == mini_sdp_) {
                mini_sdp_ = new SrsRtcNativeMiniSDP();
            }
            if(srs_success != (err = mini_sdp_->decode(&miniBuf))) {
                return srs_error_wrap(err, "decode mini sdp");
            }
        } else if(SrsRTCNativeType_mode == tlv.get_type()) {
            mode_ = *tlv.get_value();
        } else if(SrsRTCNativeType_session_param == tlv.get_type()) {
          SrsBuffer sessionBuf((char*)tlv.get_value(), tlv.get_len());
          if(NULL == session_param_) {
              session_param_ = new SrsRtcNativeSessionParam();
          }  
          if(srs_success != (err = session_param_->decode(&sessionBuf))) {
              return srs_error_wrap(err, "decode session param");
          }
        } else if(SrsRTCNativeType_msid == tlv.get_type()) {
            string msid = string((char*)tlv.get_value(), tlv.get_len());
            msids_.push_back(msid);
        } else if (SrsRTCNativeType_tenfold_config == tlv.get_type()) {
            SrsBuffer config_buf((char*)tlv.get_value(), tlv.get_len());
            SrsRtcNativeTenfoldConfig *config = get_tenfold_config();
            if(srs_success != (err = config->decode(&config_buf))) {
                return srs_error_wrap(err, "decode tenfold config");
            }
        } else {
            srs_warn("Subscribe request, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeSubscribeRequest::nb_bytes()
{
    int len  = 0;
    len += SrsRtcNativeHeader::nb_bytes();
    len += 3 + url_.length();
    if(NULL != mini_sdp_) {
        len += 3 + mini_sdp_->nb_bytes();
    }
    len += 3 + sizeof(mode_);
    if(NULL != session_param_) {
        len += 3 + session_param_->nb_bytes();
    }
    if(!msids_.empty()) {
        for(vector<string>::iterator it = msids_.begin(); it != msids_.end(); ++it) {
            len += 3 + it->length();
        }
    }
    if (tenfold_config_) {
        len += 3 + tenfold_config_->nb_bytes();
    }
    return len;
}

srs_error_t SrsRtcNativeSubscribeRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode url
    tlv.set_type(SrsRTCNativeType_url);
    tlv.set_value(url_.length(), (uint8_t*)url_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode url: %s", url_.c_str());
    }

    // mode
    tlv.set_type(SrsRTCNativeType_mode);
    tlv.set_value(sizeof(mode_), &mode_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode mode: %d", mode_);
    }
    
    if(!msids_.empty()) {
        for(vector<string>::iterator it=msids_.begin(); it != msids_.end(); ++it) {
            tlv.set_type(SrsRTCNativeType_msid);
            tlv.set_value(it->length(), (uint8_t*)it->c_str());
            if(srs_success != (err = tlv.encode(buffer))) {
                return srs_error_wrap(err, "encode msid:%s", it->c_str());
            }
        }
    }

    // miniSDP
    if(NULL != mini_sdp_) {
        tlv.set_type(SrsRTCNativeType_minisdp);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sdpBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = mini_sdp_->encode(&sdpBuf))) {
            return srs_error_wrap(err, "encode mini sdp");
        }
        tlv.set_value(sdpBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode mini sdp tlv");
        }
    }

    // session param
    if(NULL != session_param_) {
        tlv.set_type(SrsRTCNativeType_session_param);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sessionBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = session_param_->encode(&sessionBuf))) {
            return srs_error_wrap(err, "encode session param");
        }
        tlv.set_value(sessionBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode session param tlv");
        }
    }

    // tenfold config
    if (NULL != tenfold_config_) {
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer config_buf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = tenfold_config_->encode(&config_buf))) {
            return srs_error_wrap(err, "encode tenfold config");
        }
        tlv.set_type(SrsRTCNativeType_tenfold_config);
        tlv.set_value(config_buf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode session param tlv");
        }
    }

    return err;
}


SrsRtcNativeSubscribeResponse::SrsRtcNativeSubscribeResponse():mini_sdp_(NULL), code_(0), session_param_(NULL)
{
    msg_type_ = SrsRTCNativeMsgType_final_resp;
}

SrsRtcNativeSubscribeResponse::~SrsRtcNativeSubscribeResponse()
{
    if(NULL != mini_sdp_) {
        delete mini_sdp_;
        mini_sdp_ = NULL;
    }
    if(NULL != session_param_) {
        delete session_param_;
        session_param_ = NULL;
    }
}


SrsRtcNativeMiniSDP* SrsRtcNativeSubscribeResponse::get_sdp()
{
    if(NULL == mini_sdp_) {
        mini_sdp_ = new SrsRtcNativeMiniSDP();
    }
    return mini_sdp_;
}

SrsRtcNativeSessionParam* SrsRtcNativeSubscribeResponse::get_session_param()
{
    if(NULL == session_param_) {
        session_param_ = new SrsRtcNativeSessionParam();
    }
    return session_param_;
}

const uint16_t SrsRtcNativeSubscribeResponse::get_code() const
{
    return code_;
}

const string& SrsRtcNativeSubscribeResponse::get_msg() const
{
    return msg_;
}

const string& SrsRtcNativeSubscribeResponse::get_play_config() const
{
    return play_config_;
}

const string& SrsRtcNativeSubscribeResponse::get_trace_id() const
{
    return trace_id_;
}

void SrsRtcNativeSubscribeResponse::set_code(uint16_t code)
{
    code_ = code;
}

void SrsRtcNativeSubscribeResponse::set_msg(std::string& msg)
{
    msg_ = msg;
}

void SrsRtcNativeSubscribeResponse::set_play_config(std::string& config)
{
    play_config_ = config;
}

void SrsRtcNativeSubscribeResponse::set_trace_id(std::string& id)
{
    trace_id_ = id;
}

srs_error_t SrsRtcNativeSubscribeResponse::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_code == tlv.get_type()) {
            code_ = ntohs(*((uint16_t*)tlv.get_value()));
        } else if(SrsRTCNativeType_minisdp == tlv.get_type()) {
            SrsBuffer miniBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == mini_sdp_) {
                mini_sdp_ = new SrsRtcNativeMiniSDP();
            }
            if(srs_success != (err = mini_sdp_->decode(&miniBuf))) {
                return srs_error_wrap(err, "decode mini sdp");
            }
        } else if(SrsRTCNativeType_msg == tlv.get_type()) {
            msg_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_session_param == tlv.get_type()) {
            SrsBuffer sessionBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == session_param_) {
                session_param_ = new SrsRtcNativeSessionParam();
            }  
            if(srs_success != (err = session_param_->decode(&sessionBuf))) {
                return srs_error_wrap(err, "decode session param");
            }
        } else if(SrsRTCNativeType_traceid == tlv.get_type()) {
            trace_id_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_play_config == tlv.get_type()) {
            play_config_ = string((char*)tlv.get_value(), tlv.get_len());
        } else {
            srs_warn("Subscribe response, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeSubscribeResponse::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(code_);
    if(NULL != mini_sdp_) {
        len += 3 + mini_sdp_->nb_bytes();
    }
    if(!msg_.empty()) {
        len += 3 + msg_.length();
    }
    if(NULL != session_param_) {
        len += 3 + session_param_->nb_bytes();
    }
    if(!trace_id_.empty()) {
        len += 3 + trace_id_.length();
    }
    if(!play_config_.empty()) {
        len += 3 + play_config_.length();
    }
    return len;
}

srs_error_t SrsRtcNativeSubscribeResponse::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode code
    tlv.set_type(SrsRTCNativeType_code);
    uint16_t code = htons(code_);
    tlv.set_value(sizeof(code_), (uint8_t*)&code);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode code: %d", code);
    }

    if(!msg_.empty()) {
        // encode msg
        tlv.set_type(SrsRTCNativeType_msg);
        tlv.set_value(msg_.length(), (uint8_t*)msg_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msg: %s", msg_.c_str());
        }
    }

    // miniSDP
    if(NULL != mini_sdp_) {
        tlv.set_type(SrsRTCNativeType_minisdp);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sdpBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = mini_sdp_->encode(&sdpBuf))) {
            return srs_error_wrap(err, "encode mini sdp");
        }
        tlv.set_value(sdpBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode mini sdp tlv");
        }
    }

    // session param
    if(NULL != session_param_) {
        tlv.set_type(SrsRTCNativeType_session_param);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sessionBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = session_param_->encode(&sessionBuf))) {
            return srs_error_wrap(err, "encode session param");
        }
        tlv.set_value(sessionBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode session param tlv");
        }
    }

    if(!trace_id_.empty()) {
        tlv.set_type(SrsRTCNativeType_traceid);
        tlv.set_value(trace_id_.length(), (uint8_t*)trace_id_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode trace id tlv: %s", trace_id_.c_str());
        }
    }

    if(!play_config_.empty()) {
        tlv.set_type(SrsRTCNativeType_pub_config);
        tlv.set_value(play_config_.length(), (uint8_t*)play_config_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode play config: %s", play_config_.c_str());
        }
    }

    return err;
}

SrsRtcNativePublishUpdateRequest::SrsRtcNativePublishUpdateRequest()
{
    msg_type_ = SrsRTCNativeMsgType_request;
    msid_cmd_.clear();
    sdp_ = NULL;
}

SrsRtcNativePublishUpdateRequest::~SrsRtcNativePublishUpdateRequest()
{
    if(NULL != sdp_) {
        srs_freep(sdp_);
        sdp_ = NULL;
    }
}
    
string& SrsRtcNativePublishUpdateRequest::get_url()
{
    return url_;
}

vector<SrsRtcNativeMsidCMD>& SrsRtcNativePublishUpdateRequest::get_msid_cmd()
{
    return msid_cmd_;
}

SrsRtcNativeMiniSDP* SrsRtcNativePublishUpdateRequest::get_sdp()
{
    if(NULL == sdp_) {
        sdp_ = new SrsRtcNativeMiniSDP();
    }
    return sdp_;
}

void SrsRtcNativePublishUpdateRequest::set_url(std::string url)
{
    url_ = url;
}

void SrsRtcNativePublishUpdateRequest::add_msid_cmd(SrsRtcNativeMsidCMD& cmd)
{
    msid_cmd_.push_back(cmd);
}

srs_error_t SrsRtcNativePublishUpdateRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_url == tlv.get_type()) {
            url_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_minisdp == tlv.get_type()) {
            SrsBuffer miniBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == sdp_) {
                sdp_ = new SrsRtcNativeMiniSDP();
            }
            if(srs_success != (err = sdp_->decode(&miniBuf))) {
                return srs_error_wrap(err, "decode mini sdp");
            }
        } else if(SrsRTCNativeType_msid_cmd == tlv.get_type()) {
            uint8_t* p = tlv.get_value();
            SrsRtcNativeMsidCMD msid_cmd;
            msid_cmd.cmd = *p;
            p++;
            msid_cmd.msid = string((char*)p, tlv.get_len() - 1);
            msid_cmd_.push_back(msid_cmd);
            srs_info("Publish update request: decode msid cmd: cmd: %d, msid: %s", msid_cmd.cmd, msid_cmd.msid.c_str());
        } else {
            srs_warn("Publish update request, unkonw type:%d", tlv.get_type());
        }
    }

    return err;  
}
    
int SrsRtcNativePublishUpdateRequest::nb_bytes()
{
    int len  = SrsRtcNativeHeader::nb_bytes();
    len += 3 + url_.length();
    // mini sdp
    if(NULL != sdp_) {
        len += 3 + sdp_->nb_bytes();
    }

    // msid cmd
    for(size_t i = 0; i < msid_cmd_.size(); ++i) {
        len += 3 + sizeof(msid_cmd_.at(i).cmd) + msid_cmd_.at(i).msid.length();
    }
    
    return len;
}

srs_error_t SrsRtcNativePublishUpdateRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }
    
    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode url
    tlv.set_type(SrsRTCNativeType_url);
    tlv.set_value(url_.length(), (uint8_t*)url_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode url: %s", url_.c_str());
    }
    
    // msid cmd
    for(size_t i =0; i < msid_cmd_.size(); ++i) {
        tlv.set_type(SrsRTCNativeType_msid_cmd);
        size_t len = msid_cmd_.at(i).msid.length() + 1;
        srs_assert(len < sizeof(tmp));
        memcpy(tmp, &msid_cmd_.at(i).cmd, 1);
        memcpy(tmp+1, msid_cmd_.at(i).msid.c_str(), msid_cmd_.at(i).msid.length());

        tlv.set_value(len, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msid:%s, cmd:%d", msid_cmd_.at(i).msid.c_str(), msid_cmd_.at(i).cmd);
        }
    }
    

    // miniSDP
    if(NULL != sdp_) {
        tlv.set_type(SrsRTCNativeType_minisdp);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sdpBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = sdp_->encode(&sdpBuf))) {
            return srs_error_wrap(err, "encode mini sdp");
        }
        tlv.set_value(sdpBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode mini sdp tlv");
        }
    }

    return err;
}

SrsRtcNativePublishUpdateResponse::SrsRtcNativePublishUpdateResponse()
{
    msg_type_ = SrsRTCNativeMsgType_final_resp;
    mini_sdp_ = NULL;
}

SrsRtcNativePublishUpdateResponse::~SrsRtcNativePublishUpdateResponse()
{
    if(NULL != mini_sdp_) {
        srs_freep(mini_sdp_);
        mini_sdp_ = NULL;
    }
}

SrsRtcNativeMiniSDP* SrsRtcNativePublishUpdateResponse::get_sdp()
{
    if(NULL == mini_sdp_) {
        mini_sdp_ = new SrsRtcNativeMiniSDP();
    }
    return mini_sdp_;
}

const uint16_t SrsRtcNativePublishUpdateResponse::get_code() const
{
    return code_;
}

const string& SrsRtcNativePublishUpdateResponse::get_msg() const
{
    return msg_;
}

std::vector<std::string>& SrsRtcNativePublishUpdateResponse::get_msid()
{
    return msids_;
}
    
void SrsRtcNativePublishUpdateResponse::set_code(uint16_t code)
{
    code_ = code;
}

void SrsRtcNativePublishUpdateResponse::set_msg(std::string& msg)
{
    msg_ = msg;
}

void SrsRtcNativePublishUpdateResponse::add_msid(std::string& msid)
{
    if(msid.empty()) {
        return;
    }
    msids_.push_back(msid);
}

srs_error_t SrsRtcNativePublishUpdateResponse::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "fail to decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_code == tlv.get_type()) {
            code_ = ntohs(*((uint16_t*)tlv.get_value()));
        } else if(SrsRTCNativeType_minisdp == tlv.get_type()) {
            SrsBuffer miniBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == mini_sdp_) {
                mini_sdp_ = new SrsRtcNativeMiniSDP();
            }
            if(srs_success != (err = mini_sdp_->decode(&miniBuf))) {
                return srs_error_wrap(err, "decode mini sdp");
            }
        } else if(SrsRTCNativeType_msg == tlv.get_type()) {
            msg_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_msid == tlv.get_type()) {
            string msid = string((char*)tlv.get_value(), tlv.get_len());
            msids_.push_back(msid);
        } else {
            srs_warn("Publish update response, unkonw type:%d", tlv.get_type());
        }
    }

    return err;   
}

int SrsRtcNativePublishUpdateResponse::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(code_);
    if(NULL != mini_sdp_) {
        len += 3 + mini_sdp_->nb_bytes();
    }
    if(!msg_.empty()) {
        len += 3 + msg_.length();
    }
    if(!msids_.empty()) {
        for(vector<string>::iterator it = msids_.begin(); it != msids_.end(); ++it) {
            len += 3 + it->length();
        }
    }
    return len;
}

srs_error_t SrsRtcNativePublishUpdateResponse::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode code
    tlv.set_type(SrsRTCNativeType_code);
    uint16_t code = htons(code_);
    tlv.set_value(sizeof(code_), (uint8_t*)&code);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode code: %d", code_);
    }

    if(!msg_.empty()) {
        // encode msg
        tlv.set_type(SrsRTCNativeType_msg);
        tlv.set_value(msg_.length(), (uint8_t*)msg_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msg: %s", msg_.c_str());
        }
    }

    // miniSDP
    if(NULL != mini_sdp_) {
        tlv.set_type(SrsRTCNativeType_minisdp);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sdpBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = mini_sdp_->encode(&sdpBuf))) {
            return srs_error_wrap(err, "encode mini sdp");
        }
        tlv.set_value(sdpBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode mini sdp tlv");
        }
    }

     if(!msids_.empty()) {
        for(vector<string>::iterator it=msids_.begin(); it != msids_.end(); ++it) {
            tlv.set_type(SrsRTCNativeType_msid);
            tlv.set_value(it->length(), (uint8_t*)it->c_str());
            if(srs_success != (err = tlv.encode(buffer))) {
                return srs_error_wrap(err, "encode msid:%s", it->c_str());
            }
        }
    }

    return err;
}

SrsRtcNativeSubscribeUpdateRequest::SrsRtcNativeSubscribeUpdateRequest()
{
    msg_type_ = SrsRTCNativeMsgType_request;
    msid_cmd_.clear();
    sdp_ = NULL;
}
 
SrsRtcNativeSubscribeUpdateRequest::~SrsRtcNativeSubscribeUpdateRequest()
{
    if(NULL != sdp_) {
        srs_freep(sdp_);
        sdp_ = NULL;
    }
}

string& SrsRtcNativeSubscribeUpdateRequest::get_url()
{
    return url_;
}

vector<SrsRtcNativeMsidCMD>& SrsRtcNativeSubscribeUpdateRequest::get_msid_cmd()
{
    return msid_cmd_;
}

SrsRtcNativeMiniSDP* SrsRtcNativeSubscribeUpdateRequest::get_sdp()
{
    if(NULL == sdp_) {
        sdp_ = new SrsRtcNativeMiniSDP();
    }
    return sdp_;
}

void SrsRtcNativeSubscribeUpdateRequest::set_url(std::string url)
{
    url_ = url;
}

void SrsRtcNativeSubscribeUpdateRequest::add_msid_cmd(SrsRtcNativeMsidCMD& cmd)
{
    msid_cmd_.push_back(cmd);
}

srs_error_t SrsRtcNativeSubscribeUpdateRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_url == tlv.get_type()) {
            url_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_minisdp == tlv.get_type()) {
            SrsBuffer miniBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == sdp_) {
                sdp_ = new SrsRtcNativeMiniSDP();
            }
            if(srs_success != (err = sdp_->decode(&miniBuf))) {
                return srs_error_wrap(err, "decode mini sdp");
            }
        } else if(SrsRTCNativeType_msid_cmd == tlv.get_type()) {
            uint8_t* p = tlv.get_value();
            SrsRtcNativeMsidCMD msid_cmd;
            msid_cmd.cmd = *p;
            p++;
            msid_cmd.msid = string((char*)p, tlv.get_len() - 1);
            msid_cmd_.push_back(msid_cmd);
            srs_info("Subscribe update request, decode msid_cmd: cmd: %d, msid: %s",
                msid_cmd.cmd, msid_cmd.msid.c_str());
        } else {
            srs_warn("Subscribe update request, unkonw type:%d", tlv.get_type());
        }
    }

    return err; 
}

int SrsRtcNativeSubscribeUpdateRequest::nb_bytes()
{
    int len  = SrsRtcNativeHeader::nb_bytes();
    len += 3 + url_.length();
    // mini sdp
    if(NULL != sdp_) {
        len += 3 + sdp_->nb_bytes();
    }

    // msid cmd
    for(size_t i = 0; i < msid_cmd_.size(); ++i) {
        len += 3 + sizeof(msid_cmd_.at(i).cmd) + msid_cmd_.at(i).msid.length();
    }
    return len;
}

srs_error_t SrsRtcNativeSubscribeUpdateRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }
    
    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode url
    tlv.set_type(SrsRTCNativeType_url);
    tlv.set_value(url_.length(), (uint8_t*)url_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode url: %s", url_.c_str());
    }
    
    // msid cmd
    for(size_t i =0; i < msid_cmd_.size(); ++i) {
        tlv.set_type(SrsRTCNativeType_msid_cmd);
        size_t len = msid_cmd_.at(i).msid.length() + 1;
        srs_assert(len < sizeof(tmp));
        memcpy(tmp, &msid_cmd_.at(i).cmd, 1);
        memcpy(tmp+1, msid_cmd_.at(i).msid.c_str(), msid_cmd_.at(i).msid.length());

        tlv.set_value(len, tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msid:%s, cmd:%d", msid_cmd_.at(i).msid.c_str(), msid_cmd_.at(i).cmd);
        }
    }
    

    // miniSDP
    if(NULL != sdp_) {
        tlv.set_type(SrsRTCNativeType_minisdp);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sdpBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = sdp_->encode(&sdpBuf))) {
            return srs_error_wrap(err, "encode mini sdp");
        }
        tlv.set_value(sdpBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode mini sdp tlv");
        }
    }

    return err;
}


SrsRtcNativeSubscribeUpdateResponse::SrsRtcNativeSubscribeUpdateResponse()
{
    msg_type_ = SrsRTCNativeMsgType_final_resp;
    mini_sdp_ = NULL;
}

SrsRtcNativeSubscribeUpdateResponse::~SrsRtcNativeSubscribeUpdateResponse()
{
    if(NULL != mini_sdp_) {
        srs_freep(mini_sdp_);
        mini_sdp_ = NULL;
    }
}

SrsRtcNativeMiniSDP* SrsRtcNativeSubscribeUpdateResponse::get_sdp()
{
    if(NULL == mini_sdp_) {
        mini_sdp_ = new SrsRtcNativeMiniSDP();
    }
    return mini_sdp_;
}

const uint16_t SrsRtcNativeSubscribeUpdateResponse::get_code() const
{
    return code_;
}

const string& SrsRtcNativeSubscribeUpdateResponse::get_msg() const
{
    return msg_;
}

std::vector<std::string>& SrsRtcNativeSubscribeUpdateResponse::get_msid()
{
    return msids_;
}
    
void SrsRtcNativeSubscribeUpdateResponse::set_code(uint16_t code)
{
    code_ = code;
}

void SrsRtcNativeSubscribeUpdateResponse::set_msg(std::string& msg)
{
    msg_ = msg;
}

void SrsRtcNativeSubscribeUpdateResponse::add_msid(std::string& msid)
{
    if(msid.empty()) {
        return;
    }
    msids_.push_back(msid);
}

srs_error_t SrsRtcNativeSubscribeUpdateResponse::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_code == tlv.get_type()) {
            code_ = ntohs(*((uint16_t*)tlv.get_value()));
        } else if(SrsRTCNativeType_minisdp == tlv.get_type()) {
            SrsBuffer miniBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == mini_sdp_) {
                mini_sdp_ = new SrsRtcNativeMiniSDP();
            }
            if(srs_success != (err = mini_sdp_->decode(&miniBuf))) {
                return srs_error_wrap(err, "decode mini sdp");
            }
        } else if(SrsRTCNativeType_msg == tlv.get_type()) {
            msg_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_msid == tlv.get_type()) {
            string msid = string((char*)tlv.get_value(), tlv.get_len());
            msids_.push_back(msid);
        } else {
            srs_warn("Subscribe update response, unkonw type:%d", tlv.get_type());
        }
    }

    return err;   
}

int SrsRtcNativeSubscribeUpdateResponse::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(code_);
    if(NULL != mini_sdp_) {
        len += 3 + mini_sdp_->nb_bytes();
    }
    if(!msg_.empty()) {
        len += 3 + msg_.length();
    }
    if(!msids_.empty()) {
        for(vector<string>::iterator it = msids_.begin(); it != msids_.end(); ++it) {
            len += 3 + it->length();
        }
    }
    return len;
}

srs_error_t SrsRtcNativeSubscribeUpdateResponse::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode code
    tlv.set_type(SrsRTCNativeType_code);
    uint16_t code = htons(code_);
    tlv.set_value(sizeof(code_), (uint8_t*)&code);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode code: %d", code_);
    }

    if(!msg_.empty()) {
        // encode msg
        tlv.set_type(SrsRTCNativeType_msg);
        tlv.set_value(msg_.length(), (uint8_t*)msg_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msg: %s", msg_.c_str());
        }
    }

    // miniSDP
    if(NULL != mini_sdp_) {
        tlv.set_type(SrsRTCNativeType_minisdp);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sdpBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = mini_sdp_->encode(&sdpBuf))) {
            return srs_error_wrap(err, "encode mini sdp");
        }
        tlv.set_value(sdpBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode mini sdp tlv");
        }
    }

     if(!msids_.empty()) {
        for(vector<string>::iterator it=msids_.begin(); it != msids_.end(); ++it) {
            tlv.set_type(SrsRTCNativeType_msid);
            tlv.set_value(it->length(), (uint8_t*)it->c_str());
            if(srs_success != (err = tlv.encode(buffer))) {
                return srs_error_wrap(err, "encode msid:%s", it->c_str());
            }
        }
    }

    return err;
}

SrsRtcNativeCommonResponse::SrsRtcNativeCommonResponse(): code_(0)
{
    msg_type_ = SrsRTCNativeMsgType_final_resp;
}

SrsRtcNativeCommonResponse::~SrsRtcNativeCommonResponse()
{
}


const uint16_t SrsRtcNativeCommonResponse::get_code() const
{
    return code_;
}

const string& SrsRtcNativeCommonResponse::get_msg() const
{
    return msg_;
}

void SrsRtcNativeCommonResponse::set_code(uint16_t code)
{
    code_= code;
}

void SrsRtcNativeCommonResponse::set_msg(const std::string& msg)
{
    msg_ = msg;
}

srs_error_t SrsRtcNativeCommonResponse::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_code == tlv.get_type()) {
            code_ = ntohs(*((uint16_t*)tlv.get_value()));
        } else if(SrsRTCNativeType_msg == tlv.get_type()) {
            msg_ = string((char*)tlv.get_value(), tlv.get_len());
        } else {
            srs_warn("in SrsRtcNativeHeartbeatResponse, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeCommonResponse::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(code_);
    if(!msg_.empty()) {
        len += 3 + msg_.length();
    }
    return len;
}

srs_error_t SrsRtcNativeCommonResponse::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    SrsTLV tlv;

    // encode code
    tlv.set_type(SrsRTCNativeType_code);
    uint16_t code = htons(code_);
    tlv.set_value(sizeof(code_), (uint8_t*)&code);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode code: %s", code_);
    }

    if(!msg_.empty()) {
        // encode msg
        tlv.set_type(SrsRTCNativeType_msg);
        tlv.set_value(msg_.length(), (uint8_t*)msg_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msg: %s", msg_.c_str());
        }
    }

    return err;
}

SrsRtcNativeStopRequest::SrsRtcNativeStopRequest(): code_(0)
{
    msg_type_ = SrsRTCNativeMsgType_request;
}
    
SrsRtcNativeStopRequest::~SrsRtcNativeStopRequest()
{
}

const string& SrsRtcNativeStopRequest::get_url() const
{
    return url_;
}

const uint16_t SrsRtcNativeStopRequest::get_code() const
{
    return code_;
}

const string& SrsRtcNativeStopRequest::get_msg() const
{
    return msg_;
}

void SrsRtcNativeStopRequest::set_url(std::string url)
{
    url_ = url;
}

void SrsRtcNativeStopRequest::set_code(uint16_t code)
{
    code_ = code;
}

void SrsRtcNativeStopRequest::set_msg(std::string msg)
{
    msg_ = msg;
}
    
srs_error_t SrsRtcNativeStopRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_code == tlv.get_type()) {
            code_ = ntohs(*((uint16_t*)tlv.get_value()));
        } else if(SrsRTCNativeType_msg == tlv.get_type()) {
            msg_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_url == tlv.get_type()) {
            url_ = string((char*)tlv.get_value(), tlv.get_len());
        } else {
            srs_warn("in SrsRtcNativeStopRequest, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeStopRequest::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(code_);
    if(!msg_.empty()) {
        len += 3 + msg_.length();
    }
    if(!url_.empty()) {
        len += 3 + url_.length();
    }
    return len;
}

srs_error_t SrsRtcNativeStopRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    SrsTLV tlv;

    // encode code
    tlv.set_type(SrsRTCNativeType_code);
    uint16_t code = htons(code_);
    tlv.set_value(sizeof(code_), (uint8_t*)&code);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode code: %d", code_);
    }

    if(!msg_.empty()) {
        // encode msg
        tlv.set_type(SrsRTCNativeType_msg);
        tlv.set_value(msg_.length(), (uint8_t*)msg_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msg: %s", msg_.c_str());
        }
    }

    if(!url_.empty()) {
        // encode url
        tlv.set_type(SrsRTCNativeType_url);
        tlv.set_value(url_.length(), (uint8_t*)url_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode url - %s", url_.c_str());
        }
    }

    return err;
}
SrsRtcNativeStopResponse::SrsRtcNativeStopResponse()
{
}

SrsRtcNativeStopResponse::~SrsRtcNativeStopResponse()
{
}

SrsRtcNativeConnectRequest::SrsRtcNativeConnectRequest()
{
    msg_type_ = SrsRTCNativeMsgType_request;
    session_param_ = NULL;
}

SrsRtcNativeConnectRequest::~SrsRtcNativeConnectRequest()
{
    delete session_param_;
    session_param_ = NULL;
}

SrsRtcNativeSessionParam* SrsRtcNativeConnectRequest::get_session_param()
{
    if(NULL == session_param_) {
        session_param_ = new SrsRtcNativeSessionParam();
    }
    return session_param_;
}

const std::string& SrsRtcNativeConnectRequest::get_url() const
{
    return url_;
}

void SrsRtcNativeConnectRequest::set_url(std::string url)
{
    url_ = url;
}

srs_error_t SrsRtcNativeConnectRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {   
        return srs_error_wrap(err, "fail to decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_url == tlv.get_type()) {
            url_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_session_param == tlv.get_type()) {
          SrsBuffer sessionBuf((char*)tlv.get_value(), tlv.get_len());
          if(NULL == session_param_) {
              session_param_ = new SrsRtcNativeSessionParam();
          }  
          if(srs_success != (err = session_param_->decode(&sessionBuf))) {
              return srs_error_wrap(err, "decode session param");
          }
        } else {
            srs_warn("connect request, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeConnectRequest::nb_bytes()
{
    int len  = 0;
    len += SrsRtcNativeHeader::nb_bytes();
    len += 3 + url_.length();
    if(NULL != session_param_) {
        len += 3 + session_param_->nb_bytes();
    }
    return len;
}

srs_error_t SrsRtcNativeConnectRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode url
    tlv.set_type(SrsRTCNativeType_url);
    tlv.set_value(url_.length(), (uint8_t*)url_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode url: %s", url_.c_str());
    }

    // session param
    if(NULL != session_param_) {
        tlv.set_type(SrsRTCNativeType_session_param);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sessionBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = session_param_->encode(&sessionBuf))) {
            return srs_error_wrap(err, "encode session param");
        }
        tlv.set_value(sessionBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode session param tlv");
        }
    }

    return err;
}

SrsRtcNativeConnectResponse::SrsRtcNativeConnectResponse()
{
    code_ = 200;
    session_param_ = NULL;
    msg_type_ = SrsRTCNativeMsgType_final_resp;
}

SrsRtcNativeConnectResponse::~SrsRtcNativeConnectResponse()
{
    delete session_param_;
    session_param_ = NULL;
}

SrsRtcNativeSessionParam* SrsRtcNativeConnectResponse::get_session_param()
{
    if(NULL == session_param_) {
        session_param_ = new SrsRtcNativeSessionParam();
    }
    return session_param_;
}

const uint16_t SrsRtcNativeConnectResponse::get_code() const
{
    return code_;
}

const std::string& SrsRtcNativeConnectResponse::get_msg() const
{
    return msg_;
}

const std::string& SrsRtcNativeConnectResponse::get_trace_id() const
{
    return trace_id_;
}
void SrsRtcNativeConnectResponse::set_code(uint16_t code)
{
    code_ = code;
}

void SrsRtcNativeConnectResponse::set_msg(std::string& msg)
{
    msg_ = msg;
}

void SrsRtcNativeConnectResponse::set_trace_id(std::string& id)
{
    trace_id_ = id;
}

srs_error_t SrsRtcNativeConnectResponse::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_code == tlv.get_type()) {
            code_ = ntohs(*((uint16_t*)tlv.get_value()));
            srs_info("pub response: code %d", code_);
        } else if(SrsRTCNativeType_msg == tlv.get_type()) {
            msg_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_session_param == tlv.get_type()) {
            SrsBuffer sessionBuf((char*)tlv.get_value(), tlv.get_len());
            if(NULL == session_param_) {
                session_param_ = new SrsRtcNativeSessionParam();
            }  
            if(srs_success != (err = session_param_->decode(&sessionBuf))) {
                return srs_error_wrap(err, "decode session param");
            }
        } else if(SrsRTCNativeType_traceid == tlv.get_type()) {
            trace_id_ = string((char*)tlv.get_value(), tlv.get_len());
        } else {
            srs_warn("publish response, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeConnectResponse::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(code_);
    if(!msg_.empty()) {
        len += 3 + msg_.length();
    }
    if(NULL != session_param_) {
        len += 3 + session_param_->nb_bytes();
    }
    if(!trace_id_.empty()) {
        len += 3 + trace_id_.length();
    }
    return len;
}

srs_error_t SrsRtcNativeConnectResponse::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    uint8_t tmp[2048];
    SrsTLV tlv;

    // encode code
    tlv.set_type(SrsRTCNativeType_code);
    uint16_t code = htons(code_);
    tlv.set_value(sizeof(code_), (uint8_t*)&code);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode code: %d", code_);
    }

    if(!msg_.empty()) {
        // encode msg
        tlv.set_type(SrsRTCNativeType_msg);
        tlv.set_value(msg_.length(), (uint8_t*)msg_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msg: %s", msg_.c_str());
        }
    }

    // session param
    if(NULL != session_param_) {
        tlv.set_type(SrsRTCNativeType_session_param);
        memset(tmp, 0, sizeof(tmp));
        SrsBuffer sessionBuf((char*)tmp, sizeof(tmp));
        if(srs_success != (err = session_param_->encode(&sessionBuf))) {
            return srs_error_wrap(err, "encode session param");
        }
        tlv.set_value(sessionBuf.pos(), tmp);
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode session param tlv");
        }
    }

    if(!trace_id_.empty()) {
        tlv.set_type(SrsRTCNativeType_traceid);
        tlv.set_value(trace_id_.length(), (uint8_t*)trace_id_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode trace id tlv : %s", trace_id_.c_str());
        }
    }

    return err;
}

SrsRtcNativeDisconnectRequest::SrsRtcNativeDisconnectRequest()
{
    msg_type_ = SrsRTCNativeMsgType_request;
}

SrsRtcNativeDisconnectRequest::~SrsRtcNativeDisconnectRequest()
{
}

SrsRtcNativeDisconnectResponse::SrsRtcNativeDisconnectResponse()
{
}

SrsRtcNativeDisconnectResponse::~SrsRtcNativeDisconnectResponse()
{
}

SrsRtcNativeHeartbeatRequest::SrsRtcNativeHeartbeatRequest()
{
    msg_type_ = SrsRTCNativeMsgType_request;
}

SrsRtcNativeHeartbeatRequest::~SrsRtcNativeHeartbeatRequest()
{
}

SrsRtcNativeHeartbeatResponse::SrsRtcNativeHeartbeatResponse()
{
}

SrsRtcNativeHeartbeatResponse::~SrsRtcNativeHeartbeatResponse()
{
}

SrsRtcNativeMediaControlRequest::SrsRtcNativeMediaControlRequest(): sequence_(0)
{
    msg_type_ = SrsRTCNativeMsgType_request;
}

SrsRtcNativeMediaControlRequest::~SrsRtcNativeMediaControlRequest()
{
}

const string& SrsRtcNativeMediaControlRequest::get_url() const
{
    return url_;
}

vector<string>& SrsRtcNativeMediaControlRequest::get_msid()
{
    return msids_;
}

const uint32_t SrsRtcNativeMediaControlRequest::get_sequence() const
{
    return sequence_;
}

void SrsRtcNativeMediaControlRequest::set_url(std::string& url)
{
    url_ = url;
}

void SrsRtcNativeMediaControlRequest::add_msid(std::string& id)
{
    if(id.length()) {
        return;
    }
    msids_.push_back(id);
}

void SrsRtcNativeMediaControlRequest::set_sequence(uint32_t sn)
{
    sequence_ = sn;
}

srs_error_t SrsRtcNativeMediaControlRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_sequenceid == tlv.get_type()) {
            sequence_ = ntohl(*((uint32_t*)tlv.get_value()));
        } else if(SrsRTCNativeType_msid == tlv.get_type()) {
            msids_.push_back(string((char*)tlv.get_value(), tlv.get_len()));
        } else if(SrsRTCNativeType_url == tlv.get_type()) {
            url_ = string((char*)tlv.get_value(), tlv.get_len());
        } else {
            srs_warn("in SrsRtcNativeMediaControlRequest, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}
int SrsRtcNativeMediaControlRequest::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(sequence_);
    if(!url_.empty()) {
        len += 3 + url_.length();
    }
    for(size_t i = 0; i < msids_.size(); ++i) {
        len += 3 + msids_.at(i).length();
    }
    return len;
}

srs_error_t SrsRtcNativeMediaControlRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    SrsTLV tlv;

    // encode code
    tlv.set_type(SrsRTCNativeType_sequenceid);
    uint32_t sn = htonl(sequence_);
    tlv.set_value(sizeof(sequence_), (uint8_t*)&sn);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode sequence: %d", sequence_);
    }

    for(size_t i = 0; i < msids_.size(); ++i) {
        // encode msg
        tlv.set_type(SrsRTCNativeType_msg);
        tlv.set_value(msids_.at(i).length(), (uint8_t*)msids_.at(i).c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode msg: %s", msids_.at(i).c_str());
        }
    }

    if(!url_.empty()) {
        // encode url
        tlv.set_type(SrsRTCNativeType_url);
        tlv.set_value(url_.length(), (uint8_t*)url_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode url - %s", url_.c_str());
        }
    }

    return err;
}

SrsRtcNativeMediaControlReponse::SrsRtcNativeMediaControlReponse()
{
}

SrsRtcNativeMediaControlReponse::~SrsRtcNativeMediaControlReponse()
{
}

SrsRtcNativeNotifyRequest::SrsRtcNativeNotifyRequest(): need_response_(1)
{
    msg_type_ = SrsRTCNativeMsgType_request;
}

SrsRtcNativeNotifyRequest::~SrsRtcNativeNotifyRequest()
{

}

const uint8_t SrsRtcNativeNotifyRequest::get_type() const
{
    return type_;
}
    
const bool SrsRtcNativeNotifyRequest::need_response() const
{
    return need_response_ != 0 ? true : false;
}

const string& SrsRtcNativeNotifyRequest::get_info() const
{
    return info_;
}

const uint32_t SrsRtcNativeNotifyRequest::get_recv_ssrc() const
{
    return recv_ssrc_;
}

void SrsRtcNativeNotifyRequest::set_type(uint8_t type)
{
    type_ = type;
}

void SrsRtcNativeNotifyRequest::need_response(bool enable)
{
    need_response_ = enable;
}

void SrsRtcNativeNotifyRequest::set_info(std::string& info)
{
    info_ = info;
}

void SrsRtcNativeNotifyRequest::set_recv_ssrc(uint32_t ssrc)
{
    recv_ssrc_ = ssrc;
}

srs_error_t SrsRtcNativeNotifyRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_notify_recvSSRC == tlv.get_type()) {
            recv_ssrc_ = ntohl(*((uint32_t*)tlv.get_value()));
        } else if(SrsRTCNativeType_notify_info == tlv.get_type()) {
            info_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_notify_type == tlv.get_type()) {
            type_ = *tlv.get_value();
        } else if(SrsRTCNativeType_need_resp == tlv.get_type()) {
            need_response_ = *tlv.get_value();
        } else {
            srs_warn("in SrsRtcNativeNotifyRequest, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeNotifyRequest::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + sizeof(type_);
    len += 3 + sizeof(need_response_);
    len += 3 + info_.length();
    if( 0 != recv_ssrc_) {
        len += 3 + sizeof(recv_ssrc_);
    }
    return len;
}

srs_error_t SrsRtcNativeNotifyRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    SrsTLV tlv;

    // encode type
    tlv.set_type(SrsRTCNativeType_notify_type);
    tlv.set_value(sizeof(type_), (uint8_t*)&type_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode type: %d", type_);
    }

    // encode need response
    tlv.set_type(SrsRTCNativeType_need_resp);
    tlv.set_value(sizeof(need_response_), (uint8_t*)&need_response_);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode need response: %d", need_response_);
    }

    // encode receiver ssrc
    tlv.set_type(SrsRTCNativeType_notify_recvSSRC);
    uint32_t ssrc = htonl(recv_ssrc_);
    tlv.set_value(sizeof(recv_ssrc_), (uint8_t*)&ssrc);
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode receiver ssrc: %d", recv_ssrc_);
    }

    if(!info_.empty()) {
        // encode info
        tlv.set_type(SrsRTCNativeType_notify_info);
        tlv.set_value(info_.length(), (uint8_t*)info_.c_str());
        if(srs_success != (err = tlv.encode(buffer))) {
            return srs_error_wrap(err, "encode info - %s", info_.c_str());
        }
    }

    return err;
}

SrsRtcNativeNotifyResponse::SrsRtcNativeNotifyResponse()
{
}
 
SrsRtcNativeNotifyResponse::~SrsRtcNativeNotifyResponse()
{
}

SrsRtcNativeSwitchMsidRequest::SrsRtcNativeSwitchMsidRequest()
{
    msg_type_ = SrsRTCNativeMsgType_request;
}

SrsRtcNativeSwitchMsidRequest::~SrsRtcNativeSwitchMsidRequest()
{
}

const string& SrsRtcNativeSwitchMsidRequest::get_url() const
{
    return url_;
}
    
const string& SrsRtcNativeSwitchMsidRequest::get_old_msid() const
{
    return old_msid_;
}

const string& SrsRtcNativeSwitchMsidRequest::get_new_msid() const
{
    return new_msid_;
}

void SrsRtcNativeSwitchMsidRequest::set_url(std::string& url)
{
    url_ = url;
}

void SrsRtcNativeSwitchMsidRequest::set_old_msid(std::string& msid)
{
    old_msid_ = msid;
}
    
void SrsRtcNativeSwitchMsidRequest::set_new_msid(std::string& msid)
{
    new_msid_ = msid;
}

srs_error_t SrsRtcNativeSwitchMsidRequest::decode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    // header
    if((err = decode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "decode header");
    }

    SrsTLV tlv;
    while(0 != buffer->left()) {
        if(srs_success != (err = tlv.decode(buffer))) {
            if(ERROR_RTC_NATIVE_TLV_TYPE_0 == srs_error_code(err)) {
                err = srs_success;
                continue;
            }
            return srs_error_wrap(err, "decode tlv error");
        }

        if(SrsRTCNativeType_url == tlv.get_type()) {
            url_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_msid == tlv.get_type()) {
            old_msid_ = string((char*)tlv.get_value(), tlv.get_len());
        } else if(SrsRTCNativeType_new_msid == tlv.get_type()) {
            new_msid_ = string((char*)tlv.get_value(), tlv.get_len());
        } else {
            srs_warn("in SrsRtcNativeSwitchMsidRequest, unkonw type:%d", tlv.get_type());
        }
    }

    return err;
}

int SrsRtcNativeSwitchMsidRequest::nb_bytes()
{
    int len = SrsRtcNativeHeader::nb_bytes();
    len += 3 + url_.length();
    len += 3 + old_msid_.length();
    len += 3 + new_msid_.length();
    
    return len;
}

srs_error_t SrsRtcNativeSwitchMsidRequest::encode(SrsBuffer *buffer)
{
    srs_error_t err = srs_success;
    if(!buffer->require(nb_bytes())) {
        return srs_error_new(ERROR_RTC_NATIVE_ECODE, 
            "encode buffer is not enough. need:%d, buffer:%d", nb_bytes(), buffer->left());
    }

    if((err = encode_native_header(buffer)) != srs_success) {
        return srs_error_wrap(err, "encode header");
    }

    SrsTLV tlv;

    // encode url
    tlv.set_type(SrsRTCNativeType_url);
    tlv.set_value(url_.length(), (uint8_t*)url_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode url - %s", url_.c_str());
    }

    // encode old msid
    tlv.set_type(SrsRTCNativeType_msid);
    tlv.set_value(old_msid_.length(), (uint8_t*)old_msid_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode old msid - %s", old_msid_.c_str());
    }

    // encode new msid
    tlv.set_type(SrsRTCNativeType_new_msid);
    tlv.set_value(new_msid_.length(), (uint8_t*)new_msid_.c_str());
    if(srs_success != (err = tlv.encode(buffer))) {
        return srs_error_wrap(err, "encode new msid - %s", new_msid_.c_str());
    }

    return err;
}

SrsRtcNativeSwitchMsidResponse::SrsRtcNativeSwitchMsidResponse()
{

}

SrsRtcNativeSwitchMsidResponse::~SrsRtcNativeSwitchMsidResponse()
{

}

