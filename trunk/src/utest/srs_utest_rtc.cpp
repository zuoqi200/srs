/*
The MIT License (MIT)

Copyright (c) 2013-2020 Winlin

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include <srs_utest_rtc.hpp>

#include <srs_kernel_error.hpp>
#include <srs_core_autofree.hpp>
#include <srs_app_rtc_queue.hpp>
#include <srs_kernel_rtc_rtp.hpp>
#include <srs_app_rtc_source.hpp>
#include <srs_app_rtc_conn.hpp>

#include <vector>
using namespace std;

extern int srs_count_merge_stream(const std::vector<SrsTrackConfig>& cfgs);
extern SrsTrackConfig srs_find_track_config_active(const std::vector<SrsTrackConfig>& cfgs, const string& type, const string& track_id);

SrsRtpPacket2* srs_set_packet_to_keyframe(SrsRtpPacket2* pkt)
{
    SrsRtpExtensionPictureID* pid = pkt->header.get_picture_id();

    pid->has_picture_id_ = true;
    pid->ref_id_ = 0;
    pid->tid_ = 0;

    return pkt;
}

VOID TEST(KernelRTCTest, SequenceCompare)
{
    if (true) {
        EXPECT_EQ(0, srs_rtp_seq_distance(0, 0));
        EXPECT_EQ(0, srs_rtp_seq_distance(1, 1));
        EXPECT_EQ(0, srs_rtp_seq_distance(3, 3));

        EXPECT_EQ(1, srs_rtp_seq_distance(0, 1));
        EXPECT_EQ(-1, srs_rtp_seq_distance(1, 0));
        EXPECT_EQ(1, srs_rtp_seq_distance(65535, 0));
    }

    if (true) {
        EXPECT_FALSE(srs_rtp_seq_distance(1, 1) > 0);
        EXPECT_TRUE(srs_rtp_seq_distance(65534, 65535) > 0);
        EXPECT_TRUE(srs_rtp_seq_distance(0, 1) > 0);
        EXPECT_TRUE(srs_rtp_seq_distance(255, 256) > 0);

        EXPECT_TRUE(srs_rtp_seq_distance(65535, 0) > 0);
        EXPECT_TRUE(srs_rtp_seq_distance(65280, 0) > 0);
        EXPECT_TRUE(srs_rtp_seq_distance(65535, 255) > 0);
        EXPECT_TRUE(srs_rtp_seq_distance(65280, 255) > 0);

        EXPECT_FALSE(srs_rtp_seq_distance(0, 65535) > 0);
        EXPECT_FALSE(srs_rtp_seq_distance(0, 65280) > 0);
        EXPECT_FALSE(srs_rtp_seq_distance(255, 65535) > 0);
        EXPECT_FALSE(srs_rtp_seq_distance(255, 65280) > 0);

        // Note that srs_rtp_seq_distance(0, 32768)>0 is TRUE by https://mp.weixin.qq.com/s/JZTInmlB9FUWXBQw_7NYqg
        //      but for WebRTC jitter buffer it's FALSE and we follow it.
        EXPECT_FALSE(srs_rtp_seq_distance(0, 32768) > 0);
        // It's FALSE definitely.
        EXPECT_FALSE(srs_rtp_seq_distance(32768, 0) > 0);
    }

    if (true) {
        EXPECT_FALSE(srs_seq_is_newer(1, 1));
        EXPECT_TRUE(srs_seq_is_newer(65535, 65534));
        EXPECT_TRUE(srs_seq_is_newer(1, 0));
        EXPECT_TRUE(srs_seq_is_newer(256, 255));

        EXPECT_TRUE(srs_seq_is_newer(0, 65535));
        EXPECT_TRUE(srs_seq_is_newer(0, 65280));
        EXPECT_TRUE(srs_seq_is_newer(255, 65535));
        EXPECT_TRUE(srs_seq_is_newer(255, 65280));

        EXPECT_FALSE(srs_seq_is_newer(65535, 0));
        EXPECT_FALSE(srs_seq_is_newer(65280, 0));
        EXPECT_FALSE(srs_seq_is_newer(65535, 255));
        EXPECT_FALSE(srs_seq_is_newer(65280, 255));

        EXPECT_FALSE(srs_seq_is_newer(32768, 0));
        EXPECT_FALSE(srs_seq_is_newer(0, 32768));
    }

    if (true) {
        EXPECT_FALSE(srs_seq_distance(1, 1) > 0);
        EXPECT_TRUE(srs_seq_distance(65535, 65534) > 0);
        EXPECT_TRUE(srs_seq_distance(1, 0) > 0);
        EXPECT_TRUE(srs_seq_distance(256, 255) > 0);

        EXPECT_TRUE(srs_seq_distance(0, 65535) > 0);
        EXPECT_TRUE(srs_seq_distance(0, 65280) > 0);
        EXPECT_TRUE(srs_seq_distance(255, 65535) > 0);
        EXPECT_TRUE(srs_seq_distance(255, 65280) > 0);

        EXPECT_FALSE(srs_seq_distance(65535, 0) > 0);
        EXPECT_FALSE(srs_seq_distance(65280, 0) > 0);
        EXPECT_FALSE(srs_seq_distance(65535, 255) > 0);
        EXPECT_FALSE(srs_seq_distance(65280, 255) > 0);

        EXPECT_FALSE(srs_seq_distance(32768, 0) > 0);
        EXPECT_FALSE(srs_seq_distance(0, 32768) > 0);
    }

    if (true) {
        EXPECT_FALSE(srs_seq_is_rollback(1, 1));
        EXPECT_FALSE(srs_seq_is_rollback(65535, 65534));
        EXPECT_FALSE(srs_seq_is_rollback(1, 0));
        EXPECT_FALSE(srs_seq_is_rollback(256, 255));

        EXPECT_TRUE(srs_seq_is_rollback(0, 65535));
        EXPECT_TRUE(srs_seq_is_rollback(0, 65280));
        EXPECT_TRUE(srs_seq_is_rollback(255, 65535));
        EXPECT_TRUE(srs_seq_is_rollback(255, 65280));

        EXPECT_FALSE(srs_seq_is_rollback(65535, 0));
        EXPECT_FALSE(srs_seq_is_rollback(65280, 0));
        EXPECT_FALSE(srs_seq_is_rollback(65535, 255));
        EXPECT_FALSE(srs_seq_is_rollback(65280, 255));

        EXPECT_FALSE(srs_seq_is_rollback(32768, 0));
        EXPECT_FALSE(srs_seq_is_rollback(0, 32768));
    }
}

extern bool srs_is_stun(const uint8_t* data, size_t size);
extern bool srs_is_dtls(const uint8_t* data, size_t len);
extern bool srs_is_rtp_or_rtcp(const uint8_t* data, size_t len);
extern bool srs_is_rtcp(const uint8_t* data, size_t len);

#define mock_arr_push(arr, elem) arr.push_back(vector<uint8_t>(elem, elem + sizeof(elem)))

VOID TEST(KernelRTCTest, TestPacketType)
{
    // DTLS packet.
    vector< vector<uint8_t> > dtlss;
    if (true) { uint8_t data[13] = {20}; mock_arr_push(dtlss, data); } // change_cipher_spec(20)
    if (true) { uint8_t data[13] = {21}; mock_arr_push(dtlss, data); } // alert(21)
    if (true) { uint8_t data[13] = {22}; mock_arr_push(dtlss, data); } // handshake(22)
    if (true) { uint8_t data[13] = {23}; mock_arr_push(dtlss, data); } // application_data(23)
    for (int i = 0; i < (int)dtlss.size(); i++) {
        vector<uint8_t> elem = dtlss.at(i);
        EXPECT_TRUE(srs_is_dtls(&elem[0], (size_t)elem.size()));
    }

    for (int i = 0; i < (int)dtlss.size(); i++) {
        vector<uint8_t> elem = dtlss.at(i);
        EXPECT_FALSE(srs_is_dtls(&elem[0], 1));

        // All DTLS should not be other packets.
        EXPECT_FALSE(srs_is_stun(&elem[0], (size_t)elem.size()));
        EXPECT_TRUE(srs_is_dtls(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_rtp_or_rtcp(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_rtcp(&elem[0], (size_t)elem.size()));
    }

    // STUN packet.
    vector< vector<uint8_t> > stuns;
    if (true) { uint8_t data[1] = {0}; mock_arr_push(stuns, data); } // binding request.
    if (true) { uint8_t data[1] = {1}; mock_arr_push(stuns, data); } // binding success response.
    for (int i = 0; i < (int)stuns.size(); i++) {
        vector<uint8_t> elem = stuns.at(i);
        EXPECT_TRUE(srs_is_stun(&elem[0], (size_t)elem.size()));
    }

    for (int i = 0; i < (int)stuns.size(); i++) {
        vector<uint8_t> elem = stuns.at(i);
        EXPECT_FALSE(srs_is_stun(&elem[0], 0));

        // All STUN should not be other packets.
        EXPECT_TRUE(srs_is_stun(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_dtls(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_rtp_or_rtcp(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_rtcp(&elem[0], (size_t)elem.size()));
    }

    // RTCP packet.
    vector< vector<uint8_t> > rtcps;
    if (true) { uint8_t data[12] = {0x80, 192}; mock_arr_push(rtcps, data); }
    if (true) { uint8_t data[12] = {0x80, 200}; mock_arr_push(rtcps, data); } // SR
    if (true) { uint8_t data[12] = {0x80, 201}; mock_arr_push(rtcps, data); } // RR
    if (true) { uint8_t data[12] = {0x80, 202}; mock_arr_push(rtcps, data); } // SDES
    if (true) { uint8_t data[12] = {0x80, 203}; mock_arr_push(rtcps, data); } // BYE
    if (true) { uint8_t data[12] = {0x80, 204}; mock_arr_push(rtcps, data); } // APP
    if (true) { uint8_t data[12] = {0x80, 223}; mock_arr_push(rtcps, data); }
    for (int i = 0; i < (int)rtcps.size(); i++) {
        vector<uint8_t> elem = rtcps.at(i);
        EXPECT_TRUE(srs_is_rtcp(&elem[0], (size_t)elem.size()));
    }

    for (int i = 0; i < (int)rtcps.size(); i++) {
        vector<uint8_t> elem = rtcps.at(i);
        EXPECT_FALSE(srs_is_rtcp(&elem[0], 2));

        // All RTCP should not be other packets.
        EXPECT_FALSE(srs_is_stun(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_dtls(&elem[0], (size_t)elem.size()));
        EXPECT_TRUE(srs_is_rtp_or_rtcp(&elem[0], (size_t)elem.size()));
        EXPECT_TRUE(srs_is_rtcp(&elem[0], (size_t)elem.size()));
    }

    // RTP packet.
    vector< vector<uint8_t> > rtps;
    if (true) { uint8_t data[12] = {0x80, 96}; mock_arr_push(rtps, data); }
    if (true) { uint8_t data[12] = {0x80, 127}; mock_arr_push(rtps, data); }
    if (true) { uint8_t data[12] = {0x80, 224}; mock_arr_push(rtps, data); }
    if (true) { uint8_t data[12] = {0x80, 255}; mock_arr_push(rtps, data); }
    for (int i = 0; i < (int)rtps.size(); i++) {
        vector<uint8_t> elem = rtps.at(i);
        EXPECT_TRUE(srs_is_rtp_or_rtcp(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_rtcp(&elem[0], (size_t)elem.size()));
    }

    for (int i = 0; i < (int)rtps.size(); i++) {
        vector<uint8_t> elem = rtps.at(i);
        EXPECT_FALSE(srs_is_rtp_or_rtcp(&elem[0], 2));

        // All RTP should not be other packets.
        EXPECT_FALSE(srs_is_stun(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_dtls(&elem[0], (size_t)elem.size()));
        EXPECT_TRUE(srs_is_rtp_or_rtcp(&elem[0], (size_t)elem.size()));
        EXPECT_FALSE(srs_is_rtcp(&elem[0], (size_t)elem.size()));
    }
}

VOID TEST(KernelRTCTest, DefaultTrackStatus)
{
    // By default, track is disabled.
    if (true) {
        SrsRtcTrackDescription td;

        // The track must default to disable, that is, the active is false.
        EXPECT_FALSE(td.is_active_);
    }

    // Enable it by player.
    if (true) {
        SrsRtcConnection s(NULL, SrsContextId()); SrsRtcPlayStream play(&s, SrsContextId());
        SrsRtcAudioSendTrack* audio; SrsRtcVideoSendTrack *video;

        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "audio"; ds.id_ = "NSNWOn19NDn12o8nNeji2"; ds.ssrc_ = 100;
            play.audio_tracks_[ds.ssrc_] = audio = new SrsRtcAudioSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "VMo22nfLDn122nfnDNL2"; ds.ssrc_ = 200;
            play.video_tracks_[ds.ssrc_] = video = new SrsRtcVideoSendTrack(&s, &ds);
        }
        EXPECT_FALSE(audio->get_track_status());
        EXPECT_FALSE(video->get_track_status());

        play.set_all_tracks_status(true);
        EXPECT_TRUE(audio->get_track_status());
        EXPECT_TRUE(video->get_track_status());
    }

    // Enable it by publisher.
    if (true) {
        SrsRtcConnection s(NULL, SrsContextId()); SrsRtcPublishStream publish(&s);
        SrsRtcAudioRecvTrack* audio; SrsRtcVideoRecvTrack *video;

        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "audio"; ds.id_ = "NSNWOn19NDn12o8nNeji2"; ds.ssrc_ = 100;
            audio = new SrsRtcAudioRecvTrack(&s, &ds); publish.audio_tracks_.push_back(audio);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "VMo22nfLDn122nfnDNL2"; ds.ssrc_ = 200;
            video = new SrsRtcVideoRecvTrack(&s, &ds); publish.video_tracks_.push_back(video);
        }
        EXPECT_FALSE(audio->get_track_status());
        EXPECT_FALSE(video->get_track_status());

        publish.set_all_tracks_status(true);
        EXPECT_TRUE(audio->get_track_status());
        EXPECT_TRUE(video->get_track_status());
    }
}

VOID TEST(KernelRTCTest, TrackDescription)
{
    // By default, track is disabled.
    if (true) {
        SrsRtcTrackDescription td;

        // The track must default to disable, that is, the active is false.
        EXPECT_FALSE(td.is_active_);
    }

    // Enable it by player or connection.
    if (true) {
        SrsRtcConnection s(NULL, SrsContextId()); SrsRtcPlayStream play(&s, SrsContextId());
        SrsRtcAudioSendTrack* audio; SrsRtcVideoSendTrack *small, *large, *super, *screen;

        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "audio"; ds.id_ = "sophon_audio"; ds.ssrc_ = 100;
            play.audio_tracks_[ds.ssrc_] = audio = new SrsRtcAudioSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_small"; ds.ssrc_ = 200;
            play.video_tracks_[ds.ssrc_] = small = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_large"; ds.ssrc_ = 201;
            play.video_tracks_[ds.ssrc_] = large = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_super"; ds.ssrc_ = 202;
            play.video_tracks_[ds.ssrc_] = super = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_screen_share"; ds.ssrc_ = 203;
            play.video_tracks_[ds.ssrc_] = screen = new SrsRtcVideoSendTrack(&s, &ds);
        }
        EXPECT_FALSE(audio->get_track_status());
        EXPECT_FALSE(small->get_track_status());
        EXPECT_FALSE(large->get_track_status());
        EXPECT_FALSE(super->get_track_status());
        EXPECT_FALSE(screen->get_track_status());

        play.set_all_tracks_status(true);
        EXPECT_TRUE(audio->get_track_status());
        EXPECT_TRUE(small->get_track_status());
        EXPECT_TRUE(large->get_track_status());
        EXPECT_TRUE(super->get_track_status());
        EXPECT_TRUE(screen->get_track_status());
    }
}

VOID TEST(KernelRTCTest, PlayerStreamConfig)
{
    // Stream is merging.
    if (true) {
        vector<SrsTrackConfig> cfgs;

        SrsTrackConfig cfg;
        cfg.label_ = "sophon_video_camera_small";
        cfgs.push_back(cfg);
        EXPECT_EQ(1, srs_count_merge_stream(cfgs));

        cfg.label_ = "sophon_video_camera_large";
        cfgs.push_back(cfg);
        EXPECT_EQ(2, srs_count_merge_stream(cfgs));

        cfg.label_ = "sophon_video_camera_super";
        cfgs.push_back(cfg);
        EXPECT_EQ(3, srs_count_merge_stream(cfgs));
    }

    // Stream is normal or not merging.
    if (true) {
        vector<SrsTrackConfig> cfgs;
        EXPECT_EQ(0, srs_count_merge_stream(cfgs));

        SrsTrackConfig cfg;
        cfg.label_ = "sophon_audio";
        cfgs.push_back(cfg);
        EXPECT_EQ(0, srs_count_merge_stream(cfgs));

        cfg.label_ = "h5-random";
        cfgs.push_back(cfg);
        EXPECT_EQ(0, srs_count_merge_stream(cfgs));

        cfg.label_ = "sophon_video_screen_share";
        cfgs.push_back(cfg);
        EXPECT_EQ(0, srs_count_merge_stream(cfgs));

        cfg.label_ = "sophon_video_camera";
        cfgs.push_back(cfg);
        EXPECT_EQ(0, srs_count_merge_stream(cfgs));
    }

    // Config to active stream.
    if (true) {
        vector<SrsTrackConfig> cfgs;

        SrsTrackConfig cfg;
        cfg.type_ = "audio";
        cfg.label_ = "sophon_audio";
        cfg.active = true;
        cfgs.push_back(cfg);

        EXPECT_TRUE(srs_find_track_config_active(cfgs, "audio", "sophon_audio").active);
    }

    // Config to disable stream.
    if (true) {
        vector<SrsTrackConfig> cfgs;
        EXPECT_FALSE(srs_find_track_config_active(cfgs, "audio", "sophon_audio").active);

        SrsTrackConfig cfg;
        cfg.label_ = "sophon_audio";
        cfgs.push_back(cfg);
        EXPECT_FALSE(srs_find_track_config_active(cfgs, "audio", "sophon_audio").active);

        cfg.label_ = "h5";
        cfg.type_ = "audio";
        cfgs.push_back(cfg);
        EXPECT_FALSE(srs_find_track_config_active(cfgs, "audio", "sophon_audio").active);

        cfg.label_ = "sophon_audio";
        cfg.type_ = "audio";
        cfg.active = false;
        cfgs.push_back(cfg);
        EXPECT_FALSE(srs_find_track_config_active(cfgs, "audio", "sophon_audio").active);
    }
}

VOID TEST(KernelRTCTest, PlayerStreamSwitchNoMergeStream)
{
    // Typical and normal stream switch scenario.
    // User is playing bellow orignal streams:
    //      sophon_audio
    //      sophon_video_camera_small
    //      sophon_video_camera_large
    //      sophon_video_camera_super
    //      sophon_video_screen_share
    // Of course, we merge the bellow streams as sophon_video_camera:
    //      sophon_video_camera_small
    //      sophon_video_camera_large
    //      sophon_video_camera_super
    // So user is literally playing:
    //      sophon_audio
    //      sophon_video_camera
    //      sophon_video_screen_share
    // In this scenario, user maybe switch between no-merging streams.
    SrsRtcConnection s(NULL, SrsContextId()); SrsRtcPlayStream play(&s, SrsContextId());
    SrsRtcAudioSendTrack* audio; SrsRtcVideoSendTrack *small, *large, *super, *screen;
    SrsStreamSwitchContext* ctx = play.switch_context_;

    // Setup the begin state, play all streams.
    if (true) {
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "audio"; ds.id_ = "sophon_audio"; ds.ssrc_ = 100;
            play.audio_tracks_[ds.ssrc_] = audio = new SrsRtcAudioSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_small"; ds.ssrc_ = 200;
            play.video_tracks_[ds.ssrc_] = small = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_large"; ds.ssrc_ = 201;
            play.video_tracks_[ds.ssrc_] = large = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_super"; ds.ssrc_ = 202;
            play.video_tracks_[ds.ssrc_] = super = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_screen_share"; ds.ssrc_ = 203;
            play.video_tracks_[ds.ssrc_] = screen = new SrsRtcVideoSendTrack(&s, &ds);
        }
        EXPECT_FALSE(audio->get_track_status());
        EXPECT_FALSE(small->get_track_status());
        EXPECT_FALSE(large->get_track_status());
        EXPECT_FALSE(super->get_track_status());
        EXPECT_FALSE(screen->get_track_status());
    }

    // User enable audio.
    if (true) {
        vector<SrsTrackConfig> cfgs; SrsTrackConfig cfg; cfg.active = true;
        cfg.type_ = "audio"; cfg.label_ = "sophon_audio"; cfgs.push_back(cfg);
        play.set_track_active(cfgs);

        EXPECT_TRUE(audio->get_track_status());
    }

    // User enable screen share.
    if (true) {
        vector<SrsTrackConfig> cfgs; SrsTrackConfig cfg; cfg.active = true;
        cfg.type_ = "video"; cfg.label_ = "sophon_video_screen_share"; cfgs.push_back(cfg);
        play.set_track_active(cfgs);

        EXPECT_TRUE(screen->get_track_status());

        // Should not switch stream.
        EXPECT_TRUE(!ctx->prepare_);
        EXPECT_TRUE(!ctx->active_);
    }
}

VOID TEST(KernelRTCTest, PlayerStreamSwitchOnlyMergeStream)
{
    // Typical and normal stream switch scenario.
    // User is playing bellow orignal streams:
    //      sophon_audio
    //      sophon_video_camera_small
    //      sophon_video_camera_large
    //      sophon_video_screen_share
    // Of course, we merge the bellow streams as sophon_video_camera:
    //      sophon_video_camera_small
    //      sophon_video_camera_large
    // So user is literally playing:
    //      sophon_audio
    //      sophon_video_camera
    //      sophon_video_screen_share
    // In this scenario, user maybe switch between only merging streams.
    SrsRtcConnection s(NULL, SrsContextId()); SrsRtcPlayStream play(&s, SrsContextId());
    SrsRtcAudioSendTrack* audio; SrsRtcVideoSendTrack *small, *large, *screen;
    SrsStreamSwitchContext* ctx = play.switch_context_;

    // Setup the begin state, play all streams.
    if (true) {
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "audio"; ds.id_ = "sophon_audio"; ds.ssrc_ = 100;
            play.audio_tracks_[ds.ssrc_] = audio = new SrsRtcAudioSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_small"; ds.ssrc_ = 200;
            play.video_tracks_[ds.ssrc_] = small = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_large"; ds.ssrc_ = 201;
            play.video_tracks_[ds.ssrc_] = large = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_screen_share"; ds.ssrc_ = 203;
            play.video_tracks_[ds.ssrc_] = screen = new SrsRtcVideoSendTrack(&s, &ds);
        }
        EXPECT_FALSE(audio->get_track_status());
        EXPECT_FALSE(small->get_track_status());
        EXPECT_FALSE(large->get_track_status());
        EXPECT_FALSE(screen->get_track_status());
    }

    // User switch to small stream.
    if (true) {
        vector<SrsTrackConfig> cfgs; SrsTrackConfig cfg; cfg.active = true;
        cfg.type_ = "audio"; cfg.label_ = "sophon_audio"; cfgs.push_back(cfg);
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_small"; cfgs.push_back(cfg);
        play.set_track_active(cfgs);

        // The audio should be enabled now.
        EXPECT_TRUE(audio->get_track_status());
        // The small should be enabled in future.
        EXPECT_FALSE(small->get_track_status());
        // In context, we prepare to switch to small stream.
        EXPECT_TRUE(ctx->prepare_ == small); EXPECT_TRUE(!ctx->active_);

        // When got keyframe, we switch to small stream.
        SrsRtpPacket2 pkt; srs_set_packet_to_keyframe(&pkt);
        ctx->try_switch_stream(small, &pkt);

        // Now, small should be active.
        EXPECT_TRUE(!ctx->prepare_); EXPECT_TRUE(ctx->active_ == small);
        EXPECT_TRUE(small->get_track_status());
    }

    // User switch to large stream.
    if (true) {
        vector<SrsTrackConfig> cfgs; SrsTrackConfig cfg; cfg.active = true;
        cfg.type_ = "audio"; cfg.label_ = "sophon_audio"; cfgs.push_back(cfg);
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_large"; cfgs.push_back(cfg);
        play.set_track_active(cfgs);

        // The audio should be enabled now.
        EXPECT_TRUE(audio->get_track_status());
        // The large should be enabled in future.
        EXPECT_FALSE(large->get_track_status());
        // In context, we prepare to switch to large stream.
        // And now, it should still be large stream.
        EXPECT_TRUE(ctx->prepare_ == large); EXPECT_TRUE(ctx->active_ == small);

        // When got keyframe, we switch to large stream.
        SrsRtpPacket2 pkt; srs_set_packet_to_keyframe(&pkt);
        ctx->try_switch_stream(large, &pkt);

        // Now, large should be active.
        EXPECT_TRUE(!ctx->prepare_); EXPECT_TRUE(ctx->active_ == large);
        EXPECT_TRUE(large->get_track_status());
        // And, small stream should be inactive.
        EXPECT_FALSE(small->get_track_status());
    }
}

VOID TEST(KernelRTCTest, PlayerStreamSwitchBadcase)
{
    // In this scenario, we test the badcase for stream switching.
    SrsRtcConnection s(NULL, SrsContextId()); SrsRtcPlayStream play(&s, SrsContextId());
    SrsRtcAudioSendTrack* audio; SrsRtcVideoSendTrack *small, *large, *screen;
    SrsStreamSwitchContext* ctx = play.switch_context_;

    // Setup the begin state, play all streams.
    if (true) {
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "audio"; ds.id_ = "sophon_audio"; ds.ssrc_ = 100;
            play.audio_tracks_[ds.ssrc_] = audio = new SrsRtcAudioSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_small"; ds.ssrc_ = 200;
            play.video_tracks_[ds.ssrc_] = small = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_large"; ds.ssrc_ = 201;
            play.video_tracks_[ds.ssrc_] = large = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_screen_share"; ds.ssrc_ = 203;
            play.video_tracks_[ds.ssrc_] = screen = new SrsRtcVideoSendTrack(&s, &ds);
        }
        EXPECT_FALSE(audio->get_track_status());
        EXPECT_FALSE(small->get_track_status());
        EXPECT_FALSE(large->get_track_status());
        EXPECT_FALSE(screen->get_track_status());
    }

    // User switch to empty config, nothing changed.
    if (true) {
        vector<SrsTrackConfig> cfgs;
        play.set_track_active(cfgs);

        EXPECT_FALSE(audio->get_track_status());
        EXPECT_FALSE(small->get_track_status());
        EXPECT_FALSE(large->get_track_status());
        EXPECT_FALSE(screen->get_track_status());
    }

    // User enable audio and large.
    if (true) {
        vector<SrsTrackConfig> cfgs; SrsTrackConfig cfg; cfg.active = true;
        cfg.type_ = "audio"; cfg.label_ = "sophon_audio"; cfgs.push_back(cfg);
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_large"; cfgs.push_back(cfg);
        play.set_track_active(cfgs);

        // The audio should be enabled now.
        EXPECT_TRUE(audio->get_track_status());
        // The large should be enabled in future.
        EXPECT_FALSE(large->get_track_status());
        // In context, we prepare to switch to large stream.
        EXPECT_TRUE(ctx->prepare_ == large); EXPECT_TRUE(!ctx->active_);

        // When got keyframe, we switch to large stream.
        SrsRtpPacket2 pkt; srs_set_packet_to_keyframe(&pkt);
        ctx->try_switch_stream(large, &pkt);

        // Now, large should be active.
        EXPECT_TRUE(!ctx->prepare_); EXPECT_TRUE(ctx->active_ == large);
        EXPECT_TRUE(large->get_track_status());
    }
    // Then, user disable large, change to audio only.
    if (true) {
        vector<SrsTrackConfig> cfgs; SrsTrackConfig cfg; cfg.active = true;
        cfg.type_ = "audio"; cfg.label_ = "sophon_audio"; cfgs.push_back(cfg);
        play.set_track_active(cfgs);

        // The audio should be enabled now.
        EXPECT_TRUE(audio->get_track_status());
        // The large should be inactive now.
        EXPECT_FALSE(large->get_track_status());
        // In context, no stream will be switch to.
        EXPECT_TRUE(!ctx->prepare_); EXPECT_TRUE(!ctx->active_);
    }
}

