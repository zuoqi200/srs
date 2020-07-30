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

extern int srs_count_merge_stream(const std::vector<SrsTrackConfig>& cfgs);
extern SrsTrackConfig srs_find_track_config_active(const std::vector<SrsTrackConfig>& cfgs, const string& type, const string& track_id);

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
            SrsRtcTrackDescription ds; ds.type_ = "audio"; ds.id_ = "sophon_audio"; ds.ssrc_ = 100; ds.is_active_ = true;
            play.audio_tracks_[ds.ssrc_] = audio = new SrsRtcAudioSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_small"; ds.ssrc_ = 200; ds.is_active_ = true;
            play.video_tracks_[ds.ssrc_] = small = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_large"; ds.ssrc_ = 201; ds.is_active_ = true;
            play.video_tracks_[ds.ssrc_] = large = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_camera_super"; ds.ssrc_ = 202; ds.is_active_ = true;
            play.video_tracks_[ds.ssrc_] = super = new SrsRtcVideoSendTrack(&s, &ds);
        }
        if (true) {
            SrsRtcTrackDescription ds; ds.type_ = "video"; ds.id_ = "sophon_video_screen_share"; ds.ssrc_ = 203; ds.is_active_ = true;
            play.video_tracks_[ds.ssrc_] = screen = new SrsRtcVideoSendTrack(&s, &ds);
        }
        EXPECT_TRUE(audio->get_track_status());
        EXPECT_TRUE(small->get_track_status());
        EXPECT_TRUE(large->get_track_status());
        EXPECT_TRUE(super->get_track_status());
        EXPECT_TRUE(screen->get_track_status());
    }

    // User disable audio.
    if (true) {
        vector<SrsTrackConfig> cfgs; SrsTrackConfig cfg; cfg.active = true;
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_small"; cfgs.push_back(cfg);
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_large"; cfgs.push_back(cfg);
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_super"; cfgs.push_back(cfg);
        cfg.type_ = "video"; cfg.label_ = "sophon_video_screen_share"; cfgs.push_back(cfg);
        play.set_track_active(cfgs);

        EXPECT_FALSE(audio->get_track_status());
        EXPECT_TRUE(small->get_track_status());
        EXPECT_TRUE(large->get_track_status());
        EXPECT_TRUE(super->get_track_status());
        EXPECT_TRUE(screen->get_track_status());
    }

    // User disable screen share.
    if (true) {
        vector<SrsTrackConfig> cfgs; SrsTrackConfig cfg; cfg.active = true;
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_small"; cfgs.push_back(cfg);
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_large"; cfgs.push_back(cfg);
        cfg.type_ = "video"; cfg.label_ = "sophon_video_camera_super"; cfgs.push_back(cfg);
        play.set_track_active(cfgs);

        EXPECT_FALSE(audio->get_track_status());
        EXPECT_TRUE(small->get_track_status());
        EXPECT_TRUE(large->get_track_status());
        EXPECT_TRUE(super->get_track_status());
        EXPECT_FALSE(screen->get_track_status());

        // Should not switch stream.
        EXPECT_TRUE(!ctx->prepare_);
        EXPECT_TRUE(!ctx->active_);
    }
}

