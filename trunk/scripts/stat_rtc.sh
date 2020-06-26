#!/bin/bash

echo "SRS"
find src -name "*.*pp"|xargs wc -l|grep total

echo "RTC of SRS"
find src -name "*.*pp"|grep _rtc|xargs wc -l|grep total

echo "ST"
find 3rdparty/st-srs -name "*.c" -o -name "*.h" -o -name "*.S"|grep -v examples|grep -v extensions|xargs wc -l|grep total

echo "WebRTC"
find src -name "*.cc" -o -name "*.h"|xargs wc -l|grep total

echo "FFmpeg4.2-fit"
find 3rdparty/ffmpeg-4.2-fit -name "*.c" -o -name "*.h" -o -name "*.asm"|xargs wc -l|grep total

