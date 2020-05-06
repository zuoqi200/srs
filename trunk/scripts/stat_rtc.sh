#!/bin/bash

files=`find src -name "*.*pp"`
targets=""
for file in $files; do
  echo $file|grep -q app_rtc && targets="$targets $file" && continue;
  echo $file|grep -q app_dtls && targets="$targets $file" && continue;
  echo $file|grep -q app_janus && targets="$targets $file" && continue;
  echo $file|grep -q app_rtp && targets="$targets $file" && continue;
  echo $file|grep -q app_sdp && targets="$targets $file" && continue;
  echo $file|grep -q kernel_rtp && targets="$targets $file" && continue;
  echo $file|grep -q stun_stack && targets="$targets $file" && continue;
done

wc -l $targets;