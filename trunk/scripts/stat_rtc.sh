#!/bin/bash

files=`find src -name "*.*pp"`
targets=""
for file in $files; do
  echo $file|grep -q _rtc && targets="$targets $file" && continue;
done

wc -l $targets;