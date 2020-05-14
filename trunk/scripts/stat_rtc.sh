#!/bin/bash

find src -name "*.*pp"|grep _rtc|xargs wc -l
