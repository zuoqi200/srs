#!/usr/bin/env bash

if [[ $# -eq 1 ]]; then
    APPLICATION=$1
fi

usage() {
    echo "Usage: $0 <sfu>"
}

if [[ $# -lt 1 ]]; then
    usage
    exit -1
fi

PWD=`dirname $0`
PWD=`(cd $PWD && pwd)`

ALERT_LOG="$PWD/../logs/watchdog.log"
if [[ ! -d $PWD/../logs ]]; then
    ALERT_LOG="`pwd`/objs/watchdog.log"
fi

case $APPLICATION in
    sfu)
        SERVICE=$PWD/tf_sfu_ctl.sh ;;
    *)
        echo "Invalid application $APPLICATION"
        exit -1
esac

for ((;;)); do
    # Remark: Now we don't use the application name's prefix 'tf_' to check.
    # But check the directory name prefix 'tenfold'.
    # Now SFU(janus) Router(island) are checked by directory name, not $APPLICATION.
    ps aux|grep tf_|grep -v grep|grep -v master|grep -v supervise|grep $APPLICATION|grep conf 1>/dev/null 2>/dev/null
    if [[ $? -ne 0 ]]; then
        echo "`date` RUN: $SERVICE restart $PRODUCT"
        bash $SERVICE start
        pid=`ps aux|grep tf_|grep -v grep|grep -v master|grep -v supervise|grep $APPLICATION|awk '{print $2}'`
        echo "{\"module\":\"$APPLICATION\",\"hostname\":\"$(hostname)\",\"time\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"event\":\"crash\"}" >>${ALERT_LOG}
        echo "PID=${pid}"
    fi

    sleep 3
done
