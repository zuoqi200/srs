#!/usr/bin/env bash

ACTION=$1
if [[ $# -eq 2 ]]; then
    APPLICATION=$2
fi

usage() {
    echo "Usage: $0 <start|stop|restart> <sfu>"
    echo "       $0 <start|stop|restart> <sfu>"
}

if [[ $# -lt 2 ]]; then
    usage
    exit -1
fi

PWD=`dirname $0`
PWD=`(cd $PWD && pwd)`
MASTER=$PWD/tf_master_ctl.sh

case $APPLICATION in
    sfu)
        SERVICE=$PWD/tf_sfu_ctl.sh ;;
    *)
        echo "Invalid application $APPLICATION"
        exit -1
esac

# TODO: FIXME: Config log in conf file.
LOG="$PWD/../logs/superviser.log"
if [[ ! -d $PWD/../logs ]]; then
    LOG="`pwd`/objs/superviser.log"
fi
ALERT_LOG="$PWD/../logs/watchdog.log"
if [[ ! -d $PWD/../logs ]]; then
    ALERT_LOG="`pwd`/objs/watchdog.log"
fi

start() {
    echo "start master"
    echo "{\"module\":\"$APPLICATION\",\"hostname\":\"$(hostname)\",\"time\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"event\":\"start\"}" >>${ALERT_LOG}
    # Remark: We start the application before master to avoid the
    # publish make a crash event..
    bash $SERVICE restart
    nohup $MASTER $APPLICATION >>$LOG 2>&1 &
    
}

stop() {
    echo "{\"module\":\"$APPLICATION\",\"hostname\":\"$(hostname)\",\"time\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"event\":\"stop\"}" >>${ALERT_LOG}
    pid=`ps aux|grep tf_|grep -v grep|grep master|grep $APPLICATION|awk '{print $2}'`
    if [[ $pid == "" ]]; then
        echo "no master"
    else
        echo "kill $pid"
        kill $pid
    fi

    # Stop the application by script becasue we don't know the application's real binary name.
    bash $SERVICE stop
}

upgrade() {
    # upgrade application service
    echo "start upgrade"
    echo "{\"module\":\"$APPLICATION\",\"hostname\":\"$(hostname)\",\"time\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"event\":\"upgrade\"}" >>${ALERT_LOG}
    bash $SERVICE upgrade
}

status() {
    ps aux|grep tf_|grep -v grep|grep -v master|grep -v supervise|grep $APPLICATION
    ps aux|grep tf_|grep -v grep|grep master|grep $APPLICATION
}

check_watchdog() {
	ps aux|grep tf_master_ctl|grep $APPLICATION
	if [[ 0 -ne $? ]]; then
		echo "no watchdog"
		exit -1
	fi
}

case "$ACTION" in
    start)
        start
        ;;

    restart)
        stop
        sleep 0.8
        start
        ;;

    status)
        status
        ;;

    stop)
        stop
        ;;

    upgrade)
        # When upgrade, the watchdog should be alive, to keep the process exists.
        # http://gitlab.alibaba-inc.com/AliRTC/sophon-infra/issues/64363
        check_watchdog
        upgrade
        ;;

    *)
        usage
esac
