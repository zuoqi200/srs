#!/bin/sh
#
# tf_sfu          Start/Stop the Tenfold SFU daemon.
#
# chkconfig: 2345 99 60
# description: Tenfold SFU is a Aliyun RTC Mediad Process program

### BEGIN INIT INFO
# Provides: Tenfold SFU
# Required-Start: $local_fs
# Required-Stop: $local_fs
# Default-Start:  2345
# Default-Stop: 90
# Short-Description: run tenfold SFU daemon
# description: Tenfold SFU is a Aliyun RTC Mediad Process program
### END INIT INFOf

retval=0
prog=sfu
exec=/home/admin/tenfold-sfu/objs/tf_supervise_ctl.sh

start() {
    echo -n $"Starting $prog: "
    su admin $exec start $prog
    retval=$?
    echo $retval
}

stop() {
    echo -n $"Stopping $prog: "
	su admin $exec stop $prog
    retval=$?
    echo $retval 
}

restart() {
    stop
    start
}

upgrade() {
    echo -n $"upgrading $prog: "
	su admin $exec upgrade $prog
    retval=$?
    echo $retval 
}

status() {
    echo -n $"status $prog: "
	su admin $exec status $prog
    retval=$?
    echo $retval 
}


case "$1" in
    start)
        $1
        ;;
    stop)
        $1
        ;;
    restart)
        $1
        ;;
    upgrade)
        $1
        ;;
    status)
        $1
        ;;
    
    *)
        echo $"Usage: $0 {start|stop|status|restart|upgrade}"
        exit 2
esac
exit $?