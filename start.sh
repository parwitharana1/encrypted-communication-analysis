#!/bin/bash
ZEEK_PATH=
zeek_running=0
check_zeek(){
    if pgrep -x zeek > /dev/null; then
        zeek_running=1
    fi
}

start_zeek(){
    sh sudo zeek -i enp3s0 -C LogAscii::use_json=T &
}

start_script(){
    tail -n 0 -F $ZEEK_PATH | python ./main.py 
}

check_zeek
if ["$zeek_running" -eq 1]; then
    start_script
    echo "success"
else
    echo "zeek not running"
fi

