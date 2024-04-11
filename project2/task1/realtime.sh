#!/bin/bash

taskset -c 0 bash -c "while true; do :; done" &

pid=$!

sudo chrt -r -p 1 $pid
echo Realtime process created

# kill all childs when terminated
trap 'echo -e "\nkilling childs..."; kill $pid' SIGINT SIGTERM SIGQUIT

sleep 600

kill $pid