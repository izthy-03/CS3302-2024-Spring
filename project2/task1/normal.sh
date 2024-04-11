#!/bin/bash

# create 10 cpu-intensive processes
for i in {1..10}; do
    taskset -c 0 bash -c "while true; do :; done" &
done

pids=$(pgrep -P $$)

for pid in $(echo "$pids" | head -n 5); do
    sudo renice -n -2 -p $pid
done

for pid in $(echo "$pids" | tail -n 5); do
    sudo renice -n 2 -p $pid
done

# kill all childs when terminated
trap 'echo -e "\nkilling childs..."; kill $pids' SIGINT SIGTERM SIGQUIT

sleep 600

kill $pids