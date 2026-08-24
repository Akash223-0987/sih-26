#!/bin/sh

mkdir -p /logs

i=0

while true
do
    i=$((i + 1))

    echo "$(date -Iseconds) INFO request_id=req-$i method=GET path=/api/users status=200 latency=42ms" >> /logs/application.log

    sleep 2
done