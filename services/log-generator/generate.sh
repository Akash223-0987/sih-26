#!/bin/sh

mkdir -p /logs

i=0

while true
do
    i=$((i + 1))
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z")
    
    # Emit PyTrace canonical JSON structured event
    cat <<EOF >> /logs/application.log
{"timestamp":"${TIMESTAMP}","service":"user-service","environment":"production","framework":"fastapi","event":{"type":"http_request","action":"completed","severity":"INFO","message":"GET /api/users/user-${i} completed with 200 in 14.5ms"},"http":{"method":"GET","path":"/api/users/user-${i}","route":"/api/users/{user_id}","status_code":200,"client_ip":"192.168.1.10","user_agent":"Mozilla/5.0"},"duration_ms":14.5,"trace":{"trace_id":"trace-${i}00000000000000000000000","span_id":"span-${i}00000000","request_id":"req-${i}"},"attributes":{"user_id":"user-${i}","tenant":"corp-alpha"},"metadata":{"hostname":"app-node-01","pid":101,"sdk_name":"pytrace","sdk_version":"0.1.0"}}
EOF

    sleep 2
done