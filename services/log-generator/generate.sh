#!/bin/sh
# ULPF Universal Log Generator
# Emits realistic log lines in 7 industry formats to separate files.
# Each file is consumed by its dedicated Fluent Bit INPUT block.

mkdir -p /logs

i=0

while true
do
    i=$((i + 1))
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z")
    SYSLOG_TS=$(date -u +"%b %d %H:%M:%S")
    APACHE_TS=$(date -u +"%d/%b/%Y:%H:%M:%S +0000")
    WIN_TS=$(date -u +"%Y-%m-%dT%H:%M:%S")

    # 1. PyTrace canonical JSON (application layer)
    cat <<EOF >> /logs/application.log
{"timestamp":"${TIMESTAMP}","service":"user-service","environment":"production","framework":"fastapi","event":{"type":"http_request","action":"completed","severity":"INFO","message":"GET /api/users/user-${i} completed with 200 in 14.5ms"},"http":{"method":"GET","path":"/api/users/user-${i}","route":"/api/users/{user_id}","status_code":200,"client_ip":"192.168.1.10","user_agent":"Mozilla/5.0"},"duration_ms":14.5,"trace":{"trace_id":"trace-${i}00000000000000000000000","span_id":"span-${i}00000000","request_id":"req-${i}"},"attributes":{"user_id":"user-${i}","tenant":"corp-alpha"},"metadata":{"hostname":"app-node-01","pid":101,"sdk_name":"pytrace","sdk_version":"0.1.0"}}
EOF

    # 2. Syslog RFC 5424 (modern firewall / Linux kernel)
    cat <<EOF >> /logs/syslog_rfc5424.log
<134>1 ${TIMESTAMP} fw-node-01 kernel ${i} - - Firewall ACCEPT src=10.0.0.${i} dst=8.8.8.8 dpt=443 proto=TCP
EOF

    # 3. Syslog RFC 3164 (BSD syslog — Cisco, Juniper, legacy routers)
    cat <<EOF >> /logs/syslog_rfc3164.log
<190>${SYSLOG_TS} router01 sshd[${i}]: Accepted publickey for admin from 192.168.1.${i} port 51234 ssh2
EOF

    # 4. CEF (Palo Alto / Fortinet / Check Point / ArcSight)
    cat <<EOF >> /logs/cef.log
CEF:0|Palo Alto Networks|PAN-OS|10.1|threat/virus|Eicar-Test-File|8|src=10.0.0.${i} dst=172.16.0.5 dpt=80 proto=TCP act=block app=web-browsing user=corp\\user-${i} deviceExternalId=PA-VM-01
EOF

    # 5. LEEF (IBM QRadar)
    printf "LEEF:2.0|IBM|QRadar SIEM|7.5|UserLogin|devTime=${SYSLOG_TS}\tsrc=192.168.1.${i}\tdst=10.10.0.1\tusrName=analyst-${i}\tidentSrc=ActiveDirectory\toutcome=success\n" >> /logs/leef.log

    # 6. Apache / Nginx Combined Access Log
    cat <<EOF >> /logs/apache_access.log
192.168.1.${i} - user-${i} [${APACHE_TS}] "POST /api/login HTTP/1.1" 200 1024 "https://corp.example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
EOF

    # 7. Windows Event Log (NXLog CSV export)
    cat <<EOF >> /logs/windows_events.log
${WIN_TS},Security,4624,user-${i},WORKSTATION-${i},192.168.1.${i},Interactive Logon
EOF

    sleep 2
done