CREATE DATABASE IF NOT EXISTS ulpf;

-- High-performance, columnar log table with ZSTD codecs and partition-based TTL retention
CREATE TABLE IF NOT EXISTS ulpf.logs_normalized (
    event_id UUID,
    timestamp DateTime64(3, 'UTC'),
    log_source LowCardinality(String),
    log_level LowCardinality(String),
    severity LowCardinality(String),
    src_ip String,
    dest_ip String,
    dest_port Nullable(UInt16),
    user_name String,
    action LowCardinality(String),
    protocol LowCardinality(String),
    raw_message String CODEC(ZSTD(3)),
    extra_attributes String CODEC(ZSTD(3))
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (log_source, timestamp, event_id)
TTL toDateTime(timestamp) + INTERVAL 7 DAY DELETE;

-- Security alerts table
CREATE TABLE IF NOT EXISTS ulpf.alerts (
    alert_id UUID,
    timestamp DateTime64(3, 'UTC'),
    rule_name LowCardinality(String),
    severity LowCardinality(String),
    description String,
    src_ip String,
    user_name String,
    correlated_events Array(UUID)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (severity, timestamp, alert_id)
TTL toDateTime(timestamp) + INTERVAL 7 DAY DELETE;
