"""
Check Live ClickHouse Database for Real Ingested Logs
=====================================================
Connects strictly to live ClickHouse on localhost:8123 (or CLICKHOUSE_HOST).
Queries ulpf.logs_normalized and displays actual ingested logs.
Raises an explicit error if ClickHouse is unreachable or table is empty.
"""

import os
import sys
import json

def query_live_clickhouse():
    try:
        import clickhouse_connect
    except ImportError:
        print("[ERROR] clickhouse_connect package not found.")
        sys.exit(1)

    host = os.environ.get("CLICKHOUSE_HOST", "localhost")
    port = int(os.environ.get("CLICKHOUSE_PORT", 8123))

    print(f"Connecting to live ClickHouse at {host}:{port}...")

    try:
        client = clickhouse_connect.get_client(host=host, port=port, database="ulpf")
    except Exception as e:
        print(f"\n[ERROR] COULD NOT CONNECT TO CLICKHOUSE AT {host}:{port}")
        print(f"Details: {e}")
        print("\nPossible Causes:")
        print("1. ClickHouse docker container is not running.")
        print("   -> Run: docker compose -f infra/docker-compose.yml up -d")
        print("2. ClickHouse is running on a different port or host.")
        sys.exit(1)

    print("[OK] Connected to ClickHouse engine successfully!\n")

    # 1. Total row count query
    try:
        count_res = client.query("SELECT count() FROM ulpf.logs_normalized")
        total_rows = count_res.result_rows[0][0]
        print(f"[COUNT] Total Records in 'ulpf.logs_normalized': {total_rows}\n")
    except Exception as e:
        print(f"[ERROR] Table 'ulpf.logs_normalized' does not exist yet or query failed: {e}")
        sys.exit(1)

    if total_rows == 0:
        print("[WARNING] Table 'ulpf.logs_normalized' is currently EMPTY.")
        print("No live logs have been ingested yet.")
        print("Make sure the log-generator and log-consumer services are running:")
        print("  docker compose -f infra/docker-compose.yml up --build")
        sys.exit(0)

    # 2. Fetch log count grouped by log_source / format
    print("[SUMMARY] Ingested Log Summary by Log Source & Severity:")
    summary_res = client.query("""
        SELECT log_source, log_level, severity, count() AS cnt
        FROM ulpf.logs_normalized
        GROUP BY log_source, log_level, severity
        ORDER BY cnt DESC
    """)
    for row in summary_res.result_rows:
        print(f"   * Source: {row[0]:<20} Level: {row[1]:<10} Severity: {row[2]:<10} Count: {row[3]}")

    # 3. Fetch latest 10 live logs
    print("\n[LATEST LOGS] Latest 10 Live Logs in ClickHouse:")
    print("=" * 90)
    logs_res = client.query("""
        SELECT event_id, timestamp, log_source, severity, src_ip, dest_ip, dest_port, action, protocol, raw_message
        FROM ulpf.logs_normalized
        ORDER BY timestamp DESC
        LIMIT 10
    """)
    
    for idx, r in enumerate(logs_res.result_rows, 1):
        print(f"[{idx}] Time: {r[1]} | Source: {r[2]} | Severity: {r[3]}")
        print(f"    Network: {r[4]} -> {r[5]}:{r[6]} ({r[8]})")
        print(f"    Action:  {r[7]}")
        print(f"    Raw Log: {r[9]}")
        print("-" * 90)

if __name__ == "__main__":
    query_live_clickhouse()
