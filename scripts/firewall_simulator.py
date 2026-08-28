import os
import json
import time
import random
import urllib.request
import signal

# Ingestion endpoint, resolving to local or container network service
METRICS_ENDPOINT = os.environ.get("METRICS_ENDPOINT", "http://localhost:4318/v1/metrics")

running = True

def handle_shutdown(signum, frame):
    global running
    print("\nShutting down firewall simulator gracefully...")
    running = False

# Register shutdown signals
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

def send_metrics(payload):
    req = urllib.request.Request(
        METRICS_ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=3.0) as res:
            res.read()
    except Exception as e:
        print(f"[Firewall Sim] Failed to ship metrics to {METRICS_ENDPOINT}: {e}", flush=True)

def main():
    print(f"Firewall Simulator Active. Targeting endpoint: {METRICS_ENDPOINT}", flush=True)
    
    # Cumulative packet errors counter starts at 3
    packet_errors = 3
    packets_in = 18421
    packets_out = 15823
    
    while running:
        now_ns = str(time.time_ns())
        
        # 1. Generate realistic values close to user request screenshot (fluctuating naturally)
        cpu_load = random.uniform(42.0, 48.0) if random.random() < 0.95 else random.uniform(85.0, 95.0)  # Average 45%
        memory_load = random.uniform(59.0, 63.0) if random.random() < 0.95 else random.uniform(88.0, 93.0)  # Average 61%
        
        network_in = random.uniform(115.0, 135.0)  # Average 125 MB/s
        network_out = random.uniform(75.0, 90.0)    # Average 82 MB/s
        
        active_connections = random.randint(500, 525)  # Average 512
        
        # 10% chance of a new packet error
        if random.random() < 0.10:
            packet_errors += 1

        payload = {
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "device 1"}},
                            {"key": "device.model", "value": {"stringValue": "FW-NextGen-100"}},
                            {"key": "device.location", "value": {"stringValue": "data-center-east"}}
                        ]
                    },
                    "scopeMetrics": [
                        {
                            "scope": {"name": "firewall-metrics-collector"},
                            "metrics": [
                                {
                                    "name": "cpu.utilization",
                                    "description": "Firewall Core CPU utilization percentage",
                                    "unit": "%",
                                    "gauge": {
                                        "dataPoints": [{"timeUnixNano": now_ns, "asDouble": cpu_load, "attributes": []}]
                                    }
                                },
                                {
                                    "name": "memory.utilization",
                                    "description": "Firewall RAM usage percentage",
                                    "unit": "%",
                                    "gauge": {
                                        "dataPoints": [{ "timeUnixNano": now_ns, "asDouble": memory_load, "attributes": []}]
                                    }
                                },
                                {
                                    "name": "network.in",
                                    "description": "Network input rate",
                                    "unit": "MB/s",
                                    "gauge": {
                                        "dataPoints": [{"timeUnixNano": now_ns, "asDouble": network_in, "attributes": []}]
                                    }
                                },
                                {
                                    "name": "network.out",
                                    "description": "Network output rate",
                                    "unit": "MB/s",
                                    "gauge": {
                                        "dataPoints": [{"timeUnixNano": now_ns, "asDouble": network_out, "attributes": []}]
                                    }
                                },
                                {
                                    "name": "packets.in",
                                    "description": "Firewall input packets count",
                                    "unit": "count",
                                    "sum": {
                                        "dataPoints": [{"timeUnixNano": now_ns, "asInt": packets_in, "attributes": []}]
                                    }
                                },
                                {
                                    "name": "packets.out",
                                    "description": "Firewall output packets count",
                                    "unit": "count",
                                    "sum": {
                                        "dataPoints": [{"timeUnixNano": now_ns, "asInt": packets_out, "attributes": []}]
                                    }
                                },
                                {
                                    "name": "active_connections",
                                    "description": "Number of active parallel sessions",
                                    "unit": "sessions",
                                    "gauge": {
                                        "dataPoints": [{"timeUnixNano": now_ns, "asInt": active_connections, "attributes": []}]
                                    }
                                },
                                {
                                    "name": "packet_errors",
                                    "description": "Cumulative packet drop/corrupt count",
                                    "unit": "count",
                                    "sum": {
                                        "dataPoints": [{"timeUnixNano": now_ns, "asInt": packet_errors, "attributes": []}]
                                    }
                                }
                             ]
                        }
                    ]
                }
            ]
        }
        
        send_metrics(payload)
        
        # Format terminal output to match exactly
        local_time_str = time.strftime("%H:%M:%S")
        output = [
            f"Device Name: device 1",
            f"Timestamp: {local_time_str}\n",
            f"{'CPU Usage':<20} = {cpu_load:.1f} %",
            f"{'Memory Usage':<20} = {memory_load:.1f} %",
            f"{'Network In':<20} = {network_in:.1f} MB/s",
            f"{'Network Out':<20} = {network_out:.1f} MB/s",
            f"{'Packets In':<20} = {packets_in:,}",
            f"{'Packets Out':<20} = {packets_out:,}",
            f"{'Active Connections':<20} = {active_connections}",
            f"{'Packet Errors':<20} = {packet_errors}"
        ]
        
        # Clear screen and draw
        print("\033[H\033[2J", end="", flush=True)
        print("\n".join(output), flush=True)
        
        # Increment packets for the next second
        packets_in += random.randint(10, 50)
        packets_out += random.randint(5, 40)
        time.sleep(1)

if __name__ == "__main__":
    main()
