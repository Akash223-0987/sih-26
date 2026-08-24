import os
import json
import time
import datetime
import clickhouse_connect
from neo4j import GraphDatabase

# Database Connection Parameters (Env Variables)
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "ulpf")
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password123")

class DatabaseManager:
    """Manages high-performance storage operations, batching, and pruning for ClickHouse and Neo4j."""
    
    def __init__(self):
        self.ch_client = None
        self.neo4j_driver = None
        self.connect_databases()

    def connect_databases(self):
        """Attempts to establish connection to ClickHouse and Neo4j with a retry loop."""
        for attempt in range(1, 11):
            try:
                # 1. Connect to ClickHouse
                if not self.ch_client:
                    print(f"[Storage] Connecting to ClickHouse ({CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}) - Attempt {attempt}/10")
                    self.ch_client = clickhouse_connect.get_client(
                        host=CLICKHOUSE_HOST,
                        port=CLICKHOUSE_PORT,
                        username=CLICKHOUSE_USER,
                        password=CLICKHOUSE_PASSWORD
                    )
                    # Switch to correct database
                    self.ch_client.database = CLICKHOUSE_DB
                    print("[Storage] ClickHouse connection established.")

                # 2. Connect to Neo4j
                if not self.neo4j_driver:
                    print(f"[Storage] Connecting to Neo4j ({NEO4J_URI}) - Attempt {attempt}/10")
                    self.neo4j_driver = GraphDatabase.driver(
                        NEO4J_URI, 
                        auth=(NEO4J_USER, NEO4J_PASSWORD)
                    )
                    self.neo4j_driver.verify_connectivity()
                    print("[Storage] Neo4j connection established.")
                
                break
            except Exception as e:
                print(f"[Storage] Connection attempt {attempt} failed: {e}")
                time.sleep(4)
        
        if not self.ch_client or not self.neo4j_driver:
            print("[Storage] Warning: Databases are offline. Will retry on demand during write cycles.")

    # ==================== CLICKHOUSE BATCHING WRITES ====================
    
    def insert_logs_batch(self, logs_list):
        """
        Inserts a batch of logs into ClickHouse using columnar stream writing.
        Batching is highly recommended for MergeTree engines to maximize write efficiency.
        """
        if not self.ch_client:
            self.connect_databases()
        
        if not logs_list or not self.ch_client:
            return

        data_rows = []
        for log in logs_list:
            # Map dictionary keys into a list of table column values
            data_rows.append([
                log.get("event_id"),
                log.get("timestamp"),
                log.get("log_source", "unknown"),
                log.get("log_level", "INFO"),
                log.get("severity", "MEDIUM"),
                log.get("src_ip", ""),
                log.get("dest_ip", ""),
                log.get("dest_port"),
                log.get("user_name", ""),
                log.get("action", ""),
                log.get("protocol", ""),
                log.get("raw_message", ""),
                json.dumps(log.get("extra_attributes", {}))
            ])

        try:
            self.ch_client.insert(
                table="logs_normalized",
                data=data_rows,
                column_names=[
                    "event_id", "timestamp", "log_source", "log_level", "severity", 
                    "src_ip", "dest_ip", "dest_port", "user_name", "action", 
                    "protocol", "raw_message", "extra_attributes"
                ],
                database=CLICKHOUSE_DB
            )
            print(f"[Storage] Batch-inserted {len(logs_list)} records into ClickHouse.")
        except Exception as e:
            print(f"[Storage] ClickHouse batch insertion failed: {e}")

    # ==================== NEO4J GRAPH WRITES & CORRELATION ====================

    def correlate_in_neo4j(self, log):
        """
        Extracts key entities (IP, User) from the log and creates nodes/relationships in Neo4j.
        Utilizes UNIQUE constraints on IP(address) and User(username) to optimize performance.
        """
        if not self.neo4j_driver:
            self.connect_databases()
        
        if not self.neo4j_driver:
            return

        src_ip = log.get("src_ip")
        dest_ip = log.get("dest_ip")
        user_name = log.get("user_name")
        event_id = str(log.get("event_id"))
        timestamp_str = log.get("timestamp").isoformat() if isinstance(log.get("timestamp"), datetime.datetime) else str(log.get("timestamp"))

        try:
            with self.neo4j_driver.session() as session:
                # 1. Correlate Network traffic: (IP) -[:CONNECTED_TO]-> (IP)
                if src_ip and dest_ip:
                    dest_port = log.get("dest_port")
                    protocol = log.get("protocol", "TCP")
                    
                    query = """
                    MERGE (src:IP {address: $src_ip})
                    MERGE (dst:IP {address: $dest_ip})
                    CREATE (src)-[:CONNECTED_TO {
                        event_id: $event_id, 
                        timestamp: $timestamp, 
                        port: $dest_port, 
                        protocol: $protocol
                    }]->(dst)
                    """
                    session.run(query, 
                                src_ip=src_ip, 
                                dest_ip=dest_ip, 
                                event_id=event_id, 
                                timestamp=timestamp_str, 
                                dest_port=dest_port, 
                                protocol=protocol)

                # 2. Correlate SSH / OS logins: (IP) -[:AUTHENTICATED]-> (User)
                if src_ip and user_name and user_name not in ("", "SYSTEM", "-"):
                    action = log.get("action", "login")
                    query = """
                    MERGE (src:IP {address: $src_ip})
                    MERGE (u:User {username: $user_name})
                    CREATE (src)-[:AUTHENTICATED {
                        event_id: $event_id, 
                        timestamp: $timestamp, 
                        action: $action
                    }]->(u)
                    """
                    session.run(query, 
                                src_ip=src_ip, 
                                user_name=user_name, 
                                event_id=event_id, 
                                timestamp=timestamp_str, 
                                action=action)
        except Exception as e:
            print(f"[Storage] Neo4j relationship correlation failed: {e}")

    # ==================== NEO4J GRAPH STORAGE PRUNING ====================

    def prune_old_graph_data(self, retention_days=7):
        """
        Manually prunes Neo4j data to prevent database size buildup.
        Deletes relationships older than retention days and sweeps orphan nodes (no degrees).
        """
        if not self.neo4j_driver:
            self.connect_databases()
        
        if not self.neo4j_driver:
            return

        cutoff_datetime = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
        cutoff_iso = cutoff_datetime.isoformat()

        print(f"[Storage] Starting Neo4j graph pruning (older than {retention_days} days)...")
        try:
            with self.neo4j_driver.session() as session:
                # Step 1: Delete old relationships
                res_rel = session.run("""
                MATCH ()-[r]->()
                WHERE r.timestamp < $cutoff_iso
                DELETE r
                """, cutoff_iso=cutoff_iso)
                
                # Step 2: Delete nodes with 0 connections (orphan cleanup)
                res_node = session.run("""
                MATCH (n)
                WHERE NOT (n)--()
                DELETE n
                """)
            print("[Storage] Neo4j graph pruning and orphan sweep complete.")
        except Exception as e:
            print(f"[Storage] Neo4j graph pruning failed: {e}")

    def close(self):
        """Closes the Neo4j driver connection."""
        if self.neo4j_driver:
            self.neo4j_driver.close()
            print("[Storage] Neo4j driver connection closed.")
