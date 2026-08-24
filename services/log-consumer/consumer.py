import json
import logging
# pyrefly: ignore [missing-import]
from confluent_kafka import Consumer, KafkaError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

KAFKA_BROKER = "kafka:9092"
TOPIC_NAME = "enterprise-logs"

def main():
    logger.info(f"Connecting to Kafka at {KAFKA_BROKER}...")
    
    conf = {
        'bootstrap.servers': KAFKA_BROKER,
        'group.id': 'log-consumer-group',
        'auto.offset.reset': 'earliest'
    }

    consumer = Consumer(conf)
    consumer.subscribe([TOPIC_NAME])

    logger.info(f"Subscribed to topic '{TOPIC_NAME}'. Waiting for messages...")

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                else:
                    logger.error(f"Consumer error: {msg.error()}")
                    continue

            # Parse JSON message
            try:
                log_entry = json.loads(msg.value().decode('utf-8'))
                logger.info(f"Received log: {log_entry}")
            except json.JSONDecodeError:
                logger.info(f"Received raw log: {msg.value().decode('utf-8')}")

    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()

if __name__ == "__main__":
    main()
