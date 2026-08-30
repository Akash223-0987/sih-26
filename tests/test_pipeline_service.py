import pytest

from services.pipeline_service import PipelineService, StreamConfig


@pytest.mark.asyncio
async def test_batch_publishes_and_commits_after_processing():
    service = PipelineService(config=StreamConfig(batch_size=2))
    published = []
    committed = []

    async def publish(topic, payload):
        published.append((topic, payload))

    async def commit():
        committed.append(True)

    await service.process_batch(
        [b'{"message":"routine health check"}', b'not-json but valid raw log'],
        publish,
        commit,
    )

    assert [topic for topic, _ in published].count("logs.normalized") == 2
    assert {topic for topic, _ in published} >= {"logs.normalized", "ulpf.clickhouse", "ulpf.neo4j"}
    assert committed == [True]
    assert all(payload["ml_processed"] for topic, payload in published if topic == "logs.normalized")


@pytest.mark.asyncio
async def test_malformed_pipeline_result_goes_to_dlq_without_crashing():
    service = PipelineService()
    service.pipeline.process = lambda _: (_ for _ in ()).throw(ValueError("bad record"))
    published = []

    async def publish(topic, payload):
        published.append((topic, payload))

    async def commit():
        pass

    await service.process_batch([b"raw malformed payload"], publish, commit)
    assert published[0][0] == "logs.dlq"
    assert published[0][1]["ml_processed"] is False
    assert published[0][1]["raw_payload"] == "raw malformed payload"
    assert "ValueError" in published[0][1]["error_traceback"]


def test_alert_threshold_is_confidence_or_anomaly_based():
    service = PipelineService(config=StreamConfig(alert_confidence=0.85, alert_anomaly_score=0.90))
    status, payload = service.process_message(b"nmap port scan detected")
    assert status == "ok"
    assert payload["alert"] is True
