import asyncio

import pytest

from pytrace.adapters.clickhouse_adapter import ClickHouseAdapter
from pytrace.adapters.neo4j_adapter import Neo4jAdapter
from pytrace.ml import ULPFPipeline


def result():
    return ULPFPipeline().process("src_ip=10.0.0.1 dst_ip=10.0.0.2 dst_port=443 protocol=tcp action=allow").inference


def test_clickhouse_record_has_columnar_types():
    record = ClickHouseAdapter.format_record(result())
    assert isinstance(record["embedding"], list)
    assert all(isinstance(value, float) for value in record["embedding"])
    assert len(record["raw_log_sha256"]) == 64
    assert isinstance(record["threat_confidence"], float)


def test_neo4j_transform_uses_idempotent_merge_statements():
    statements = Neo4jAdapter().transform(result())
    assert statements
    assert all("MERGE" in statement["cypher"] for statement in statements)
    assert statements[0]["parameters"]["src"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_clickhouse_flushes_at_batch_size_and_on_close():
    batches = []

    async def writer(batch):
        batches.append(batch)

    adapter = ClickHouseAdapter(writer=writer, batch_size=2)
    await adapter.add(result())
    assert batches == []
    await adapter.add(result())
    assert len(batches) == 1
    await adapter.add(result())
    await adapter.close()
    assert len(batches) == 2
