import hashlib
import logging
from time import perf_counter

import pytest

from pytrace.ml import ULPFPipeline
from pytrace.ml.features import LogVectorizer
from pytrace.ml.model_engine import ModelEngine


def _classification_metrics(actual, predicted):
    labels = {"Benign", "Port Scan", "Brute Force", "Exfiltration", "Lateral Movement"}
    true_positive = sum(expected == observed for expected, observed in zip(actual, predicted))
    accuracy = true_positive / len(actual)
    precisions = []
    recalls = []
    for label in labels:
        tp = sum(expected == label and observed == label for expected, observed in zip(actual, predicted))
        fp = sum(expected != label and observed == label for expected, observed in zip(actual, predicted))
        fn = sum(expected == label and observed != label for expected, observed in zip(actual, predicted))
        precisions.append(tp / (tp + fp) if tp + fp else 0.0)
        recalls.append(tp / (tp + fn) if tp + fn else 0.0)
    precision = sum(precisions) / len(labels)
    recall = sum(recalls) / len(labels)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return accuracy, precision, recall, f1


def test_pipeline_preserves_hash_and_routes_entities():
    raw = "src_ip=10.0.0.1 dst_ip=10.0.0.2 dst_port=22 protocol=tcp action=port_scan"
    processed = ULPFPipeline().process(raw)
    inference = processed.inference

    assert inference.normalized.raw_log == raw
    assert inference.normalized.raw_log_sha256 == hashlib.sha256(raw.encode()).hexdigest()
    assert inference.normalized.src_ip == "10.0.0.1"
    assert inference.normalized.dst_ip == "10.0.0.2"
    assert processed.routes.neo4j["relationship"] == "CONNECTS_TO"
    assert processed.routes.siem["raw_log_sha256"] == inference.normalized.raw_log_sha256


def test_pipeline_accepts_structured_logs_and_bounds_scores():
    processed = ULPFPipeline().process({"message": "failed password from 10.0.0.4", "service": "ssh"})
    assert processed.inference.threat_label == "Brute Force"
    assert 0.0 <= processed.inference.anomaly_score <= 1.0
    assert 0.0 <= processed.inference.threat_confidence <= 1.0
    assert 0.0 <= processed.inference.risk_score <= 1.0
    assert len(processed.inference.embedding) == 384


def test_vectorizer_validates_shape_and_dtype():
    vectorizer = LogVectorizer(dimensions=8)
    embedding = vectorizer.transform("protocol=tcp")
    assert len(embedding) == 8
    assert all(isinstance(value, float) for value in embedding)
    with pytest.raises(ValueError):
        LogVectorizer(dimensions=3)


def test_inference_latency_is_bounded():
    pipeline = ULPFPipeline()
    started = perf_counter()
    result = pipeline.process("src_ip=10.0.0.1 dst_ip=10.0.0.2 protocol=tcp")
    elapsed_ms = (perf_counter() - started) * 1000
    assert result.inference.processing_ms >= 0
    assert elapsed_ms < 100, "CI-safe upper bound; production target remains sub-10ms"


def test_validation_split_metrics_meet_minimum_threshold(caplog):
    validation_split = [
        ("routine health check", "Benign"),
        ("nmap port scan detected", "Port Scan"),
        ("failed password for invalid user", "Brute Force"),
        ("large upload exfiltration", "Exfiltration"),
        ("psexec remote service", "Lateral Movement"),
    ]
    pipeline = ULPFPipeline()
    actual = [label for _, label in validation_split]
    predicted = [pipeline.process(text).inference.threat_label for text, _ in validation_split]
    accuracy, precision, recall, f1 = _classification_metrics(actual, predicted)
    with caplog.at_level(logging.INFO):
        logging.getLogger(__name__).info(
            "validation metrics accuracy=%.3f precision=%.3f recall=%.3f f1=%.3f",
            accuracy, precision, recall, f1,
        )
    assert accuracy >= 0.80
    assert precision >= 0.80
    assert recall >= 0.80
    assert f1 >= 0.80
    assert "validation metrics" in caplog.text


@pytest.mark.parametrize("raw", ["", "   ", {"message": None, "src_ip": None}])
def test_empty_and_missing_values_are_handled(raw):
    processed = ULPFPipeline().process(raw)
    assert processed.inference.normalized.raw_log_sha256
    assert len(processed.inference.embedding) == 384
    assert 0.0 <= processed.inference.risk_score <= 1.0


def test_zero_variance_inputs_remain_finite():
    vectorizer = LogVectorizer(dimensions=8)
    embedding = vectorizer.transform("same same same same")
    assert all(value == value and abs(value) <= 1.0 for value in embedding)


def test_engine_contract_is_offline_deterministic_and_traceable():
    raw = "2026-08-26T12:00:00Z session=abcdef0123456789abcdef0123456789 nmap port scan \u2603"
    first = ModelEngine(dimensions=384).infer(raw)
    second = ModelEngine(dimensions=384).infer(raw)
    payload = first.to_dict()

    assert set(payload) == {
        "embedding", "predicted_label", "threat_confidence",
        "anomaly_score", "raw_log_sha256",
    }
    assert len(payload["embedding"]) == 384
    assert payload["predicted_label"] == "Reconnaissance"
    assert payload["raw_log_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert first.embedding == second.embedding
    assert 0.0 <= payload["threat_confidence"] <= 1.0
    assert 0.0 <= payload["anomaly_score"] <= 1.0


@pytest.mark.parametrize(
    ("raw", "expected_label"),
    [
        ("GET /health status=success", "Benign"),
        ("scheduled backup completed protocol=ssh", "Benign"),
        ("MASSCAN detected against subnet", "Reconnaissance"),
        ("phishing payload delivered to mailbox", "Initial Access"),
        ("powershell script execute encoded command", "Execution"),
        ("staged data large upload to external host", "Exfiltration"),
        ("WINRM remote service lateral movement", "Lateral Movement"),
        ("unseen event format with unicode character \u2603", "Benign"),
    ],
)
def test_varied_threat_inputs_produce_expected_taxonomy(raw, expected_label):
    result = ULPFPipeline().process(raw).inference

    assert result.predicted_label == expected_label
    assert result.threat_label in {
        "Benign", "Port Scan", "Brute Force", "Exfiltration", "Lateral Movement",
        "Reconnaissance", "Initial Access", "Execution",
    }
    assert 0.0 <= result.threat_confidence <= 1.0
    assert 0.0 <= result.anomaly_score <= 1.0


def test_varied_structured_payloads_preserve_attributes_and_hashes():
    payloads = [
        {"message": "allow connection", "src_ip": "192.0.2.10", "dst_port": 443, "vendor": "firewall-a"},
        {"message": "successful user login", "source.ip": "192.0.2.11", "request_id": "req-42"},
        {"log": "data transfer complete", "protocol": "https", "bytes": 4096},
    ]

    results = [ULPFPipeline().process(payload).inference for payload in payloads]

    assert [result.predicted_label for result in results] == ["Benign", "Benign", "Exfiltration"]
    assert results[0].normalized.vendor == "firewall-a"
    assert results[1].normalized.attributes["request_id"] == "req-42"
    assert results[2].normalized.attributes["bytes"] == 4096
    assert len({result.normalized.raw_log_sha256 for result in results}) == 3
