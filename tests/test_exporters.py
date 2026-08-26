import io
import json
import os
import tempfile
import pytest
from pathlib import Path
from pytrace.config import PyTraceConfig
from pytrace.exporters.composite import CompositeExporter, create_exporter_from_config
from pytrace.exporters.file import FileExporter
from pytrace.exporters.stdout import StdoutExporter
from pytrace.models.event import EventDetails, PyTraceEvent


def test_file_exporter_writes_jsonl():
    with tempfile.TemporaryDirectory() as tmpdir:
        logfile = Path(tmpdir) / "app.log"
        exporter = FileExporter(filepath=str(logfile))

        event1 = PyTraceEvent(event=EventDetails(message="Test 1"))
        event2 = PyTraceEvent(event=EventDetails(message="Test 2"))

        exporter.export(event1)
        exporter.export(event2)

        assert logfile.exists()
        lines = logfile.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

        d1 = json.loads(lines[0])
        d2 = json.loads(lines[1])
        assert d1["event"]["message"] == "Test 1"
        assert d2["event"]["message"] == "Test 2"


def test_stdout_exporter_json():
    buf = io.StringIO()
    exporter = StdoutExporter(json_format=True, stream=buf)

    event = PyTraceEvent(event=EventDetails(message="Console output"))
    exporter.export(event)

    output = buf.getvalue().strip()
    data = json.loads(output)
    assert data["event"]["message"] == "Console output"


def test_stdout_exporter_pretty():
    buf = io.StringIO()
    exporter = StdoutExporter(json_format=False, stream=buf)

    event = PyTraceEvent(event=EventDetails(severity="WARNING", message="Warning test"))
    exporter.export(event)

    output = buf.getvalue().strip()
    assert "[WARNING]" in output
    assert "Warning test" in output


def test_composite_exporter_factory():
    cfg = PyTraceConfig(exporter_type="file,stdout", log_dir="temp_logs")
    exporter = create_exporter_from_config(cfg)

    assert isinstance(exporter, CompositeExporter)
    assert len(exporter.exporters) == 2
