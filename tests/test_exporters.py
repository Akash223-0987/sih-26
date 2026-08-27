import io
import json
import os
import tempfile
import sys
import socket
from typing import Any, cast, List
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pytrace.config import PyTraceConfig
from pytrace.exporters.base import BaseExporter
from pytrace.exporters.composite import CompositeExporter, create_exporter_from_config
from pytrace.exporters.file import FileExporter
from pytrace.exporters.stdout import StdoutExporter
from pytrace.exporters.fluentbit import FluentBitExporter
from pytrace.exporters.http import HttpExporter
from pytrace.models.event import EventDetails, PyTraceEvent, HttpDetails


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


# ==============================================================================
# EDGE CASES & BOUNDARY VALUES
# ==============================================================================

def test_stdout_exporter_json_and_pretty_edge_cases():
    """Test StdoutExporter pretty format logic with None variables and error resilience."""
    # None values: duration_ms = None, http = None
    buf_pretty = io.StringIO()
    exporter_pretty = StdoutExporter(json_format=False, stream=buf_pretty)
    event_none = PyTraceEvent(
        event=EventDetails(message="pretty-test", severity="INFO"),
        http=None,
        duration_ms=None
    )
    exporter_pretty.export(event_none)
    assert "[INFO]" in buf_pretty.getvalue()
    assert "pretty-test" in buf_pretty.getvalue()

    # HttpDetails present but duration_ms is None (boundary case)
    buf_pretty2 = io.StringIO()
    exporter_pretty2 = StdoutExporter(json_format=False, stream=buf_pretty2)
    event_http_no_duration = PyTraceEvent(
        event=EventDetails(message="pretty-test-http", severity="INFO"),
        http=HttpDetails(method="GET", path="/test"),
        duration_ms=None
    )
    exporter_pretty2.export(event_http_no_duration)
    assert "[GET /test]" in buf_pretty2.getvalue()

    # Exception handling: write fails (e.g. stream raises Exception)
    bad_stream = MagicMock()
    bad_stream.write.side_effect = Exception("Write failed")
    exporter_bad = StdoutExporter(stream=bad_stream)

    # Should gracefully capture exception internally and log to sys.stderr
    with patch("sys.stderr.write") as mock_stderr:
        exporter_bad.export(event_none)
        mock_stderr.assert_called_once()
        assert "StdoutExporter error" in mock_stderr.call_args[0][0]


def test_file_exporter_error_handling():
    """Test FileExporter resilient fallback when target paths are invalid or unwritable."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Pass a directory path instead of a file path, causing write permission exception
        exporter = FileExporter(filepath=tmpdir)
        event = PyTraceEvent(event=EventDetails(message="should fail writing to directory"))

        with patch("sys.stderr.write") as mock_stderr:
            exporter.export(event)
            mock_stderr.assert_called_once()
            assert "FileExporter error writing to" in mock_stderr.call_args[0][0]


def test_http_exporter_failures():
    """Test HttpExporter urllib exception resilience on malformed endpoints."""
    event = PyTraceEvent(event=EventDetails(message="http export test"))

    # Exception handling: invalid URL or network exceptions
    exporter_bad = HttpExporter(endpoint_url="invalid-url")
    exporter_bad.export(event)  # Should fail silently

    exporter_none = HttpExporter(endpoint_url=cast(Any, None))
    exporter_none.export(event)  # Should fail silently


@patch("socket.socket")
def test_fluentbit_exporter_mocked(mock_socket_class):
    """Test FluentBitExporter TCP socket connection failures and re-connect operations."""
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # 1. Connection failure
    mock_socket.connect.side_effect = Exception("Connection refused")
    exporter = FluentBitExporter(host="127.0.0.1", port=24224)
    event = PyTraceEvent(event=EventDetails(message="fluentbit log"))

    exporter.export(event)  # Should fail silently
    assert exporter._sock is None

    # 2. Connection success
    mock_socket.connect.side_effect = None
    exporter_success = FluentBitExporter(host="127.0.0.1", port=24224)
    exporter_success.export(event)

    assert exporter_success._sock is not None
    mock_socket.sendall.assert_called_once()

    # 3. Connection dropped, sendall raises exception, reconnect succeeds
    mock_socket.sendall.reset_mock()
    mock_socket.sendall.side_effect = [Exception("Socket closed"), None]

    exporter_success.export(event)
    # The first sendall fails, closes the socket, reconnects, then calls sendall again
    assert mock_socket.sendall.call_count == 2
    mock_socket.close.assert_called_once()


def test_composite_exporter_and_factory_edge_cases():
    """Test composite pipeline factory with empty, whitespace, and unknown targets."""
    # Empty string configuration fallback
    cfg_empty = PyTraceConfig(exporter_type="")
    exporter_empty = create_exporter_from_config(cfg_empty)
    assert isinstance(exporter_empty, StdoutExporter)

    # Whitespaces and multiple entries parsing
    cfg_spaces = PyTraceConfig(exporter_type="  file ,  stdout  ", log_dir="temp_logs")
    exporter_spaces = create_exporter_from_config(cfg_spaces)
    assert isinstance(exporter_spaces, CompositeExporter)
    assert len(exporter_spaces.exporters) == 2
    assert isinstance(exporter_spaces.exporters[0], FileExporter)
    assert isinstance(exporter_spaces.exporters[1], StdoutExporter)

    # Unknown exporter config targets
    cfg_unknown = PyTraceConfig(exporter_type="unknown_target")
    exporter_unknown = create_exporter_from_config(cfg_unknown)
    assert isinstance(exporter_unknown, StdoutExporter)

    # Composite pipeline exceptions tolerance
    bad_exporter = MagicMock()
    bad_exporter.export.side_effect = Exception("Fail")
    good_exporter = MagicMock()

    comp = CompositeExporter([bad_exporter, good_exporter])
    event = PyTraceEvent()
    comp.export(event)  # Should not raise exception
    bad_exporter.export.assert_called_once_with(event)
    good_exporter.export.assert_called_once_with(event)

    # Flush/close operations tolerance
    bad_exporter.flush.side_effect = Exception("Flush fail")
    bad_exporter.close.side_effect = Exception("Close fail")
    comp.flush()
    comp.close()
    bad_exporter.flush.assert_called_once()
    bad_exporter.close.assert_called_once()
    good_exporter.flush.assert_called_once()
    good_exporter.close.assert_called_once()
