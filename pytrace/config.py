"""
PyTrace Global Configuration.
Loads settings from arguments or environment variables with intelligent defaults.
"""

from __future__ import annotations

import os
from typing import List, Optional
from pydantic import BaseModel, Field


class PyTraceConfig(BaseModel):
    """Configuration options for PyTrace SDK."""
    service_name: str = Field(
        default_factory=lambda: os.getenv("PYTRACE_SERVICE_NAME") or os.getenv("SERVICE_NAME") or "default-service"
    )
    environment: str = Field(
        default_factory=lambda: os.getenv("PYTRACE_ENV") or os.getenv("ENVIRONMENT") or "development"
    )
    log_dir: str = Field(
        default_factory=lambda: os.getenv("PYTRACE_LOG_DIR") or "logs"
    )
    log_file: str = Field(
        default_factory=lambda: os.getenv("PYTRACE_LOG_FILE") or "application.log"
    )
    exporter_type: str = Field(
        default_factory=lambda: os.getenv("PYTRACE_EXPORTER") or "file,stdout"
    )
    log_level: str = Field(
        default_factory=lambda: os.getenv("PYTRACE_LOG_LEVEL") or "INFO"
    )
    fluentbit_host: str = Field(
        default_factory=lambda: os.getenv("PYTRACE_FLUENTBIT_HOST") or "127.0.0.1"
    )
    fluentbit_port: int = Field(
        default_factory=lambda: int(os.getenv("PYTRACE_FLUENTBIT_PORT", "24224"))
    )
    capture_headers: bool = Field(
        default_factory=lambda: os.getenv("PYTRACE_CAPTURE_HEADERS", "true").lower() in ("true", "1", "yes")
    )
    capture_query_params: bool = Field(
        default_factory=lambda: os.getenv("PYTRACE_CAPTURE_QUERY_PARAMS", "true").lower() in ("true", "1", "yes")
    )
    capture_raw_event: bool = Field(
        default_factory=lambda: os.getenv("PYTRACE_CAPTURE_RAW", "false").lower() in ("true", "1", "yes")
    )
    mask_headers: List[str] = Field(
        default_factory=lambda: ["authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"]
    )
    include_response_headers: bool = Field(default=True)
    sample_rate: float = Field(default=1.0)


# Global default configuration instance
_global_config: Optional[PyTraceConfig] = None


def get_config() -> PyTraceConfig:
    """Retrieve global configuration or instantiate with defaults."""
    global _global_config
    if _global_config is None:
        _global_config = PyTraceConfig()
    return _global_config


def set_config(config: PyTraceConfig) -> None:
    """Update global configuration."""
    global _global_config
    _global_config = config
