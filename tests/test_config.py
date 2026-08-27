from typing import Any, cast
import pytest
from pydantic import ValidationError
from pytrace.config import PyTraceConfig, get_config, set_config


def test_config_empty_values():
    """Test PyTraceConfig with empty string settings (empty inputs)."""
    config = PyTraceConfig(service_name="", environment="", log_dir="", log_file="")
    assert config.service_name == ""
    assert config.environment == ""
    assert config.log_dir == ""
    assert config.log_file == ""


def test_config_invalid_types():
    """Test PyTraceConfig with invalid data types (invalid inputs)."""
    with pytest.raises(ValidationError):
        PyTraceConfig(fluentbit_port=cast(Any, "not-an-integer"))

    with pytest.raises(ValidationError):
        PyTraceConfig(sample_rate=cast(Any, "not-a-float"))


def test_global_config_lifecycle():
    """Test retrieving, setting, and resetting the global configuration object."""
    orig_config = get_config()
    new_config = PyTraceConfig(service_name="custom-global-service")
    set_config(new_config)
    assert get_config().service_name == "custom-global-service"

    # None value testing for set_config
    set_config(cast(Any, None))
    assert get_config().service_name == "default-service"

    # Restore original config
    set_config(orig_config)
