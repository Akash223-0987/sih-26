# PyTrace Test Cases & Run Report

This document details all **43 passing test cases** implemented for the `pytrace` observability framework, including the live execution report.

---

## 1. Live Test Execution Report

* **Execution Timestamp**: 2026-08-27T19:00:13Z
* **Environment**: Windows (Python 3.11.9, pytest-9.0.2, pluggy-1.6.0)
* **Outcome**: **43 passed**, 1 warning in 0.58s

### Execution Log Output:
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0 -- E:\Python\python.exe
cachedir: .pytest_cache
rootdir: E:\sih-26
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.12.1, timeout-2.4.0
collecting ... collected 43 items

tests/test_config.py::test_config_empty_values PASSED                    [  2%]
tests/test_config.py::test_config_invalid_types PASSED                   [  4%]
tests/test_config.py::test_global_config_lifecycle PASSED                [  6%]
tests/test_context.py::test_trace_id_generation PASSED                   [  9%]
tests/test_context.py::test_span_id_generation PASSED                    [ 11%]
tests/test_context.py::test_request_id_generation PASSED                 [ 13%]
tests/test_context.py::test_trace_context_propagation PASSED             [ 16%]
tests/test_context.py::test_w3c_traceparent_parse_and_format PASSED      [ 18%]
tests/test_context.py::test_request_attributes PASSED                    [ 20%]
tests/test_context.py::test_trace_generation_extreme PASSED              [ 23%]
tests/test_context.py::test_trace_context_get_set_reset_tokens PASSED    [ 25%]
tests/test_context.py::test_w3c_traceparent_parse_and_format_edge_cases PASSED [ 27%]
tests/test_context.py::test_request_attributes_edge_cases PASSED         [ 30%]
tests/test_exporters.py::test_file_exporter_writes_jsonl PASSED          [ 32%]
tests/test_exporters.py::test_stdout_exporter_json PASSED                [ 34%]
tests/test_exporters.py::test_stdout_exporter_pretty PASSED              [ 37%]
tests/test_exporters.py::test_composite_exporter_factory PASSED          [ 39%]
tests/test_exporters.py::test_stdout_exporter_json_and_pretty_edge_cases PASSED [ 41%]
tests/test_exporters.py::test_file_exporter_error_handling PASSED        [ 44%]
tests/test_exporters.py::test_http_exporter_failures PASSED              [ 46%]
tests/test_exporters.py::test_fluentbit_exporter_mocked PASSED           [ 48%]
tests/test_exporters.py::test_composite_exporter_and_factory_edge_cases PASSED [ 51%]
tests/test_fastapi_instrumentation.py::test_fastapi_auto_instrumentation_success PASSED [ 53%]
tests/test_fastapi_instrumentation.py::test_fastapi_traceparent_header_propagation PASSED [ 55%]
tests/test_fastapi_instrumentation.py::test_fastapi_exception_capture PASSED [ 58%]
tests/test_fastapi_instrumentation.py::test_fastapi_client_error_warning PASSED [ 60%]
tests/test_fastapi_instrumentation.py::test_fastapi_middleware_non_http_scope PASSED [ 62%]
tests/test_fastapi_instrumentation.py::test_fastapi_middleware_client_ip_edge_cases PASSED [ 65%]
tests/test_fastapi_instrumentation.py::test_fastapi_middleware_header_decoding_resilience PASSED [ 67%]
tests/test_fastapi_instrumentation.py::test_fastapi_middleware_exception_and_error_handling PASSED [ 69%]
tests/test_fastapi_instrumentation.py::test_fastapi_middleware_send_wrapper_missing_headers PASSED [ 72%]
tests/test_logger.py::test_structured_logger_info PASSED                 [ 74%]
tests/test_logger.py::test_structured_logger_with_context PASSED         [ 76%]
tests/test_logger.py::test_structured_logger_exception PASSED            [ 79%]
tests/test_logger.py::test_pytrace_handler_for_stdlib_logging PASSED     [ 81%]
tests/test_logger.py::test_structured_logger_levels_and_thresholds PASSED [ 83%]
tests/test_logger.py::test_structured_logger_exception_capture_edge_cases PASSED [ 86%]
tests/test_logger.py::test_pytrace_handler_stdlib_logging_failures PASSED [ 88%]
tests/test_models.py::test_utc_now_iso PASSED                            [ 90%]
tests/test_models.py::test_pytrace_event_defaults PASSED                 [ 93%]
tests/test_models.py::test_pytrace_event_serialization PASSED            [ 95%]
tests/test_models.py::test_pytrace_error_details PASSED                  [ 97%]
tests/test_models.py::test_pytrace_event_validation_boundaries_and_types PASSED [100%]

======================== 43 passed, 1 warning in 0.58s ========================
```

---

## 2. Configuration Tests (`tests/test_config.py`)

| Test Case Name | Description | Status |
| :--- | :--- | :--- |
| `test_config_empty_values` | Verifies that `PyTraceConfig` accepts and handles empty string parameters for service name, environment, log directory, and log files. | **PASSED** |
| `test_config_invalid_types` | Asserts that inputting invalid data types for configuration properties (e.g., passing a string to port or sample rate) raises Pydantic `ValidationError`. | **PASSED** |
| `test_global_config_lifecycle` | Validates getting, setting, and resetting the global singleton config object (including fallback recovery when setting configuration to `None`). | **PASSED** |

---

## 3. Context Propagation Tests (`tests/test_context.py`)

| Test Case Name | Description | Status |
| :--- | :--- | :--- |
| `test_trace_id_generation` | Verifies generation of a valid 32-character hexadecimal trace ID (128-bit). | **PASSED** |
| `test_span_id_generation` | Verifies generation of a valid 16-character hexadecimal span ID (64-bit). | **PASSED** |
| `test_request_id_generation` | Validates request ID prefixing and standard generation lengths. | **PASSED** |
| `test_trace_context_propagation` | Verifies that setting and retrieving trace IDs from context variables functions correctly across calls. | **PASSED** |
| `test_w3c_traceparent_parse_and_format` | Validates W3C traceparent formatting and parsing logic under standard inputs. | **PASSED** |
| `test_request_attributes` | Tests basic setting, updating, and retrieval of request-scoped attribute dictionaries. | **PASSED** |
| `test_trace_generation_extreme` | Tests generating request IDs under boundary values: empty prefix string and 10,000-character prefix string. | **PASSED** |
| `test_trace_context_get_set_reset_tokens` | Checks setting context values to `None` and verifies that resetting a context variable using an invalid or foreign token raises a `ValueError`. | **PASSED** |
| `test_w3c_traceparent_parse_and_format_edge_cases` | Verifies parser robustness under empty, `None`, invalid types (e.g. integers), and malformed (too short, too long) traceparent headers. | **PASSED** |
| `test_request_attributes_edge_cases` | Validates duplicate attribute updates, invalid data types (e.g. string or `None`) raising `AttributeError`, and clean resets using tokens. | **PASSED** |

---

## 4. Data Model Tests (`tests/test_models.py`)

| Test Case Name | Description | Status |
| :--- | :--- | :--- |
| `test_utc_now_iso` | Confirms current timestamp generation returns a correctly formatted ISO-8601 UTC string. | **PASSED** |
| `test_pytrace_event_defaults` | Validates standard default fallback fields when instantiating a blank `PyTraceEvent`. | **PASSED** |
| `test_pytrace_event_serialization` | Verifies that a full `PyTraceEvent` with request, trace, and HTTP attributes serializes to JSON correctly. | **PASSED** |
| `test_pytrace_error_details` | Validates that Python exception objects and stack traces serialize to `ErrorDetails` structures accurately. | **PASSED** |
| `test_pytrace_event_validation_boundaries_and_types` | Tests float duration boundary constraints (minimum `0.0`, negative values, maximum values), invalid duration data types, missing required error fields, and non-serializable property conversions. | **PASSED** |

---

## 5. Exporter Tests (`tests/test_exporters.py`)

| Test Case Name | Description | Status |
| :--- | :--- | :--- |
| `test_file_exporter_writes_jsonl` | Verifies that the file exporter correctly formats telemetry records as JSONL lines on disk. | **PASSED** |
| `test_stdout_exporter_json` | Validates standard console exporting in pure JSON format. | **PASSED** |
| `test_stdout_exporter_pretty` | Validates pretty-printed console log output structure. | **PASSED** |
| `test_composite_exporter_factory` | Validates composite exporter factory parses comma-separated lists of exporter targets. | **PASSED** |
| `test_stdout_exporter_json_and_pretty_edge_cases` | Asserts that pretty-printing handles missing HTTP/duration metadata without crashing, and logs to `sys.stderr` if stream writing fails. | **PASSED** |
| `test_file_exporter_error_handling` | Confirms that file exporter handles unwritable files or directory write attempts gracefully without throwing runtime exceptions. | **PASSED** |
| `test_http_exporter_failures` | Verifies that network/HTTP failures and `None` endpoint configurations are handled silently by the HTTP exporter. | **PASSED** |
| `test_fluentbit_exporter_mocked` | Tests TCP socket exporting to Fluent Bit: mocks connection failures, data-send drops, and verifies auto-reconnection logic. | **PASSED** |
| `test_composite_exporter_and_factory_edge_cases` | Verifies composite exporter factory trims spaces, ignores unknown types, and executes close/flush callbacks on all nested exporters even if some fail. | **PASSED** |

---

## 6. Logger Tests (`tests/test_logger.py`)

| Test Case Name | Description | Status |
| :--- | :--- | :--- |
| `test_structured_logger_info` | Validates structured event logging with extra key-value attributes. | **PASSED** |
| `test_structured_logger_with_context` | Confirms structured logs correctly inherit parent trace, request, and active session variables. | **PASSED** |
| `test_structured_logger_exception` | Validates logging runtime exceptions along with automatic stacktrace captures. | **PASSED** |
| `test_pytrace_handler_for_stdlib_logging` | Verifies that standard library logger records are intercepted and converted to structured events by `PyTraceHandler`. | **PASSED** |
| `test_structured_logger_levels_and_thresholds` | Tests logger severity filtering (e.g. configured to WARNING, ignoring INFO) and unexpected severity defaults. | **PASSED** |
| `test_structured_logger_exception_capture_edge_cases` | Validates logging exception tracebacks under irregular formats (exception instances, 3-tuples, `None`-tuples, invalid integer types, or no active traceback). | **PASSED** |
| `test_pytrace_handler_stdlib_logging_failures` | Asserts stdlib logger record conversion filters private variables and intercepts inner logging write failures gracefully. | **PASSED** |

---

## 7. FastAPI Middleware Tests (`tests/test_fastapi_instrumentation.py`)

| Test Case Name | Description | Status |
| :--- | :--- | :--- |
| `test_fastapi_auto_instrumentation_success` | Verifies successful automatic HTTP telemetry capture and context propagation on healthy FastAPI HTTP requests. | **PASSED** |
| `test_fastapi_traceparent_header_propagation` | Validates distributed tracing: traceparent header in HTTP request is propagated to downstream contexts and response headers. | **PASSED** |
| `test_fastapi_exception_capture` | Checks that unhandled route exceptions are captured as `ERROR` events and response status is set to `500`. | **PASSED** |
| `test_fastapi_client_error_warning` | Asserts that standard client route warnings (like HTTP 404) are registered at `WARNING` severity. | **PASSED** |
| `test_fastapi_middleware_non_http_scope` | Verifies that non-HTTP scopes (such as `websocket` protocol connections) bypass the middleware immediately. | **PASSED** |
| `test_fastapi_middleware_client_ip_edge_cases` | Validates client IP extraction logic when ASGI client metadata is missing (`None`) or empty (`()`). | **PASSED** |
| `test_fastapi_middleware_header_decoding_resilience` | Confirms that headers containing invalid byte characters are bypassed and do not crash the middleware thread. | **PASSED** |
| `test_fastapi_middleware_exception_and_error_handling` | Verifies that route exceptions are caught, logged, and re-raised to keep original user routing logic intact. | **PASSED** |
| `test_fastapi_middleware_send_wrapper_missing_headers` | Asserts that correlation headers are successfully injected into the response even if the application response starts without any header collection. | **PASSED** |
