# Universal Log Pre-processing Framework (ULPF)

## Project Overview

The Universal Log Pre-processing Framework (ULPF) is a vendor-agnostic, extensible framework designed to ingest, parse, normalize, and standardize logs and events from any hardware or software source. ULPF converts heterogeneous log formats into a unified, lossless, analytics-ready representation suitable for SIEMs, data lakes, and AI/ML platforms while preserving original raw events for forensic and compliance purposes.

## Objectives

- Provide a universal event schema and processing pipeline that supports diverse log formats (Syslog, JSON, XML, CSV, CEF, LEEF, proprietary, and application-specific schemas).
- Preserve complete raw event data without information loss.
- Extract source-specific attributes and normalize fields into a common taxonomy.
- Maintain traceability between normalized and original events.
- Enable plug-and-play onboarding for new log sources.
- Support scalable deployments suitable for Big Data environments (billions of events per day).
- Be deployable in air-gapped environments and packaged as containers for platform independence.

## Key Features

- Source-agnostic ingestion layer with adapters for common formats and protocols.
- Pluggable parsing and enrichment components to extract and standardize attributes.
- Common event schema and taxonomy for downstream analytics and correlation.
- Raw event retention with pointers to normalized records for full traceability.
- Extensible rules and configuration to accelerate onboarding of new sources.
- Integration hooks for SIEMs, data lakes, and ML pipelines.

## Deliverables

- Source code repository (this project)
- README with setup and usage instructions
- Architecture document (maximum 2 pages)
- Demo video (maximum 2 minutes)
- Technical presentation (maximum 5 slides)

## Current Scope for Evaluation

Build a framework that converts perimeter network device logs and events—regardless of source, format, vendor, or technology—into a standardized, lossless, analytics-ready representation intended for next-generation SIEM and cybersecurity workflows.

## Quick Start (Development)

Prerequisites:
- Docker (for containerized components)
- Java 11+ / Python 3.8+ (depending on implementation choices)
- Node.js 14+ (optional for tooling)

Basic steps:
1. Clone the repository.
2. Review architecture and configuration files under the `docs/` and `config/` directories.
3. Start the ingestion and processing services using the provided docker-compose or container runtime scripts.
4. Use the sample adapters in `adapters/` to ingest sample logs and verify normalized output in `output/` or the configured sink.

Refer to the project-specific setup guide in docs/README-SETUP.md for precise commands and environment variables.

## Architecture Notes

- The framework separates ingestion, parsing, normalization, enrichment, and output stages to allow independent scaling.
- Parsers are pluggable modules that emit both raw and normalized records and attach metadata for traceability.
- Storage and forwarding are abstracted via sinks (e.g., object storage, message queues, SIEM connectors) to support different deployment models.

(See the Architecture Document for a concise diagram and deployment patterns.)

## Integration and Extensibility

- Onboarding new sources is supported via adapter templates and configuration-driven parsing rules.
- Enrichment pipelines (e.g., geo-IP, threat intel lookup, identity mapping) are implemented as optional stages.
- Output adapters support SIEM, data lake ingestion, and message bus publishing.

## Testing and Validation

- Unit tests cover parsing and normalization logic.
- End-to-end tests validate traceability between raw and normalized events.
- Performance tests should be run against representative datasets to validate throughput and resource usage.

## Security and Compliance

- Raw events are preserved for forensic requirements and access-controlled according to deployment policies.
- Support for air-gapped deployment ensures sensitive environments are accommodated.

## Contribution

Contributions are welcome. Please follow the contribution guidelines in CONTRIBUTING.md. Create feature branches, add tests for new functionality, and open pull requests with a clear description of changes.

## Contact

Organization: National Technical Research Organisation (NTRO)

For project coordination and submission details, refer to the SIH 2026 project page: https://sih.gov.in/sih2026PS

## License

Specify the project license in LICENSE.md.

--

This README was prepared from the project problem statement and is intended to serve as the canonical project overview and developer getting-started guide.
