# Security policy

## Reporting a vulnerability in GHA-ThreatLens

Use GitHub private vulnerability reporting or GitHub Security Advisories on this repository if that feature is enabled for the project.

Do not open a public issue for a vulnerability in the scanner itself.

## Supported versions

| Version | Support |
| --- | --- |
| 0.1.x | Current development line |

Older versions are not maintained until a later stable series exists.

## What is in scope

- Defects in GHA-ThreatLens that allow unexpected code execution in the scanner process.
- Path escape during discovery (symlinks or scan-root confinement).
- Unsafe YAML object construction.
- Leakage of scan evidence to the network.
- Uncontrolled consumption of GitHub tokens by the tool.

## What is not a scanner vulnerability

Findings that GHA-ThreatLens reports in *other* repositories’ workflows are detections, not defects in this tool. A missed detection or a noisy finding should be filed as a bug or rule request, not as a security advisory, unless it causes harm in the scanner process.

Workflow files under `examples/vulnerable/` and `tests/fixtures/vulnerable/` are intentional.

## Local scan guarantees

Local scans do not require a token, do not make network requests, and do not collect telemetry.
