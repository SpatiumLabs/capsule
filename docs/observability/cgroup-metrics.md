# Cgroup v2 Memory Pressure Metrics

**Status**: Implemented
**Related**: [SC-02 side-channel assessment](../security/side-channel-assessment.md#sc-02-memory-pressure-and-page-cache-contention)

## Overview

The host-agent polls the cgroup v2 `memory.pressure` interface for each
active sandbox and exposes a host-level aggregate gauge. This provides
operators with visibility into memory contention without exposing
per-sandbox pressure to tenants.

## Metric

| Instrument | Type | Description |
|---|---|---|
| `capsule_cgroup_memory_pressure` | Gauge | Maximum `memory.pressure` `some avg10` value across all active sandbox cgroups. Range 0.0 (no pressure) to 100.0 (full stall). |

The gauge is always host-level aggregate -- it never exposes per-sandbox
values. This avoids the cross-tenant inference concern documented in SC-02.

## Polling

The host-agent reads `memory.pressure` for every active sandbox every 30
seconds. The gauge is set to the maximum `some avg10` value observed. If
no sandboxes are present or the cgroup v2 filesystem is not mounted, the
gauge reads 0.0.

## Interpreting the value

| Range | Meaning | Suggested action |
|---|---|---|
| **0--5** | Normal light contention | Healthy |
| **5--15** | Noticeable pressure | Investigate workload or limits |
| **15--30** | Elevated | Consider scaling or rebalancing |
| **30--50** | High pressure | Strong signal to act (drain, shed) |
| **>50** | Severe thrashing | Critical - risk of OOM or stalls |

 maps these onto density zones: <15 safe, 15-30 warning (LPOP cap),
>=30 saturation. See
[active-sandbox-defaults](../capacity/active-sandbox-defaults.md).

## Alerting guidance

| Alert | Condition | Severity | Action |
|---|---|---|---|
| `resource_pressure` | `capsule_cgroup_memory_pressure > 30` for 5m | Warning | Consider scaling, rebalancing, or shedding load |
| `resource_pressure` | `capsule_cgroup_memory_pressure > 50` for 2m | Critical | Stop placement on host, drain existing sandboxes - risk of OOM |

See [ADR-0009 alert categories](../adr/0009-observability-and-reliability-signals.md#alert-categories-and-operational-action)
for the `resource_pressure` alert classification.

## Implementation

- cgroup reading: `crates/capsule-host-agent/src/cgroups.rs`
- metric registration: `crates/capsule-host-agent/src/metrics.rs`
- polling loop: `HostAgent::spawn_memory_pressure_poller` in
  `crates/capsule-host-agent/src/lib.rs`
