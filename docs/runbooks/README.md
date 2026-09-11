# Operational Runbooks

**Owner**: SRE-Capsule
**Contract**: [ADR-0009](../adr/0009-observability-and-reliability-signals.md)
**Dashboards**: `o11y/*.json` (Grafana folder `Capsule`)

These runbooks are the operational response for Capsule lifecycle and
infrastructure failures. Dashboards and alerts are not enough; each failure
mode has a linked runbook with severity, first checks, mitigation,
escalation, and rollback.

## Coverage

| Failure mode | Runbook | Alert category |
|---|---|---|
| Create or schedule issues | [control-plane](control-plane.md), [scheduling-capacity](scheduling-capacity.md), [lifecycle-operations](lifecycle-operations.md) | `regional_lifecycle_failure`, `capacity_exhaustion` |
| Host-agent unavailable or stale capacity | [host-health](host-health.md), [scheduling-capacity](scheduling-capacity.md) | `host_degradation`, `telemetry_delivery_failure` |
| Boot non-ready (image, network, runtime, guest-agent) | [lifecycle-operations](lifecycle-operations.md), [image-cache](image-cache.md), [networking](networking.md), [runtime-backend](runtime-backend.md) | `regional_lifecycle_failure` |
| Exec timeout or stuck command | [lifecycle-operations](lifecycle-operations.md) | `regional_lifecycle_failure` |
| Snapshot restore or fork | [snapshot-fork](snapshot-fork.md) | `regional_lifecycle_failure`, `capacity_exhaustion` |
| Network policy and DNS | [networking](networking.md), [dns](dns.md) | `security_event`, `regional_lifecycle_failure` |
| Cleanup/reconciliation and host quarantine | [cleanup-reconciliation](cleanup-reconciliation.md), [host-quarantine](host-quarantine.md) | `cleanup_drift`, `host_quarantine`, `resource_pressure` |
| Audit or telemetry pipeline | [audit-telemetry](audit-telemetry.md) | `audit_delivery_failure`, `audit_integrity_gap`, `telemetry_delivery_failure`, `cardinality_overflow` |
| SLO burn | [slo-error-budget](slo-error-budget.md) | `slo_burn` |

Numeric SLO targets, freeze rules, and burn alerts are
[slo-error-budget-policy](../observability/slo-error-budget-policy.md)
.
Use the SLO runbook only for first response, then jump to the owning failure mode.

## Required sections

Every runbook defines:

1. **Severity** - page, quarantine, drain, or ticket
2. **First checks** - dashboards and aggregate metrics before any host access
3. **Mitigation** - stop the blast radius without guessing
4. **Escalation** - when to page the next owner
5. **Rollback** - how to undo the mitigation

## Host mutation policy

Runbooks do **not** require direct host mutation. Diagnose from dashboards,
platform logs, traces, and audit events first.

| Class | Allowed without extra approval | Requires on-call SRE approval |
|---|---|---|
| Read telemetry | Grafana, Loki, Tempo, audit query | Protected tenant/sandbox pivot |
| Placement | Wait for scheduler exclusion (`Healthy`/`Degraded` only admit) | `POST /rpc/v1/drain` on a host-agent |
| Quarantine | Let `AlertStateManager` auto-resolve after 120s of a cleared condition | Manual `acknowledge`/`resolve` (in-process API; no CLI shipped) |
| Process | None | Restart `capsule-host-agent`, `sandboxd`, or `capsule-metrics-agent` |
| Cleanup | None | Fenced GC, ledger inspect, netns/cgroup removal |
| Rebuild | None | Cordon, drain remaining sandboxes, rebuild host |

**Prohibited without a reviewed incident ticket:**

- editing the sandboxd ledger by hand
- killing guest processes or VMMs outside drain/destroy
- deleting cgroups, netns, taps, or workspaces without fencing tokens
- replaying audit dead-letters without Security review
- attaching high-cardinality tenant or sandbox labels to metrics

SSH/`dmesg`/`journalctl` are read-only diagnostics. They are not first checks
and they are not a substitute for drain, quarantine, or fenced cleanup.

## Signal lookup

### Dashboards

Grafana folder `Capsule`. Filter every panel by `region` and `cell` before
acting. Dashboards do not expose tenant or sandbox dimensions.

| UID | File |
|---|---|
| `capsule-control-plane` | `o11y/control-plane.json` |
| `capsule-lifecycle-operations` | `o11y/lifecycle-operations.json` |
| `capsule-scheduling-capacity` | `o11y/scheduling-capacity.json` |
| `capsule-host-health` | `o11y/host-health.json` |
| `capsule-runtime-backend` | `o11y/runtime-backend.json` |
| `capsule-image-cache` | `o11y/image-cache.json` |
| `capsule-networking` | `o11y/networking.json` |
| `capsule-dns` | `o11y/dns.json` |
| `capsule-snapshot-fork` | `o11y/snapshot-fork.json` |
| `capsule-cleanup-reconciliation` | `o11y/cleanup-reconciliation.json` |
| `capsule-audit-telemetry` | `o11y/audit-telemetry.json` |
| `capsule-slo-error-budget` | `o11y/slo-error-budget.json` |

### Metrics vs ADR taxonomy

Dashboards and recording rules use Prometheus names. Boot and exec labels are
the **implemented** `event`/`reason` values, not ADR-0009 `outcome` strings.

| Signal | Implemented labels |
|---|---|
| Create | `capsule_create_events_total{event="create_started\|create_completed\|create_failed"}` |
| Boot | `capsule_boot_events_total{event="boot_start\|boot_ready\|boot_not_ready\|boot_cleanup", reason="image\|network\|resource\|backend\|protocol\|timeout\|cleanup"}` |
| Exec | `capsule_exec_events_total{event="exec_started\|succeeded\|failed\|canceled\|timed_out\|not_completed"}` |
| Placement | `capsule_placement_latency_seconds`, `capsule_placement_hosts_evaluated`, `capsule_placement_hosts_passed_constraints` |
| Quarantine | `capsule_quarantine_hosts_quarantined`, `capsule_quarantine_alerts_active`, `capsule_quarantine_alerts_fired_total` |
| Image cache | `capsule_image_cache_hits`/`misses`/`evictions` (`tier`), `capsule_image_prepare_latency_seconds` (`cache_result`, `image_profile`). Not emitted until host image cache (BSD-184). |

Scheduler inventory drops a host after **60s** without a capacity report.
Quarantine `capacity_reporting_staleness` fires after **120s**.

### Logs

Platform logs use `target = "capsule_platform_log"` and the `LogRecord` fields
in `capsule-telemetry`. Query by `event`, then pivot on `operation_id`,
`trace_id`, `host_id`, `cell_id`, and `region`.

```
{service_name="capsule-host-agent"} | json | event="boot_not_ready"
```

Diagnostic `tracing` events may include a `diagnostics` field. They are not
the terminal record. Terminal non-success operations emit ERROR platform logs.

Never search logs for commands, credentials, paths, or workload output. Those
fields are redacted at source.

### Traces

1. Copy `trace_id` from the platform log or audit event.
2. Open Tempo/Jaeger and search that W3C trace ID.
3. Implemented span names: `request`, `create`, `host_agent_rpc`,
   `create_sandbox`, `prepare_sandbox`, `boot_sandbox`, `exec`, `suspend`,
   `resume`, `restore_from_snapshot`, `destroy`, `prepare`, `boot`,
   `provision`, `build`.

Failed, timed-out, and rejected traces are the diagnostic path. Successful
traces may be sampled.

See [distributed tracing](../observability/distributed-tracing.md).

### Audit

Query the durable audit store (not logs) with `event_kind`, `operation_id`,
`trace_id`, `sandbox_id`, or `lease_id`. Relevant kinds:

| Kind | Use |
|---|---|
| `lifecycle_transition` | state changes |
| `placement_outcome` | schedule/create |
| `quota_rejection`/`policy_decision` | admission |
| `runtime_outcome` | prepare/start/stop |
| `network_enforcement` | DNS/egress/port-forward |
| `snapshot_operation` | restore/fork/integrity |
| `cleanup_disposition` | GC/quarantine/reconcile |
| `host_disabled` | placement disable |
| `audit_delivery` | pipeline health |

Audit events are unsampled. A gap, dead-letter, or sequence hole is itself an
incident ([audit-telemetry](audit-telemetry.md)).

## Severity

| Level | Meaning | Typical action |
|---|---|---|
| Page | User-visible or safety-critical now | Page SRE-Capsule; stop placement if a host or cell is unsafe |
| Quarantine | Host must not receive new work | Confirm scheduler exclusion; do not mutate the host |
| Drain | Host is over pressure or being emptied | Prefer natural drain; `POST /rpc/v1/drain` only with approval |
| Ticket | Elevated error rate, budget burn, or single-tenant impact | File to the owning team; watch SLO burn |

## Incident drills

The boot non-ready and host-quarantine drill is
[drills/boot-non-ready-and-quarantine.md](drills/boot-non-ready-and-quarantine.md).
Update the owning runbook when a drill finding changes a check or mitigation.

## Related

- [ADR-0009](../adr/0009-observability-and-reliability-signals.md)
- [ARCHITECTURE.md](..../ARCHITECTURE.md) section 13
- Alert rules: `o11y/rules/capsule-recording-rules.yaml`
-: operational runbooks
-: dashboards
-: host quarantine alerts
- [SLO and error-budget policy](../observability/slo-error-budget-policy.md)
