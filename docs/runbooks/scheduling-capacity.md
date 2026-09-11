# Scheduling and Capacity

**Owner**: SRE-Capsule
**Alert category**: `capacity_exhaustion`, `host_degradation`
**Severity**: Page when a cell cannot place; drain/quarantine for one host; ticket for efficiency drift
**Dashboards**: `capsule-scheduling-capacity`, `capsule-host-health`, `capsule-control-plane`, `capsule-cleanup-reconciliation`

## When to use

Creates fail with no host, insufficient capacity, all hosts draining, or
pressure saturation. Also use for stale capacity: hosts disappear from
placement before boot starts.

## Severity

| Condition | Level |
|---|---|
| Cell `NoHostsAvailable`/`InsufficientCapacity`/`AllHostsDraining`/`PressureSaturated` or `CapsuleCellCannotPlace` | Page |
| One host missing from inventory (60s TTL) | Quarantine after 120s ([host-health](host-health.md)) |
| Placement efficiency low but creates still succeed | Ticket |
| >20% of hosts in a cell missing capacity reports | Page |

## First checks

1. `capsule-scheduling-capacity` -> **Placement Latency**, **Active
   Sandbox Count per Host**, **Host Memory Pressure** (15 30 zone
   lines), **Hosts Quarantined**, and **Orphan Reconcile**.
2. **Placement Efficiency Ratio**:
   `passed_constraints/evaluated`. A collapse with high evaluated count is
   constraint/pressure. A collapse with low evaluated count is inventory
   loss (stale host-agent).
3. `capsule-control-plane` **Admission & Auth Rates**: `create_failed` plus
   audit `placement_outcome`.
4. `capsule-host-health` **Draining Hosts** (`capsule_host_draining > 0`) and
   **Active Sandbox Count per Host**.
5. Distinguish:

   | Evidence | Cause |
   |---|---|
   | Evaluated ~ 0 | Host-agent/inventory stale ([host-health](host-health.md)) |
   | Evaluated high, passed ~ 0, draining table full | Intentional drain |
   | Evaluated high, passed ~ 0, cgroup pressure up | [host-quarantine](host-quarantine.md) `resource_pressure` |
   | Passed > 0 but boot `reason=resource` | Host accepted then failed allocation |

Active density zones use the same pressure series:

| Zone | Memory pressure | Utilization | Operator action |
|---|---|---|---|
| Safe | < 15 | < 0.75 | Normal placement |
| Warning (LPOP cap) | 15-30 | 0.75-0.90 | Shed toward warning-max; do not raise overcommit |
| Saturation | >= 30 | >= 0.90 | Stop new placement. Isolation/cleanup breaks are class-A |

P0 packing on the lab 64-vCPU SKU advertises **32** default-shape sandboxes
(vCPU-bound). Process slots of 100 overstate that cap. Measured zones:
[active-sandbox-defaults](../capacity/active-sandbox-defaults.md).

Cell/host unavailability: unavailable cells never receive new
placements; running sandboxes stay until fence or approved drain. Treat
`schedule` `Err` as shed. Do not retry. See
[cell-unavailability](../capacity/cell-unavailability.md).

Scheduler inventory TTL is **60s**. Quarantine staleness is **120s**. A host
can fail placement for a minute without a quarantine alert.

Do not SSH. Do not add capacity by starting extra VMMs on a packed host.

## Logs, traces, audit

**Logs**

```
{service_name="capsule-api"} | json | reason=~"no_capacity|assignment_stale|host_degraded|host_draining|host_unsafe"
```

**Traces**

`create` span with `outcome=placement_failed`. No `host_agent_rpc` child
means the scheduler never assigned a host.

**Audit**

`placement_outcome` reasons include `best_score`, `only_candidate`,
`cache_hit`, `failure_domain_spread`, `no_cell_available`,
`no_host_available`. Rejection categories: `unavailable`, `draining`,
`disabled_for_placement`, `insufficient_capacity`, `unsupported_runtime`,
`pressure_saturated`.

## Mitigation

1. Cell full: stop new non-essential creates (admission shed, Control Plane
   approval). Do not pack draining hosts.
2. Stale inventory: follow [host-health](host-health.md). The host is already
   out of placement after 60s.
3. Pressure: allow natural drain. `POST /rpc/v1/drain` only with SRE
   approval, and only on the affected host.
4. Unsupported runtime: fail those creates; do not silently select a weaker
   backend.
5. Do not raise overcommit during an incident.

## Escalation

- Page SRE if a cell rejects creates for 10m.
- Page infra if the cell needs more hosts.
- Page Runtime if `unsupported_runtime` follows a backend rollout.
- Jump to [host-quarantine](host-quarantine.md) when quarantine gauges move.

## Rollback

1. Restore admission limits after passed-constraint count and create success
   recover for 15m.
2. Re-enable a drained host only when `capsule_host_draining` is 0, health is
   `Healthy` or `Degraded`, and capacity reports are fresh (<60s).
3. Never resolve quarantine to recover capacity.

## Related

- [host-health](host-health.md), [host-quarantine](host-quarantine.md),
  [control-plane](control-plane.md)
- [active sandbox defaults](../capacity/active-sandbox-defaults.md),
  [cell unavailability](../capacity/cell-unavailability.md)
