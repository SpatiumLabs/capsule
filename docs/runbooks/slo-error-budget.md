# SLO and Error Budget

**Owner**: SRE-Capsule
**Alert category**: `slo_burn`
**Severity**: Page on `CapsuleSloBurnFast` or `CapsuleSloBudgetExhausted`; ticket on `CapsuleSloBurnSlow`
**Policy**: [slo-error-budget-policy](../observability/slo-error-budget-policy.md)
**Dashboards**: `capsule-slo-error-budget`, `capsule-lifecycle-operations`, `capsule-host-health`, `capsule-snapshot-fork`, `capsule-audit-telemetry`

## When to use

Error-budget remaining is falling, a `slo_burn` alert fired, or a readiness
review (G-14) asks which lifecycle operation is consuming budget.

## Severity

| Condition | Level |
|---|---|
| `CapsuleSloBurnFast` (14.4x on 1h and 5m) | Page; freeze non-incident rollouts in the region |
| `CapsuleSloBudgetExhausted` (30d remaining = 0%) | Page; freeze all non-incident production changes |
| `CapsuleSloBurnSlow` (6x on 6h and 30m) | Ticket the owning team; no automatic freeze |
| Remaining < 25% without a page | Freeze feature rollouts; security and SLO-restoring fixes proceed |
| `CapsuleSloTelemetryStale` | Treat SLO status as unknown; use [audit-telemetry](audit-telemetry.md) |

Numeric targets, exclusions, and freeze rules are only in the policy.

## First checks

1. `capsule-slo-error-budget` -> **Error Budget Remaining** and the fast/slow
   burn bars. Note the `slo` label.
2. Confirm traffic: `capsule:slo:valid:rate5m` for that `slo` is above the
   alert floor. A quiet region can look like a huge ratio.
3. Jump:

   | `slo` | Runbook |
   |---|---|
   | create | [control-plane](control-plane.md), [scheduling-capacity](scheduling-capacity.md), [lifecycle-operations](lifecycle-operations.md) |
   | boot | [lifecycle-operations](lifecycle-operations.md), [image-cache](image-cache.md), [runtime-backend](runtime-backend.md) |
   | exec | [lifecycle-operations](lifecycle-operations.md) |
   | destroy | [lifecycle-operations](lifecycle-operations.md), [cleanup-reconciliation](cleanup-reconciliation.md) |
   | suspend resume | [runtime-backend](runtime-backend.md) |
   | restore fork | [snapshot-fork](snapshot-fork.md) |
   | audit | [audit-telemetry](audit-telemetry.md) |

4. Confirm the burn is real traffic, not a missing-data dip
   ([audit-telemetry](audit-telemetry.md)).

## Logs, traces, audit

Use the owning failure-mode runbook. SLO panels are aggregates; they have
no tenant pivot.

## Mitigation

1. Stop the rollout that started the burn.
2. Shed new creates if create/boot is the burner and a cell is unsafe.
3. Do not spend budget on an experiment during a page.
4. Apply the freeze table in the policy until remaining budget recovers or
   SRE records an exception.

## Escalation

SRE owns the page. The subsystem owner of the burning `slo` owns the fix.
Page Control Plane or Runtime after 15m on create, boot, exec, restore, or
audit. Security joins audit pages.

## Rollback

Revert the rollout. Budget remaining recovers only over the 30d window; do
not expect the 30d gauge to jump after a 15m fix. Use 5m and 1h burn to
confirm the incident is over.

## Related

- [slo-error-budget-policy](../observability/slo-error-budget-policy.md)
- [lifecycle-operations](lifecycle-operations.md)
- ADR-0009 dashboard and SLO categories
