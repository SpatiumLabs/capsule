# Drill: Boot Non-Ready and Host Quarantine

**Owner**: SRE-Capsule
**Runbooks**: [lifecycle-operations](../lifecycle-operations.md),
[runtime-backend](../runtime-backend.md),
[image-cache](../image-cache.md),
[networking](../networking.md),
[host-quarantine](../host-quarantine.md),
[cleanup-reconciliation](../cleanup-reconciliation.md)
**Alert category**: `regional_lifecycle_failure`, `host_quarantine`, `cleanup_drift`

Tabletop by default. A live drill that drains or restarts a host needs SRE
lead approval and is out of scope for the first pass.

## Objectives

1. Split `boot_not_ready` by `reason` (`image`, `network`, `backend`,
   `protocol`) without SSHing.
2. Follow quarantine first checks for a single bad host, then for cell-wide
   fire.
3. Refuse unapproved host mutation (no un-fenced cleanup, no ledger edits).
4. Record findings back into the owning runbook.

## Participants

SRE (facilitator), Runtime, Networking, Image Pipeline, Observability,
Control Plane. Security joins if inject 4 is used.

## Preconditions

- Grafana folder `Capsule` loads all dashboards.
- Loki/Tempo (or equivalent) can filter `event="boot_not_ready"`.
- Alert rules in `o11y/rules/capsule-recording-rules.yaml` are provisioned
  in the drill environment, or the facilitator injects the alert payload.
- No production host mutation.

## Inject 1: Image non-ready (15m)

Facilitator states: after digest promotion `sha256:dead...`, cell `cel_east`
shows `capsule_boot_events_total{event="boot_not_ready",reason="image"}`
rising. Other reasons are flat. Placement efficiency is normal.

**Expect**

- First checks on `capsule-lifecycle-operations`, then
  [image-cache](../image-cache.md).
- Mitigation: stop promotion, pin last known-good digest from control
  plane. No host pull, no signature bypass.
- Escalation: Image Pipeline. Security only if verification failed.

## Inject 2: Protocol non-ready on one host (15m)

Facilitator states: host `hst_01` has consecutive `reason=protocol` boots.
`capsule_quarantine_hosts_quarantined=1`. Other hosts `boot_ready`.
`CapsuleHostQuarantined` is firing.

**Expect**

- [lifecycle-operations](../lifecycle-operations.md) reason table ->
  [runtime-backend](../runtime-backend.md) ->
  [host-quarantine](../host-quarantine.md) `repeated_runtime_outcomes`.
- First checks use `event`/`reason`, not `outcome="runtime_failed"`.
- Mitigation: leave quarantined. No `POST /rpc/v1/drain` without approval.
- No `capsule-cli quarantine resolve` (not shipped). Auto-resolve is 120s
  after the condition clears.

## Inject 3: Cleanup review-required (15m)

Facilitator states: same host now has `capsule_gc_review_required` and
`network_reconciliation_review_required`. Orphans detected, none removed.

**Expect**

- [cleanup-reconciliation](../cleanup-reconciliation.md): stop deleting.
- `requires_review` is not "retry rm".
- Fenced cleanup only with a ticket and fencing tokens.
- Rollback: host stays quarantined until a later reconciliation pass is
  clean.

## Inject 4 (optional): Cell-wide fire (10m)

Facilitator states: `CapsuleHostAlertFiringRateHigh` and three hosts in
`cel_east` quarantined. Audit outbox pending is also climbing.

**Expect**

- Do not restart every host-agent.
- Split [audit-telemetry](../audit-telemetry.md) vs runtime.
- Page SRE lead; shed admission rather than mutate hosts.

## Pass criteria

- Reason split for image vs protocol vs network vs backend
- Telemetry before SSH
- No unapproved drain, restart, GC, or ledger edit
- Quarantine rollback does not use a fake CLI
- At least one runbook patch filed from a finding (or an explicit
      "no change" note)

## Findings log

| Inject | What broke in the runbook | Follow-up |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |

Facilitator files findings as comments on or a follow-up issue and
patches the runbook in the same change when the check is wrong.

## Related

- [README](../README.md) host mutation policy
- test plan: tabletop + this drill
- G-13 in [production-readiness](..../security/production-readiness.md)
