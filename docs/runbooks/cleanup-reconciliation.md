# Cleanup and Reconciliation

**Owner**: SRE-Capsule/Runtime/Networking
**Alert category**: `cleanup_drift`, `host_quarantine`
**Severity**: Quarantine when review is required; page when drift is cell-wide or stale resources persist
**Dashboards**: `capsule-cleanup-reconciliation`, `capsule-host-health`, `capsule-networking`

## When to use

GC finds orphans, cleanup fails, reconciliation marks `requires_review`,
network rollback is incomplete, or quarantine condition
`cleanup_or_reconciliation_issue`/`stale_resources` is active.

## Severity

| Condition | Level |
|---|---|
| `capsule_gc_review_required` or `network_reconciliation_review_required` | Quarantine |
| `capsule_gc_orphans_detected` sustained >15m, or cleanup_failed rising | Page |
| Review required on >1 host in 30m | Page SRE lead |
| Single pass with orphans that are then removed | Ticket |

Destroy/GC already retries transient `EBUSY`/non-empty directories.
`requires_review` means a human decision is still required: fencing
conflict, unknown resource class, unparsable receipt, non-directory path,
or leftovers that survived the retry budget.

## First checks

1. `capsule-cleanup-reconciliation` -> **GC Pass Duration**, **Orphans
   Detected vs Removed**.
2. **GC Review Required** and **GC Cleanup Failed** stats.
3. **Network Reconciliation Passes**, **Stale Objects & Cleaned**,
   **Reconciliation Health State**, **Network Rollback Completions**,
   **Network Review Required**.
4. `capsule-host-health` draining and cgroup setup errors on the same host.
5. Quarantine gauges: `capsule_quarantine_hosts_quarantined` and alert
   condition `cleanup_or_reconciliation_issue` or `stale_resources`.

Do not delete cgroups, netns, or workspaces. Do not run un-fenced GC.

## Logs, traces, audit

**Logs**

```
{service_name=~"capsule-host-agent|capsule-network-agent|capsule-sandboxd"} | json | event=~"gc_.*|reconcil.*|cleanup.*"
```

**Traces**

Reconciliation and destroy spans. Ambiguous live resources should quarantine
rather than continue the delete.

**Audit**

`cleanup_disposition` is authoritative: cleanup, quarantine, or reviewed
disposition. `host_disabled` if the host was taken out of placement.
Preserve these records; do not replay them as deletes.

## Mitigation

1. Stop unsafe deletion. The correct default is quarantine, not cleanup.
2. Confirm the host cannot admit (`can_admit` is false). If it still admits,
   page SRE; do not fix fencing on the host.
3. Fenced cleanup, ledger inspect, and `gc --force-stale` are **not
   shipped** as `capsule-cli` commands. Any equivalent host RPC is mutation
   and needs an incident ticket plus fencing-token evidence.
4. If receipts belong to live sandboxes, leave them. Mismatched fencing
   tokens are a control-plane bug, not a local rm.
5. Network `requires-review`/`confirmed-owned`/`safe-to-remove` must
   stay in that classification. Do not reclassify from the host.

## Escalation

- Page SRE if review-required lasts >1h on one host.
- Page SRE lead if resources appear to span hosts or cells.
- Page Networking if only network reconciliation is unhealthy.
- Continue at [host-quarantine](host-quarantine.md).

## Rollback

1. After an **approved** fenced cleanup: another reconciliation pass must
   show zero orphans and zero review-required before anyone re-admits the
   host.
2. Do not resolve the quarantine alert to test cleanup.
3. If cleanup made things worse, stop. Leave the host quarantined and
   rebuild only with a reviewed ticket.

## Related

- [host-quarantine](host-quarantine.md)
- [networking](networking.md)
- [host-health](host-health.md)
- Drill: [boot-non-ready-and-quarantine](drills/boot-non-ready-and-quarantine.md)
