# Control Plane Production Readiness Report

**Date**: 2026-09-10
**Status**: Draft (pending architecture and SRE owner review)

## Executive Summary

This report validates the Capsule Control Plane as an integrated subsystem
for production rollout. Validation composes the real lifecycle metadata
store, policy/quota admission, lease issuance/enforcement, regional/cell
schedulers, and audit pipeline through their public APIs in a single test
suite, instead of re-testing each component in isolation.

**Overall verdict**: The control plane meets the readiness criteria
with documented exceptions. All 36 integrated validation tests pass. Known
boundaries are pinned by tests and recorded below as open risks; none
blocks the validation itself, but the scheduler create-path gap
must close before placement evidence can be called production-complete.

## How to Run the Evidence

```bash
cargo nextest run -p capsule-core --test control_plane_readiness
cargo clippy -p capsule-core --test control_plane_readiness --locked -- -D warnings
```

Suite: `crates/capsule-core/tests/control_plane_readiness.rs` (36 tests,
sections A-H mapping to the validation areas).

Related prior evidence (not duplicated here): metadata unit coverage in
`crates/capsule-core/src/metadata.rs`, lease/policy/quota units in
`leases.rs`/`policy.rs`/`quota.rs`/`admission.rs`, scheduler units in
`scheduler.rs`/`cell_scheduler/tests.rs`, scheduler degradation drills in
`src/availability/tests.rs`, audit ordering/correlation/contract/pipeline
suites in `tests/audit_*.rs`, and the API admission wrapper tests in
`crates/capsule-api/src/policy_enforcer.rs`.

## 1. Lifecycle API Contract Compatibility

| Test | Proves |
|---|---|
| `lifecycle_contract_twelve_states_stable` | 12-state model, wire names, PascalCase serde round-trip, transitory/terminal classification |
| `lifecycle_commit_walk_create_to_destroy` | Full create/suspend/resume/destroy/status walk through `commit` (the sole desired-state mutation), with per-step version bump, `committed_at` evidence, and status-surface consistency |
| `lifecycle_commit_rejects_stale_and_terminal_writes` | Stale from-state fails with `UnexpectedState`; illegal jumps fail; `Destroyed` is terminal |
| `lifecycle_failure_and_reconcile_paths` | `Failed` escalation with structured `FailureInfo`, retryable vs unrecoverable classification, `EvaluateFailure` reconcile, teardown-only exit from `Failed` |

Contract pin: `Failed` is a sink for execution. A retryable failure
recovers by evaluate/destroy/re-prepare (new record), never by reviving the
failed record in place. `commit` clears the failure info on the teardown
commit out of `Failed`.

## 2. Metadata Retry and Concurrency

| Test | Proves |
|---|---|
| `concurrent_transitions_single_winner` | 16 racing writers resolve to exactly 1 winner; 15 observe `VersionConflict` |
| `version_conflict_retry_converges_after_reread` | Conflict carries the actual version; re-read/retry converges |
| `completed_operation_retry_is_idempotent` | Replayed transition returns `AlreadyInState` with no version move |
| `stale_record_detection_guards_read_modify_write` | Racing `commit` calls resolve to 1 winner; losers get `UnexpectedState` |
| `stuck_transitory_state_escalates_to_failed` | `is_stuck` + `transitory_timeout` detect wedged boots; escalation to `Failed` is a legal commit |

Contract pin: `commit` performs no version comparison. Its only
concurrency guard is the expected-state precondition, so staleness
protection is exactly as strong as the caller's from-state. Detached copies
cannot be guarded; `is_stale` exists so version holders can check before
writing.

## 3. Secure Time and Identity Binding

| Test | Proves |
|---|---|
| `hlc_timestamps_are_monotonic_across_rapid_events` | 50 back-to-back HLC stamps strictly increase (ordering never depends on wall-clock granularity) |
| `fencing_epoch_bump_invalidates_stale_holders` | Newer fencing epoch takes over; prior holder fails closed with `StaleFencingToken`; equal tokens are not stale |
| `stale_policy_epoch_is_rejected_before_side_effects` | Request epoch behind current epoch fails via `validate_policy_epoch`/`check_policy_epoch` |
| `lease_expiry_on_enforcement_path_is_bare_iso_compare` | Production expiry is `expires_at <= now` with no skew; `is_lease_expired` is unused by `validate`/`enforce_blob` |
| `actor_identity_is_stored_but_not_copied_onto_lifecycle_audit` | Actor identity persists on the metadata record; lifecycle audit pins `principal=None` |

## 4. Policy and Quota Enforcement

| Test | Proves |
|---|---|
| `admission_permit_issues_enforceable_lease` | One `Admission` call evaluates policy and returns a signed blob the offline seam accepts at the same epoch |
| `policy_deny_blocks_admission_without_consuming_quota` | Deny precedence: no lease minted, quota counters untouched |
| `quota_exceeded_blocks_admission_without_minting_lease` | Exhaustion fails with `QuotaExceeded`; no artifact escapes |
| `concurrent_create_admission_respects_quota_limit` | 12-way create storm with `max_sandboxes=3` admits exactly 3; 9 get `QuotaExceeded` |
| `invalid_policy_push_preserves_last_good_epoch` | Malformed policy push is rejected; epoch and previous policy keep serving (degradation) |

## 5. Access Lease Lifecycle

| Test | Proves |
|---|---|
| `lease_issue_expiry_renew_revocation_lifecycle` | Issue/validate/renew/revoke/deny/expire/prune full cycle with ordered audit kinds (`LeaseIssued`, `LeaseEnforced`, `LeaseRevoked`, `LeaseDenied`, `LeaseExpired`) |
| `policy_update_invalidates_stale_leases` | Post-update enforcement rejects pre-update leases as `StalePolicyEpoch` on both manager and offline blob paths; new admissions are denied |
| `revocation_takes_precedence_over_staleness` | Revoked lease under a newer epoch reports `Revoked`, not `StalePolicyEpoch` |
| `offline_enforcement_requires_revocable_path_for_revocation` | Plain `enforce_blob` cannot see manager revocation; `enforce_blob_revocable` can |
| `lease_wrong_binding_is_rejected` | Wrong sandbox/tenant/action rejected with typed errors |
| `leases_require_explicit_revocation_on_destroy` | Destroy without explicit revoke leaves the lease valid; `ResourceRemoved` revoke closes it |

Contract pins: `renew` emits `LeaseRevoked` (predecessor) plus
`LeaseIssued` (successor); there is no separate renewal event, so
predecessor/successor linkage is by sandbox/action/scope. Signed blobs
carry no revocation state, so revocation-aware edge enforcement must use
`enforce_blob_revocable` or re-validate against the manager; short TTLs
bound the exposure otherwise.

## 6. Scheduler Placement

| Test | Proves |
|---|---|
| `regional_scheduler_places_on_healthy_cell_with_evidence` | Placement carries reason, per-candidate scores, placement identity, backpressure, and an audit outcome with score/candidate count |
| `regional_scheduler_degrades_and_recovers` | A region with only a degraded cell still places on it; unavailable never selected; total loss fails closed typed; every call emits an outcome; restore resumes |
| `regional_scheduler_rejection_taxonomy_is_typed` | Unsupported runtime, insufficient capacity, draining fleet, and empty region each surface as distinct typed errors |
| `cell_scheduler_places_on_healthy_host_with_rejections` | Host selection with per-candidate rejection causes; cell outcome records the host |
| `cell_scheduler_quarantine_and_recovery` | Quarantine overlay rejects without rewriting operator drains; drained cell fails closed; restore resumes |
| `two_stage_placement_regional_then_cell` | Regional selection feeds the cell stage; both outcomes land ordered in one stream joined by sandbox id; chain recorded on metadata placement |
| `scheduler_audit_sink_failure_does_not_fail_placement` | Saturated audit channel does not fail placement (best-effort emission contract) |

## 7. Audit Ordering and Correlation

| Test | Proves |
|---|---|
| `full_control_plane_chain_is_ordered_and_correlated` | Composed seam: injected `PolicyDecision` (Admission does not emit), real regional/cell placement, 10 lifecycle transitions, and lease issue/validate/revoke/deny through one HLC domain and one sink form a single HLC-ordered, sandbox-correlated trail; lifecycle subsequence passes `validate_causal_chain`; denial references the revoked lease id |
| `placement_and_lifecycle_share_sandbox_identity` | Join keys (sandbox/tenant/cell/host/from/to) are present on real component output; scheduler outcomes pin `trace_id=None` until |

## 8. Degradation and Recovery

Covered by `invalid_policy_push_preserves_last_good_epoch` (bad policy
push), `scheduler_audit_sink_failure_does_not_fail_placement` (audit
backpressure), `quota_reservations_release_on_destroy` (quota release and
no-negative double release), `operation_identity_rejects_replay` (replay
detection), and the scheduler degradation/recovery tests in section 6.
Host-inventory staleness, expiry, and quarantine-overlay recovery drills
remain covered by `src/availability/tests.rs` and are referenced, not
duplicated.

## Acceptance Criteria Mapping

- End-to-end create, exec, suspend, resume, fork, destroy, and status flows
  pass against the integrated control-plane path: covered at the metadata
  desired-state layer (`lifecycle_commit_walk_create_to_destroy`,
  `lifecycle_failure_and_reconcile_paths`) plus admission/lease enforcement
  for the exec/data-plane seam. Fork has no facade method and
  suspend/resume have no admission gate (open risk 2).
- Retry, idempotency, stale policy, stale lease, and stale operation
  scenarios are tested: sections 2 and 5. `TransitionError::StaleOperation`
  is dead code (open risk 5); idempotency keys have no dedup store, only
  pattern validation plus `AlreadyInState`/`is_replayed` helpers (open
  risk 5).
- Scheduler placement and rejection reasons are visible in traces and audit
  events: audit outcomes carry reason/score/candidate counts on admit and
  reject (section 6); typed errors reach callers for trace attachment.
  No trace context flows into placement events (open risk 1).
- Readiness report links to test runs, dashboards, open risks, and accepted
  limitations: this document; dashboards `capsule-scheduling-capacity`,
  `capsule-host-health`, `capsule-control-plane`,
  `capsule-cleanup-reconciliation`, `capsule-audit-telemetry` (per
  `docs/capacity/cell-unavailability.md`); risks below.
- Architecture and SRE owners approve the readiness report: pending (see
  Approval).

## Open Risks and Accepted Limitations

1. **Schedulers are not on the API create admission path** (follow-up:
   ). Placement is
   validated scheduler-to-audit, not API-to-placement. Scheduler audit
   events carry `sandbox_id` but no `trace_id`/`operation_id`, so
   request-level trace correlation through placement is not yet possible.
   Pinned by `placement_and_lifecycle_share_sandbox_identity`.
2. **Suspend/resume/fork have no API admission gate.** `SandboxFacade`
   inherits existence-check defaults for suspend/resume and has no fork
   method; `PolicyAction` has no suspend/resume/fork variants. Lifecycle
   gating for these actions is validated at the metadata layer only.
3. **Destroy does not revoke outstanding leases.** A lease remains valid
   until expiry unless the destroy flow explicitly revokes it with
   `ResourceRemoved`. Pinned by `leases_require_explicit_revocation_on_destroy`.
4. **Offline enforcement is revocation-blind by default.** Plain
   `enforce_blob` accepts revoked-but-unexpired blobs; revocation-aware
   edges must use `enforce_blob_revocable` or re-validate. Short TTLs bound
   the window. Pinned by
   `offline_enforcement_requires_revocable_path_for_revocation`.
5. **Stale-operation and idempotency plumbing is partial.**
   `TransitionError::StaleOperation` is never constructed, and idempotency
   keys have no server-side dedup store; safe retry today rests on
   `AlreadyInState`, version/from-state preconditions, and
   `is_replayed_operation`. No test breakage, but no full exactly-once
   story either.
6. **Lifecycle audit does not copy actor identity.**
   `apply_transition_with_audit` emits `principal=None` even when
   `SandboxMetadata.actor_identity` is set. Pinned by
   `actor_identity_is_stored_but_not_copied_onto_lifecycle_audit`.
7. **Lease expiry has no skew window on the enforcement path.**
   `LeaseManager::validate` and `enforce_blob` use `has_lease_expired`
   (`expires_at <= now`). `is_lease_expired` is unused by those paths.
   Pinned by `lease_expiry_on_enforcement_path_is_bare_iso_compare`.
8. **Pre-existing CI gap (unrelated):** `cargo clippy -p capsule-core
   --all-targets` fails on `tests/secrets_broker.rs`, which needs the
   `secrets-http` feature. The new suite is clippy-clean under `-D
   warnings` on its own target.

## Approval

- Architecture owner review
- SRE owner review
