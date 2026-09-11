# Isolation Backend Production Readiness Report

**Date**: 2026-09-10
**Status**: Draft (pending architecture, runtime, security, and SRE owner review)
**Strategy**: [ADR-0004](../adr/0004-default-isolation-backend-strategy.md)
**Posture**: [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md)
**Readiness model**: [Production readiness](../security/production-readiness.md) gates `G-01` and `G-05`

## Executive Summary

This report validates the Capsule isolation backends as an integrated subsystem
for production rollout. Validation composes backend strategy, selection policy,
adapter behavior, compatibility boundaries, and conformance evidence through
public APIs and automated suites, instead of re-testing each adapter in
isolation.

**Overall verdict**: The backend subsystem does not yet meet production
readiness. Firecracker, QEMU, and gVisor have implemented adapters, explicit
capability declarations, and passing unit/conformance-on-mock evidence, but
the wired host path still uses TCP, several ADR-0004 gates fail open when
inputs are omitted, and live VMM boot is not in CI. Status is therefore
**preview** for Firecracker and QEMU, **preview with policy restriction** for
gVisor, **evaluation-only** for Cloud Hypervisor and Kata, and **rejected**
for RemoteFirecracker. All 207 integrated validation tests pass. Known
boundaries are pinned by tests and recorded below as open risks. Do not
approve a production launch stage until the blocking gaps in section 10
close.

## How to Run the Evidence

```bash
cargo nextest run -p capsule-runtime --test conformance
cargo nextest run -p capsule-runtime --test isolation
cargo nextest run -p capsule-runtime --lib
cargo nextest run -p capsule-core --lib backend_selection
cargo clippy -p capsule-runtime -p capsule-core --lib --locked -- -D warnings
```

Suite mapping to validation areas:

| Validation area | Suite | Location |
|---|---|---|
| Backend strategy and fallback matrix | ADR-0004 plus selection fixtures | `docs/adr/0004-default-isolation-backend-strategy.md`, `crates/capsule-core/src/backend_selection/` |
| Selection policy and reason codes | 21 selection tests | `crates/capsule-core/src/backend_selection/tests.rs` |
| Firecracker production path | Adapter units plus conformance contract | `crates/capsule-runtime/src/firecracker/` |
| gVisor fast path | Adapter units plus compatibility report | `crates/capsule-runtime/src/gvisor/` |
| QEMU/KVM compatibility fallback | Adapter units plus QMP suspend/resume | `crates/capsule-runtime/src/qemu/` |
| Cloud Hypervisor and Kata evaluation | ADR-0004 evaluation-only clause, state | This report section 6 |
| Conformance suite results | 15 conformance tests, 143 runtime lib tests | `crates/capsule-runtime/tests/conformance.rs`, `src/conformance/` |
| Isolation boundaries | 28 isolation tests | `crates/capsule-runtime/tests/isolation.rs`, `src/isolation/` |
| Metrics and diagnostics | Backend stats/health/diagnostics plus dashboards | `o11y/runtime-backend.json`, `docs/runbooks/runtime-backend.md` |

Related prior evidence (not duplicated here): host/guest protocol readiness in
`docs/robustness/guest-agent-proto-prod-readiness-report.md`, control
plane readiness in `docs/control-plane/prod-readiness-report.md`,
threat model in `docs/security/threat-model.md`, side-channel assessment in
`docs/security/side-channel-assessment.md`, lifecycle orchestration in
`docs/adr/0002-host-runtime-lifecycle-orchestration.md`.

## 1. Backend Strategy and Fallback Matrix

Strategy follows ADR-0004. Backend choice is a control-plane policy decision,
not an adapter preference, host-local retry, or tenant-controlled escape hatch.
Fallback is a new control-plane selection decision with persisted audit events.
Runtime adapters, `sandboxd`, host agents, and schedulers must not silently
start another backend when the selected backend fails.

| Workload class | Eligibility | Preferred backend | Permitted fallback order | Failure behavior |
|---|---|---|---|---|
| Public untrusted | Internet-facing or cross-tenant code, unknown provenance, or strong isolation required | Firecracker | QEMU | Reject placement when neither backend passes every gate. gVisor is never an automatic fallback. |
| Trusted fast path | Explicit tenant and platform policy approval for a lower isolation floor and gVisor compatibility | gVisor | Firecracker, then QEMU | Recompute and audit the selection. Never weaken below the approved isolation floor. |
| Compatibility VM | Workload requires a broader VM device model, guest kernel behavior, firmware path, or image format unavailable in Firecracker | QEMU | None automatically | Reject placement. A different backend requires a new request or policy decision proving compatibility. |
| Kubernetes-integrated | Deployment environment uses Kubernetes | Apply the underlying workload class | Apply the underlying workload class | Kubernetes integration does not change the isolation floor or make Kata production-eligible. |

ADR-0004 hard gates: tenant policy, isolation floor, capabilities, image
compatibility, snapshot compatibility, protocol compatibility, host support,
health and capacity, conformance status. The ADR says no gate is advisory.
The current policy implements a subset and several implemented gates skip
when their input maps are `None` (section 3.2 and section 10). Cross-backend
restore is prohibited. Cross-version restore is allowed only when the backend
compatibility policy and conformance evidence explicitly cover that version
pair.

## 2. Production Status Matrix

Explicit production status per acceptance criteria. Status is enforced
by a combination of `RuntimeType::is_production_eligible`,
`BackendSelectionPolicy::ordered_candidates`, tenant `allowed_runtimes`, and
the conformance gate.

| Backend | `RuntimeType` | Isolation boundary | Production status | Eligible workload classes | Selection order |
|---|---|---|---|---|---|
| Firecracker | `Firecracker` | KVM microVM, minimized device model | Preview | Intended public-untrusted preferred and trusted-fast-path fallback. Production blocked on vsock host transport, fail-closed selection gates, and live-boot evidence. | Rank 0 for public untrusted, rank 1 for trusted fast path |
| QEMU/KVM | `Qemu` | KVM VM, broad machine and device model | Preview | Intended public-untrusted fallback and compatibility VM. Production blocked on vsock host transport, fail-closed selection gates, and live-boot evidence. | Rank 1 for public untrusted, rank 0 for compatibility VM, rank 2 for trusted fast path |
| gVisor | `GVisor` | Userspace application kernel with syscall mediation | Preview with policy restriction | Trusted fast path only, with explicit tenant and platform grant. Never a public-untrusted candidate. Production blocked on Unix-transport host path (`sandboxd` accepts TCP only), conformance `GuestReadiness` required-set mismatch, and live-boot evidence. | Rank 0 for trusted fast path only |
| RemoteFirecracker | `RemoteFirecracker` | KVM microVM via externally managed guest | Rejected for production (development-only) | None in production policy | Not in any `ordered_candidates` list. `is_production_eligible` returns false. Cost model blocks rollout with `backend_not_production_eligible`. |
| Cloud Hypervisor | No `RuntimeType` variant | KVM microVM, modern virtio device model | Evaluation-only | None until evaluation is accepted plus adapter, capability metadata, ADR-0003 transport, image and snapshot policy, security and operational review, and passing conformance | Not selectable. No candidate path exists in code. |
| Kata Containers | No `RuntimeType` variant | VM-isolated container via CRI/containerd integration | Evaluation-only | None until evaluation is accepted plus adapter, capability metadata, ADR-0003 transport, image and snapshot policy, security and operational review, and passing conformance | Not selectable. No candidate path exists in code. |

Production eligibility pin:

```rust
// crates/capsule-core/src/runtime.rs
pub fn is_production_eligible(&self) -> bool {
    matches!(self, Self::Firecracker | Self::Qemu | Self::GVisor)
}
```

Boundary classification pin (`backend_selection::tests::vm_boundary_classification`,
`production_eligibility`, `runtime_isolation_floor_values`):

- `Firecracker.is_vm_boundary` is true, `is_microvm_boundary` is true
- `Qemu.is_vm_boundary` is true, `is_microvm_boundary` is false
- `GVisor.is_vm_boundary` is false, isolation floor is `Container`
- `RemoteFirecracker.is_production_eligible` is false

Isolation floor mapping pin (`IsolationFloor::from(WorkloadClass)` plus
`RuntimeType::isolation_floor`):

- `PublicUntrusted` requires at least `MicroVm`
- `TrustedFastPath` requires at least `Container`
- `CompatibilityVm` requires at least `MicroVm` (satisfied by QEMU `Vm`)
- `KubernetesIntegrated` requires at least `MicroVm`

## 3. Backend Selection Policy and Reason Codes

Implementation: `crates/capsule-core/src/backend_selection/mod.rs`
(`BackendSelectionPolicy::evaluate`). Tests:
`crates/capsule-core/src/backend_selection/tests.rs` (21 tests, all passing).

### 3.1 Ordered candidates

Pinned by `public_untrusted_prefers_firecracker_then_qemu`,
`trusted_fast_path_prefers_gvisor_then_firecracker_then_qemu`,
`compatibility_vm_selects_qemu_only`,
`public_untrusted_rejects_gvisor_output`:

- PublicUntrusted: `[Firecracker, Qemu]`, never gVisor
- TrustedFastPath: `[GVisor, Firecracker, Qemu]`
- CompatibilityVm: `[Qemu]` only
- KubernetesIntegrated: code in `ordered_candidates_for_kubernetes` prefers
  `[GVisor, Firecracker, Qemu]` when the tenant is authorized for
  `TrustedFastPath`, otherwise `[Firecracker, Qemu]`. Kubernetes never makes
  Kata eligible. This path is **not pinned by a fixture**: no test constructs
  `WorkloadClass::KubernetesIntegrated`. Isolation floor for the class is
  always `MicroVm`, so gVisor (`Container`) is rejected by
  `check_isolation_floor` even when trusted order puts it first. The working
  Kubernetes trusted path implied by the order list does not exist until the
  floor mapping or candidate filter changes.

### 3.2 Gates implemented in code

| Gate | Check function | Fixture coverage |
|---|---|---|
| TenantPolicy | `check_tenant_policy` | `tenant_policy_rejects_backend_not_in_allowed_runtimes`, `tenant_unauthorized_for_workload_class`, `stranded_tenant_with_no_allowed_runtimes` |
| IsolationFloor | `check_isolation_floor` | `isolation_floor_from_workload_class`, `isolation_floor_ordering`, `public_untrusted_rejects_gvisor_output`, `runtime_isolation_floor_values` |
| Capabilities | `check_capabilities` | `missing_capability_rejects_backend`, `compatibility_vm_rejects_without_qemu` |
| HealthCapacity | `check_health_capacity` | `health_gate_rejects_unhealthy_backend` (Unavailable rejected, Ready and Degraded pass) **only when `host_health` is `Some`**. `None` skips the gate (`?` on the Option). Most of the 21 fixtures pass `None` and still succeed. |
| CpuIsolation | `check_cpu_isolation` | Cross-tenant host requires pinning for microVM paths and pinning plus SMT exclusion for gVisor. Non-cross-tenant hosts always pass. When `cross_tenant_host` is true and `cpu_isolation_policy` is `None`, the gate also skips. |
| ConformanceStatus | `check_conformance_status` | `conformance_gate_rejects_non_passing_backend` (missing record or `passing=false` rejected) **only when `conformance` is `Some`**. `None` skips the gate. A production caller that omits the map does not enforce ADR-0004's "no gate is advisory" rule. |
| Host support (`available_backends`) | Not implemented | `SelectionInputs.available_backends` is unused. `evaluate` never reads it. A backend not present on the host can still be selected. CpuIsolation is not host support (CPU virt, devices, kernel, network, backend version). |

### 3.3 Reason codes

Stable machine-readable `SelectionReasonCode`, pinned by
`selection_records_metadata_on_success` and the fallback fixtures:

- `preferred-backend-passed`: rank 0 passed every gate
- `fallback-backend-selected`: rank greater than 0 passed, earlier ranks recorded in `rejected_candidates`
- `no-backend-available`: typed `BackendSelectionError::NoBackendAvailable` with per-candidate `RejectedCandidate{runtime, gate, reason}`

Successful decisions record workload class, isolation floor, selected backend,
fallback rank, reason code, required capabilities, rejected candidates,
tenant id, policy epoch, and `decided_at`. Rejections map to
`SandboxError::BackendSelectionRejected` with candidate-specific reasons, so
scheduler scoring never substitutes a backend through placement scoring.

### 3.4 Selection policy fixtures reviewed

Public-untrusted fallback to QEMU when Firecracker is unavailable, trusted
fast-path fallback to Firecracker when gVisor is unavailable, compatibility-VM
QEMU-only selection, health-gate rejection when a health map is supplied,
conformance-gate rejection when a conformance map is supplied, tenant-policy
rejection, unauthorized-class rejection, and metadata recording. All 21
fixtures pass at the tested revision. No fixture asserts that omitted health
or conformance maps fail closed, that `available_backends` is honored, or
that `KubernetesIntegrated` selects a working trusted path.

## 4. Firecracker Production Path

Adapter: `crates/capsule-runtime/src/firecracker/mod.rs` with
`config.rs` and `api.rs`. Base lifecycle via `VmBackendBase` in `base.rs`.

Capability declaration (pinned by
`conformance_capability_declarations_match_firecracker_lifecycle` and
`metadata_advertises_expected_capabilities`):

Declared: `Boot`, `GuestTransport`, `GuestReadiness`, `Exec`, `Suspend`,
`Resume`, `SnapshotRestore`, `Stats`, `Health`, `Diagnostics`.
Explicitly unsupported: `Fork`, `BackendManagedPortForwarding`.

Lifecycle behavior validated:

- `prepare` validates kernel, rootfs, and optional initrd paths when
  `validate_paths` is set, stores config, derives TAP identity via
  `NetworkConfig::for_sandbox_id`, sets `Preparing`, and returns an
  `api-socket` receipt. TAP receipts belong to network-agent, not the
  adapter (pinned by `prepare_records_api_socket_not_tap`).
- `boot` enforces `Preparing` precondition without mutating state on
  violation, removes stale API sockets, launches via jailer when configured
  (UID/GID drop, chroot, seccomp level, x86 `--enable-pci` handling), applies
  CPU affinity when `cpu_set` is present, configures logger, boot source,
  machine config, rootfs drive, optional vsock (`enable_vsock`, default
  `false`), entropy device, and TAP interface via the Firecracker API, waits
  for the guest agent with fail-fast on terminal handshake errors, records
  `boot_latency_ms`, and transitions to `Running`. Boot failure transitions
  to `Failed` and enriches the error with VMM, stdout, and stderr log tails.
- `attach_transport` requires `Running` and always returns
  `GuestTransport::Tcp`. There is no production config that disables TCP or
  selects vsock. `sandboxd::establish_guest_session` rejects any non-TCP
  transport. ADR-0003 production vsock mapping is unimplemented on the wired
  host path (section 10).
- `wait_ready` requires TCP transport and validates guest-agent readiness
  with `Backend` versus `Protocol` classification.
- `exec` requires `Running`, serializes on the single framed session,
  re-handshakes on establishment, and drops poisoned sessions after failure
  (pinned by `exec_error_drops_session_and_next_exec_rehandshakes`).
- `suspend` and `resume` are **state-only**. They flip `Running`/`Suspended`
  and log. They do not call a Firecracker pause/resume or snapshot API. The
  guest keeps running. QEMU at least issues QMP `stop`/`cont` when
  `qmp_enabled`. If the scheduler suspends for oversubscribe or snapshot,
  Firecracker does not pause the VM.
- `restore_snapshot` requires `Running`, requires **at least** two blob paths
  (`len < 2` fails; extra paths are ignored), treats index 0 as memory dump
  and index 1 as VM state, loads via the Firecracker snapshot API, and
  invalidates the prior guest session.
- `fork` returns `Unsupported` for `Fork` without a silent skip.
- `destroy` and `cleanup` are idempotent via `begin_destroy`/`finish_destroy`,
  kill the VMM process, clear guest session and network state, and end in
  `Destroyed` (pinned by `destroy_is_idempotent`,
  `destroy_transitions_to_destroyed_state`, `cleanup_delegates_to_destroy`).
- `stats` returns state plus `boot_latency_ms` with `backend=Firecracker`.
- `health` maps `Running` to `Ready`, `Failed` to `Degraded`, `Destroyed` to
  `Unavailable`, other states to transitional `Ready`.
- `diagnostics` returns a non-empty summary with `boot_latency_ms` plus three
  artifacts: stdout log, stderr log, and VMM log.
- `port_exposure` returns `HostProxy` for all ports. `ssh_username` is `root`,
  `ssh_home_dir` is `/root`. `port_addr` returns `None` until `Running`.

Security posture: jailer-based process isolation with production defaults
(nobody UID/GID, chroot base dir, seccomp level 2), approved KVM/seccomp
cgroup/namespace/device/filesystem controls via `init_seccomp` and
`capsule-runtime-hardening`, signed guest kernel and rootfs artifacts,
deterministic TAP identities, snapshot metadata with restore validation,
  and guest-agent readiness before `Running`. Vsock identity is not created
  unless `enable_vsock` is set (default false). The wired guest transport is
  TCP, not ADR-0003 virtio-vsock.

## 5. gVisor Fast Path

Adapter: `crates/capsule-runtime/src/gvisor/mod.rs` with `config.rs`.
Policy gate: trusted fast path requires an explicit tenant and platform grant.
Removal of that grant removes gVisor from future placement candidates.

Capability declaration (pinned by
`conformance_capability_declarations_match_gvisor_lifecycle` and
`metadata_advertises_gvisor_capabilities`):

Declared: `Boot`, `GuestTransport`, `Exec`, `Stats`, `Health`, `Diagnostics`.
Explicitly unsupported: `GuestReadiness`, `Suspend`, `Resume`, `Fork`,
`BackendManagedPortForwarding`. `suspend`, `resume`, and `fork` return
`Unsupported`.

Lifecycle behavior validated:

- `prepare` validates `runsc` and rootfs paths, stores config, creates an OCI
  bundle (`config.json` with pinned capabilities, masked paths, readonly
  paths, `noNewPrivileges`, memory and CPU shares from sandbox config, and
  `CAPSULE_SANDBOX_ID`), sets `Preparing`, and returns `oci-bundle` plus
  `config-json` receipts.
- `boot` enforces `Preparing` precondition, applies host-side hardening,
  runs `runsc create` plus `runsc start`, probes readiness via `runsc exec
  true` until `boot_timeout`, records `boot_latency_ms`, and cleans up with
  `runsc delete --force` plus `Failed` on error.
- `attach_transport` requires `Running` and returns `GuestTransport::Unix`
  under `runsc_root/container/{id}/sandbox.sock`. That return is currently
  unusable on the host path: `sandboxd::establish_guest_session` accepts
  TCP only and fails closed on Unix.
- `exec` requires `Running` and shells out to `runsc exec` with working
  directory and environment scoping, returning exit code, stdout, stderr, and
  duration.
- `destroy` and `cleanup` are idempotent, run `runsc kill --all SIGKILL` plus
  `runsc delete --force`, remove the OCI bundle directory, and surface
  `PartialCleanup` with `runsc-container` or `bundle` remaining entries when
  removal fails.
- `stats` returns base stats plus optional `runsc_stats` detail when running.
- `health` returns `Ready` with optional `runsc state` detail when running,
  `Degraded` while destroying, otherwise base mapping.
- `diagnostics` returns a summary containing `runsc=` version, `boot_latency`,
  and the compatibility report string, plus `config.json` and log-dir
  artifacts.
- `port_addr` always returns `None`. `port_exposure` is always `HostProxy`.

Compatibility limitations (also emitted in diagnostics via
`gvisor_compatibility_report`, pinned by
`gvisor_compatibility_report_lists_known_limitations`):

Compatible: most CLI tools, package managers, language runtimes, and
statically linked binaries. Limitations: no `perf_event_open`, no `fanotify`,
no `kcmp`, synthetic `/proc` and `/sys`, no kernel module loading, no nested
virtualization via `/dev/kvm`, limited `ptrace` and in-sandbox cgroup support.
Host-network passthrough is forbidden in production. Checkpoint/restore is
supported only when the requested capability has passed Capsule conformance.

Policy restriction: gVisor cross-tenant placement requires CPU pinning with
SMT sibling exclusion. MicroVM backends require at least dedicated-core
pinning on cross-tenant hosts. Enforced by `check_cpu_isolation`.

## 6. QEMU/KVM Compatibility Fallback

Adapter: `crates/capsule-runtime/src/qemu/mod.rs` with `config.rs`.
Role: public-workload fallback that preserves a hardware virtualization
boundary, plus the deliberate compatibility VM for broader device, kernel,
firmware, or image requirements.

Capability declaration (pinned by
`conformance_capability_declarations_match_qemu_lifecycle` and
`metadata_advertises_expected_capabilities`):

Declared: `Boot`, `GuestTransport`, `GuestReadiness`, `Exec`, `Suspend`,
`Resume`, `Stats`, `Health`, `Diagnostics`, `BackendManagedPortForwarding`.
Explicitly unsupported: `Fork`.

Lifecycle behavior validated:

- `prepare` validates kernel and rootfs paths in production mode, stores
  config, sets `Preparing`, and returns a `vm-process` receipt.
- `boot` enforces `Preparing` precondition, validates
  `validate_for_start`, allocates ephemeral guest-agent and QMP addresses,
  builds versioned command args, creates log directories, applies
  `RuntimeHardening` namespace isolation, spawns QEMU, applies CPU affinity
  when `cpu_set` is present, records `boot_latency_ms`, and fails closed to
  `Failed` with console and stderr tails on error.
- `attach_transport` requires `Running` and always returns
  `GuestTransport::Tcp`. Same host-path constraint as Firecracker:
  `sandboxd` accepts TCP only. ADR-0003 vsock is unimplemented.
- `wait_ready` requires TCP transport and classifies readiness failures as
  `Backend` non-ready.
- `exec` requires `Running`, establishes a framed guest session on demand,
  and drops poisoned sessions after failure (pinned by
  `exec_error_drops_session_and_next_exec_rehandshakes`).
- `suspend` and `resume` use QMP `stop`/`cont` when `qmp_enabled`, otherwise
  transition state directly. Both are idempotent on their terminal states
  (pinned by `suspend_and_resume_are_noop_when_qmp_disabled`,
  `suspend_of_suspended_is_idempotent`, `resume_of_running_is_idempotent`).
  Suspend clears the guest session so resume re-handshakes.
- `fork` returns `Unsupported` for `Fork` without a silent skip.
- `destroy` and `cleanup` are idempotent, kill and reap the VM process, clear
  guest session and agent addresses, and end in `Destroyed`.
- `stats` returns state plus `boot_latency_ms` with `backend=QEMU`.
- `health` returns `Ready` with no message when running, otherwise base
  mapping.
- `diagnostics` returns a non-empty summary with `boot_latency_ms` plus two
  artifacts: stdout log and stderr log.
- `port_exposure` returns `BackendManaged` for port 22 and `HostProxy`
  otherwise (pinned by `port_exposure_returns_backend_managed_for_ssh`).
  `port_addr` maps the guest-agent IP with the requested guest port when
  running, else `None`.

ADR-0004 production requirements (not all implemented): pinned machine type,
CPU model or template, firmware policy, and minimized device set; minimized
devices and privileges per workload profile; signed guest artifacts;
Capsule-owned TAP and virtio networking; virtio-vsock by default with
virtio-serial only when compatibility requires it; snapshot metadata bound
to QEMU version, machine type, CPU, devices, image, and protocol
capabilities. Current adapter transport is TCP, not vsock.

## 7. Cloud Hypervisor and Kata Evaluation Outcomes

Status at this revision: and
 are in `Backlog` (priority
Low, kind spike). No production adapter exists. No `RuntimeType` variant
exists. No selection-policy candidate path exists. No conformance profile
passes. Per ADR-0004 both remain disabled in production policy.

| Backend | Evaluation issue | Required evaluation evidence | Outcome at this revision |
|---|---|---|---|
| Cloud Hypervisor |, Isolation Backends 06/9 | Measured boot and memory overhead, snapshot compatibility with Capsule requirements, virtio and transport validation, operational and upgrade model, security posture, implement/defer/reject recommendation with adapter task list and risk register | Not started. Remains evaluation-only. An accepted evaluation alone would not enable selection. Still requires a bounded production adapter, declared capability metadata, approved ADR-0003 transport, backend-specific image and snapshot policy, security and operational review, and passing conformance for every enabled profile. |
| Kata Containers |, Isolation Backends 07/9 | Minimal sandbox boot path, runtime integration model with host-agent and Kubernetes nodes, transport and image compatibility, network ownership, snapshot feasibility, security posture versus direct microVM control, architecture note with integration diagram, lifecycle-gap matrix, implement/defer/reject recommendation | Not started. Remains evaluation-only. Kubernetes is a deployment environment, not an isolation class. Kata is not a public-untrusted production path until, adapter implementation, and conformance approval are complete. If a Kubernetes environment cannot expose an eligible backend, placement is rejected rather than downgraded to a standard container runtime. |

Do-before ordering is preserved: and sit before the final
backend matrix and any implementation issue. does not approve either
backend. A future implement decision must create follow-up implementation
issues and pass the same lifecycle, protocol, snapshot, and isolation gates
as any other backend.

## 8. Backend Conformance Suite Results

Suite: `crates/capsule-runtime/src/conformance/` with
`run_lifecycle_suite` and the backward-compatible `run_backend_conformance`.
Report type: `ConformanceReport` with `passed`, `total_latency_ms`, ordered
`checks`, `unsupported_capabilities`, `missing_capabilities`, and
`resource_accounting`. Rendering via `render_json` and `render_text`
(`Display`).

### 8.1 Test counts at the tested revision

| Suite | Tests | Passed | Failed |
|---|---|---|---|
| Conformance integration (`tests/conformance.rs`) | 15 | 15 | 0 |
| Runtime lib (`cargo nextest run -p capsule-runtime --lib`) | 143 | 143 | 0 |
| Isolation integration (`tests/isolation.rs`) | 28 | 28 | 0 |
| Selection policy (`capsule-core --lib backend_selection`) | 21 | 21 | 0 |
| **Total pinned by this report** | **207** | **207** | **0** |

Conformance integration breakdown:

- `full_suite_passes_with_mock_default`: full lifecycle passes with no missing
  capabilities
- `suite_reports_missing_capabilities`: minimal `Boot`-only backend fails with
  `GuestTransport` in `missing_capabilities`
- `suite_reports_unsupported_capabilities`: minimal production profile reports
  `Suspend`, `Resume`, `Fork`, and `BackendManagedPortForwarding` as
  unsupported
- `suite_records_checks_with_latency`: every check carries a name and latency
- `suite_reports_failures_as_struct`: injected `Boot` timeout surfaces via
  `failures`
- `backward_compat_runner_still_works`: legacy runner still walks
  `Prepare` through `Cleanup`
- `destroy_idempotency_succeeds_with_mock` and
  `cleanup_idempotency_succeeds_with_mock`: destroy and cleanup are repeatable
- `resource_accounting_tracks_prepare_resources`: prepare receipts populate
  resource classes and receipt counts
- `observability_latency_bounds_pass_for_mock`,
  `observability_resource_classes_present`,
  `observability_stats_memory_nonzero`,
  `observability_diagnostics_has_summary`: observability contract holds
- `render_json_produces_valid_output` and
  `display_format_includes_status_and_checks`: reports serialize and render

### 8.2 Conformance phases

Per `run_lifecycle_suite`: capability declarations, state-machine guards,
lifecycle (`prepare`, `boot`, `attach`, `wait-ready`, `exec`, optional
`suspend`/`resume`/`fork`, `destroy`, `cleanup`), destroy idempotency, cleanup
idempotency, restart reconciliation, error taxonomy, network behavior, SSH
metadata, and observability. Lifecycle uses fail-fast on prepare and boot
failures because later operations depend on a running runtime. Independent
phases (destroy, cleanup, error taxonomy, network, SSH) run regardless, so
early-boot failures still produce a partial report.

### 8.3 Unsupported capability declarations reviewed

Unsupported capabilities are explicit declarations, never silent skips.
Capability-gated checks verify that undeclared operations return
`BackendError::Unsupported`:

- Firecracker: `Fork` returns `Unsupported`. `BackendManagedPortForwarding`
  absent and `port_exposure` never returns `BackendManaged`.
- gVisor: `Fork`, `Suspend`, and `Resume` return `Unsupported`.
  `GuestReadiness` absent. `BackendManagedPortForwarding` absent.
- QEMU: `Fork` returns `Unsupported`. Port 22 is `BackendManaged`, other
  ports are `HostProxy`.
- Mock: full capability set passes; minimal sets correctly report missing and
  unsupported entries; `SnapshotRestore` undeclared paths return
  `Unsupported` via `restore_snapshot` with empty blob paths.

Conformance also pins `capabilities/version-non-empty`,
`capabilities/declares-at-least-one`, and `capabilities/boot-declared`.

### 8.4 Isolation boundary evidence (supporting)

`run_isolation_suite` validates filesystem, process, network, resource,
credential, backend, data-sharing, and side-channel boundaries with
`Pass`/`Fail`/`Skipped` outcomes. Skipped checks do not affect pass status.
Non-live mode validates policy, configuration, metadata, and classification
invariants. Live boundary probing requires `live_boundary_tests=true` with a
real backend. Backend-specific pins reviewed:
`backend/boundary-classification-invariants`,
`backend/production-eligibility-invariants`,
`backend/capability-declarations`, `backend/selection-policy-boundaries`, and
`isolation-floor/assertion` per backend floor.

## 9. Backend-Specific Security, Observability, and Operational Limitations

### 9.1 Security limitations

- Firecracker: KVM, jailer, guest kernel, TAP, artifact, and snapshot
  compatibility must be managed. Requires jailer confinement, dedicated
  runtime identities, namespaces, seccomp, capability removal, cgroup v2
  enforcement before untrusted execution, minimal pinned device model,
  per-sandbox TAP/API-socket/console/snapshot/filesystem ownership, and
  narrow privileged helpers. Covered by.
  Vsock is off by default. The wired guest transport is TCP.
  Shared-host cross-tenant placement is not eligible until the
  assessment approves the exact host, CPU, virtualization, scheduling, and
  workload profile. Until then use dedicated tenancy.
- gVisor: syscall, filesystem, networking, accelerator, and checkpoint
  compatibility vary by workload. Requires explicit policy grant, verified
  syscall/filesystem/network/accelerator/image compatibility, approved
  isolated network mode (netstack or CNI integration, never host-network
  passthrough), permission-controlled Unix socket transport, and conformance
  for any checkpoint/restore capability requested. Never an automatic public
  fallback. Silent isolation downgrade from hardware virtualization to syscall
  mediation is prohibited by policy and pinned by selection fixtures.
- QEMU: broader device surface, configuration space, patching, and tuning
  increase operational burden. Requires pinned machine type and CPU policy,
  minimized devices and privileges, signed artifacts, Capsule-owned TAP and
  virtio networking, and version-bound snapshot metadata. ADR-0004 wants
  vsock by default; the adapter currently uses TCP. Operational cost is
  higher than Firecracker. Use as fallback and compatibility VM, not as the
  default.
- Cloud Hypervisor and Kata: high operational risk until evaluation proves
  lifecycle, upgrade, snapshot, and security readiness. Remain disabled.

Snapshot and restore rules: snapshots bind to the creating backend family
with exact runtime version or approved range, architecture, CPU
vendor/model/template/features, machine and device model, kernel/firmware
rootfs/image digests, snapshot format version and lineage, guest-agent
protocol versions and capabilities, and regenerated network and identity
resources. Cross-backend restore is prohibited.

### 9.2 Observability and metrics

Per-backend metrics and diagnostics are available for all preview paths:

- `stats`: state plus `boot_latency_ms` plus `backend` label in `details`.
  Firecracker and QEMU expose `boot_latency_ms` after boot. gVisor optionally
  includes `runsc_stats` when running.
- `health`: `Ready`/`Degraded`/`Unavailable` with checked-at timestamp and
  redacted message. Running maps to `Ready`. Failed maps to `Degraded`.
  Destroyed maps to `Unavailable`.
- `diagnostics`: redacted summary plus artifact paths. Firecracker exposes
  three artifacts (stdout, stderr, VMM log). QEMU exposes two artifacts
  (stdout, stderr). gVisor exposes bundle config plus log dir plus
  compatibility text plus `runsc --version`.
- Boot telemetry: host-agent emits `boot_ready` and `boot_not_ready` with
  `reason=backend` (VMM start), `reason=protocol` (transport/auth/handshake),
  `reason=timeout`, `reason=cleanup`, plus `outcome=runtime_start_failed` or
  `protocol_error`. Default boot budget is 60s. Conformance enforces a 60s
  per-operation latency bound via `observability/latency-bounds`.
- Lifecycle telemetry: suspend/resume/quiesce latency histograms, resume
  notify events and durations, `capsule_network_health_state` (0 ready,
  1 degraded, 2 unsafe), cgroup OOM and setup signals, and tracing spans
  (`boot_sandbox` to adapter `boot` to guest protocol with bounded `backend`
  attribute).
- Dashboards: `capsule-runtime-backend` (network health, suspend/resume
  quiesce latency, resume notify), `capsule-lifecycle-operations` (operation
  volume by phase with `boot_not_ready` by `backend`/`protocol`),
  `capsule-host-health` (cgroup and host signals). All dashboards template by
  region, cell, and backend.
- Runbook: `docs/runbooks/runtime-backend.md` (owner Runtime/SRE-Capsule,
  severity, first checks, logs/traces/audit, mitigation without weaker-backend
  substitution, escalation, rollback). Related: `lifecycle-operations`,
  `host-quarantine`, `networking`, and the `boot-non-ready-and-quarantine`
  drill.

### 9.3 Operational limitations and policy restrictions

- Public capacity must support at least one production VM backend. Robust
  fallback requires both Firecracker and QEMU capacity.
- Maintaining two public-workload VM paths increases patching, conformance,
  image, snapshot, and operational work.
- Trusted fast-path admission requires policy and compatibility evidence.
  Removing the grant immediately removes gVisor from future candidates.
- Cross-backend restore is unavailable. Cold boot from durable workspace state
  is a separate operation, never represented as snapshot resume.
- Kubernetes environments without an approved VM backend cannot run public
  untrusted workloads.
- Destroy without complete cleanup must return `PartialCleanup` with
  deterministic remaining identities, never a silent leak. Identity and
  address reuse requires proven absence or quarantine.
- No tenant-visible VMM management sockets (Firecracker API socket, QMP
  socket), host-agent sockets, control-plane credentials, or privileged helper
  sockets.

## 10. Known Gaps and Recommendations

| Gap | Severity | Evidence | Mitigation and follow-up |
|---|---|---|---|
| Wired host path is TCP. ADR-0003 requires virtio-vsock for Firecracker/QEMU and Unix socket for gVisor. There is no production config that disables TCP. | High | `FirecrackerAdapter::attach_transport` and `QemuAdapter::attach_transport` always return `GuestTransport::Tcp`. `enable_vsock` defaults to `false`. `sandboxd::establish_guest_session` rejects anything except TCP. `GVisorAdapter` returns `Unix`, which `sandboxd` then rejects. deferred vsock to this phase. | Blocking for production. Implement vsock (Firecracker/QEMU) and Unix (gVisor) on the host path, or fail `ProtocolCompatibility` closed on TCP. Do not treat a missing kill-switch as containment. Add transport integration tests. |
| Health and conformance gates fail open when input maps are omitted | High | `check_health_capacity` and `check_conformance_status` use `?` on `Option`. `None` skips the gate. Most of the 21 fixtures pass `None` and still succeed. ADR-0004 says no gate is advisory. | Require `Some` maps in production callers, or change the checks so omitted maps reject. Add fixtures that fail closed on `None`. |
| `available_backends` is unused, so host support is not a selection gate | High | `SelectionInputs.available_backends` is never read by `evaluate`. A backend not present on the host can still be selected. CpuIsolation is not host support. | Filter candidates to `available_backends` (or reject missing host support) and pin with a fixture. |
| Firecracker `suspend`/`resume` are state-only no-ops | Medium | They flip `Running`/`Suspended` and log. No Firecracker pause/resume API. The guest keeps running. | Implement Firecracker pause/snapshot APIs, or undeclare `Suspend`/`Resume` until they do real work. Do not schedule oversubscribe or snapshot on the assumption that Firecracker is paused. |
| KubernetesIntegrated order is not pinned and gVisor cannot pass its floor | Medium | No test constructs `WorkloadClass::KubernetesIntegrated`. Floor is always `MicroVm`, so gVisor (`Container`) is rejected even when trusted order puts it first. | Add fixtures. Either lower the Kubernetes trusted floor via an underlying class, or stop putting gVisor first in that order. |
| Conformance required set is not profile-aware: `GuestReadiness` is required for all backends, so gVisor (which correctly omits it) cannot pass `run_lifecycle_suite` | Medium | `run_lifecycle_suite` required set includes `GuestReadiness`. `GVisorAdapter` omits it by design. `conformance_capability_declarations_match_gvisor_lifecycle` pins the omission. | Resolve before calling gVisor conformance production-complete. Either implement `wait_ready` for gVisor over its Unix transport or introduce profile-aware required sets. |
| Conformance `all_capabilities` omits `SnapshotRestore` and `EbpFNetworking`, so unsupported accounting never lists them | Low | `conformance/mod.rs::all_capabilities` lists 11 variants. `runtime.rs::BackendCapability` has 13 variants. `capabilities.rs` handles `SnapshotRestore` but the check never triggers for backends that omit it. | Include the two missing variants in `all_capabilities`. Firecracker restore requires `len >= 2` and ignores extra paths. |
| Selection policy implements 6 of 9 ADR-0004 gates in code. Image, snapshot, and protocol compatibility have enum variants but no dedicated `check_*` functions | Medium | `BackendSelectionGate` has 9 variants. Image, snapshot, and protocol compatibility are not standalone policy checks. Combined with fail-open optional maps and unused `available_backends`, host support is also unimplemented. | Add dedicated checks that fail closed. Until then, do not claim ADR-0004 gates are enforced. |
| No end-to-end VMM boot in CI. Conformance passes against `MockBackend`. Adapter boot paths require KVM, jailer/runsc/QEMU binaries, and TAP networking | Medium | `conformance_lifecycle_with_mocked_guest_agent` is `ignore`d and requires Firecracker plus `CAP_NET_ADMIN`. | Run at least one live boot per preview backend before any launch stage on the exact host image, kernel, VMM version, and guest artifact profile, and attach the immutable results to. |
| Cloud Hypervisor and Kata have no measured boot, memory, snapshot, or security evidence | Low (expected) | and in `Backlog`. No adapter, no selection path, no conformance run. | Keep both evaluation-only. Do not create adapters until evaluations produce implement recommendations with risk registers. |
| Shared-host cross-tenant placement depends on approval or dedicated tenancy | High for shared hosts | ADR-0006 invariant 12, `check_cpu_isolation`, side-channel assessment. | Maintain dedicated tenancy for public multi-tenant execution until approves the exact shared-host profile. |

Recommendations:

1. Blocking: make vsock the Firecracker/QEMU host path and Unix the gVisor
   host path, or fail `ProtocolCompatibility` closed on TCP. Teach
   `sandboxd::establish_guest_session` to accept those transports. There is
   no TCP kill-switch today.
2. Blocking: fail closed when health, conformance, or host-availability
   inputs are omitted, and honor `available_backends`. Pin with fixtures.
3. Before any launch stage: run one live boot plus guest-agent handshake per
   preview backend on the candidate host profile. Attach VMM versions,
   artifact digests, and log tails to.
4. Implement Firecracker pause/resume or undeclare `Suspend`/`Resume`.
5. Resolve the gVisor `GuestReadiness` required-set mismatch and the
   KubernetesIntegrated floor/order contradiction before treating gVisor as
   a working Kubernetes path.
6. Continuous: expand the conformance suite as new RPCs and capabilities are
   added, following the misuse-resistance checklist in
   `docs/robustness/misuse-resistance-checklist.md`.
7. Continuous: keep Cloud Hypervisor and Kata disabled in tenant
   `allowed_runtimes` and verify in admission tests that no configuration
   alone can enable them.

## 11. Acceptance Criteria Mapping

- Supported backends have explicit production status (supported, preview,
  evaluation-only, or rejected): section 2. Firecracker and QEMU are
  preview. gVisor is preview with policy restriction. RemoteFirecracker is
  rejected for production. Cloud Hypervisor and Kata are evaluation-only.
  No backend is `supported` at this revision.
- Backend conformance results are linked: section 8. 15 conformance tests,
  143 runtime lib tests, 28 isolation tests, and 21 selection tests pass.
  Repro commands in the header. Reports render via `to_json` and `Display`.
- Backend-specific limitations and policy restrictions are documented:
  sections 5 through 9. Includes gVisor syscall and network limits, QEMU
  operational burden, Firecracker artifact and snapshot management, snapshot
  and restore prohibitions, and tenant-grant revocation semantics.
- Backend metrics and diagnostics are available for preview paths:
  section 9.2. Stats, health, diagnostics, boot telemetry, lifecycle
  histograms, network health, dashboards, and runbooks are listed per path.
- Architecture, runtime, security, and SRE owners approve the readiness
  report: pending (see Approval).

## Approval

See and the associated pull request for implementation evidence.

| Role | Name | Date | Decision |
|---|---|---|---|
| Architecture owner | - | - | Pending |
| Runtime owner | - | - | Pending |
| Security owner | - | - | Pending |
| SRE owner | - | - | Pending |

## Appendix A: Test Run Output

```
#Conformance integration
test result: ok. 15 passed; 0 failed; 0 ignored (capsule-runtime conformance)

#Isolation integration
test result: ok. 28 passed; 0 failed; 0 ignored (capsule-runtime isolation)

#Runtime lib (includes firecracker, gvisor, qemu, conformance, isolation,
#mock, snapshot_optimizer, validation units)
test result: ok. 143 passed; 0 failed; 0 ignored (capsule-runtime lib)

#Selection policy (lib filter)
test result: ok. 21 passed; 0 failed; 0 ignored (capsule-core backend_selection)

Total pinned by this report: 207 tests, 0 failures
```

Note: `cargo nextest run -p capsule-core` without a lib filter also builds
`tests/secrets_broker.rs`, which requires the `secrets-http` feature and
fails to compile without it. That pre-existing CI gap is unrelated to
backends. The backend evidence above uses `--lib` filters plus the two
runtime integration binaries, all of which are clippy-clean under
`-D warnings` on their own targets.

## Appendix B: Reproducibility

```bash
#Full backend evidence set used by this report
cargo nextest run -p capsule-runtime --test conformance
cargo nextest run -p capsule-runtime --test isolation
cargo nextest run -p capsule-runtime --lib
cargo nextest run -p capsule-core --lib backend_selection

#Clippy for the touched crates
cargo clippy -p capsule-runtime -p capsule-core --lib --locked -- -D warnings
```
