<p align="center">
  <img src="favicon.svg" alt="Capsule Logo" width="64" height="64" />
</p>

<h1 align="center">Capsule</h1>

<p align="center">
  <a href="https://github.com/SpatiumLabs/capsule/actions/workflows/test.yaml"><img src="https://github.com/SpatiumLabs/capsule/actions/workflows/test.yaml/badge.svg?branch=main&style=flat" alt="Test Status"></a>
  <a href="https://github.com/SpatiumLabs/capsule/actions/workflows/audit.yaml"><img src="https://github.com/SpatiumLabs/capsule/actions/workflows/audit.yaml/badge.svg?branch=main&style=flat" alt="Audit Status"></a>
  <a href="https://github.com/SpatiumLabs/capsule/actions/workflows/semgrep.yaml"><img src="https://github.com/SpatiumLabs/capsule/actions/workflows/semgrep.yaml/badge.svg?branch=main&style=flat" alt="Semgrep Status"></a>
  <a href="https://github.com/SpatiumLabs/capsule/actions/workflows/release-cli.yaml"><img src="https://github.com/SpatiumLabs/capsule/actions/workflows/release-cli.yaml/badge.svg?branch=main&style=flat" alt="Release CLI Status"></a>
</p>

**Capsule is a cloud compute layer for the Age of AI Agents.**

It provides secure, policy-controlled, observable sandboxes for AI agents and developer workloads. Capsule is designed for workloads that need to create environments quickly, run commands safely, preserve or fork state, expose controlled network access, and clean up reliably.

The project focuses on the infrastructure layer behind agent execution:

- sandbox lifecycle management
- microVM/container runtime orchestration
- host/guest protocol
- per-sandbox networking
- reproducible guest images
- snapshot, resume, and fork
- zero-trust access control
- observability, reliability, and production readiness

## Why Capsule exists

AI agents increasingly need isolated compute environments where they can:

- run tools and commands
- access scoped credentials
- fetch or modify files
- call external services
- keep state across sessions
- fork workspaces for parallel exploration
- expose temporary preview or callback endpoints

Running these workloads safely is not only a container problem. Agent compute needs stronger lifecycle control, explicit policy enforcement, auditability, snapshot semantics, and reliable cleanup.

Capsule aims to provide that substrate.

## Core goals

Capsule is designed around these goals:

1. **Secure multi-tenant execution**
   Public/untrusted workloads should run in strong isolation by default.

2. **Fast sandbox startup**
   Support cold boot, warm pool, warm snapshot restore, and eventually lazy restore.

3. **Explicit lifecycle semantics**
   Every sandbox follows a clear state machine from creation through execution, suspension, restoration, fork, and destruction.

4. **Zero-trust access control**
   Network access, port exposure, and runtime credentials are policy-granted capabilities, not ambient defaults.

5. **Snapshot, resume, and fork**
   Sandboxes can preserve state, resume later, and fork into independent children with controlled filesystem and identity semantics.

6. **Production-grade observability**
   Operators can debug lifecycle latency, placement, runtime behavior, networking, image preparation, snapshot restore, and audit events.

7. **Evidence-based readiness**
   Production rollout depends on validation reports, SLOs, dashboards, runbooks, security assurance, and capacity models.

## High-level architecture

```text
Client/Agent Platform
        |
        v
Public Platform API
        |
        v
Regional Control Plane
  - API gateway
  - AuthN/AuthZ
  - Tenant policy engine
  - Access lease manager
  - Sandbox scheduler
  - Runtime orchestrator
  - Image resolver
  - Snapshot manager
  - Network policy controller
  - Audit/event bus
        |
        v
Cell Control Plane
  - Placement manager
  - Host inventory
  - Capacity manager
  - Warm pool manager
  - Snapshot cache index
  - Failure detector
        |
        v
Compute Host
  - host-agent
  - sandboxd
  - runtime adapters
  - network-agent
  - image-agent
  - snapshot-agent
  - metrics-agent
        |
        v
Sandbox Backends
  - Firecracker
  - gVisor
  - QEMU
  - Cloud Hypervisor
  - Kata Containers
```

## Main components

### Control Plane

The control plane owns API admission, tenant policy, quota, access leases, scheduling, lifecycle state, audit events, and production readiness gates.

Important capabilities:

- public sandbox lifecycle API
- sandbox metadata state machine
- secure time and identity binding
- tenant quota and policy enforcement
- zero-trust access lease management
- regional and cell scheduling
- lifecycle audit event emission

### Host Runtime

The host runtime owns local sandbox execution.

Important capabilities:

- Rust `host-agent` as the host lifecycle coordinator and sole reporter to the
  cell control plane
- authenticated host RPC endpoints with bearer-token protection on every route
  except `/rpc/v1/health`, and loopback binding by default
- local `sandboxd` as the durable supervisor for per-sandbox serialization,
  process and stream handles, restart reconciliation, and cleanup progress
- runtime adapter interface
- narrow typed helpers for privileged network, cgroup, mount, and runtime work
- boot lifecycle
- exec lifecycle
- suspend and resume lifecycle
- destroy cleanup and reconciliation

Runtime adapters and helper agents execute bounded, idempotent operations.
They do not own lifecycle policy or regional state. `sandboxd` persists only
host-local observed state and resource receipts; the regional metadata store
remains authoritative. See
[ADR-0002](docs/adr/0002-host-runtime-lifecycle-orchestration.md).

The QEMU backend captures stdout and stderr to
`$HOME.local/share/capsule/logs/qemu/{sandbox_id}-stdout.log` and
`{sandbox_id}-stderr.log`. Set `CAPSULE_QEMU_LOG_DIR` to override the
default log directory. These paths appear in `diagnostics` output for
operator tooling.

The `capsule-sandboxd` crate implements the local supervision foundation:

- per-sandbox serialization for mutating runtime and process operations
- explicit cancellation and absolute deadlines
- typed succeeded, failed, canceled, timed-out, and review-required outcomes
- durable boot outcomes classified as image, network, resource, backend,
  protocol, timeout, or cleanup failures
- host resource materialization during prepare and teardown during destroy:
  workspace directories, cgroup v2 limits and cpuset, and CPU pinning
  allocation, each recorded as durable workspace and cgroup resource receipts
- a single-writer SQLite ledger using WAL and `synchronous=FULL`
- durable fencing tokens, operation intents, resource receipts, process
  identities, and restart reconciliation
- process-tree cleanup, bounded stdout and stderr capture, and pidfd ownership
  on Linux kernels that support `pidfd_open`

Runtime stdout, stderr, stdin, credentials, and user data are not persisted in
the supervisor ledger.

When a host enters drain mode, it stops accepting new sandbox prepare or boot
work and uses the configured drain timeout during shutdown before exiting.

### Isolation Backends

Capsule supports multiple runtime backends through a shared `RuntimeBackend` interface.

The interface lives in `capsule-core` and defines backend-neutral prepare,
boot, transport attachment, guest readiness, exec, suspend, resume, fork,
destroy, cleanup, stats, health, diagnostics, and port exposure operations.
Backends publish an explicit capability set, deterministic resource receipts,
and typed failures for image, network, resource, backend, protocol, timeout,
cleanup, incomplete setup, stale state, unsupported capabilities, and invalid
lifecycle state.

`capsule-runtime::mock` provides a configurable backend and conformance runner
for lifecycle integration tests. The host agent stores only
`Arc<dyn RuntimeBackend>` and uses interface-provided port ownership instead
of checking concrete backend types.

The adopted backend policy is defined by
[ADR-0004](docs/adr/0004-default-isolation-backend-strategy.md):

- **Firecracker** as the default for public multi-tenant workloads
- **gVisor** as an explicit trusted fast path
- **QEMU** as the public-workload fallback and compatibility VM
- **Cloud Hypervisor** and **Kata Containers** remain evaluation-only

Fallback never silently lowers the isolation boundary. The control plane
records a new audited selection decision, and snapshot restore remains bound
to a compatible backend, runtime version, CPU and device profile, image, and
guest protocol contract.

### Guest Agent Protocol

Capsule uses tonic gRPC with Protocol Buffers `proto3` to coordinate work
inside the sandbox. Runtime backends provide the local byte stream:
Firecracker and the QEMU backend use vsock, and the QEMU backend may
fall back to virtio-serial,
and gVisor or container runtimes use permission-controlled Unix domain
sockets. TCP loopback is limited to local development and tests.

Each production connection uses a fresh per-sandbox, per-boot secret for
HMAC-SHA256 mutual challenge-response. The resulting session binds sandbox,
image, boot, policy, protocol, and capability identity to that connection.
Hosts and newly built guest agents support the current and immediately
previous protocol major and negotiate the highest compatible version.

Messages and streams are bounded: protobuf messages are limited to 1 MiB,
stream payload frames to 64 KiB, and replay buffering to 1 MiB per output
stream. Streams use sequence IDs, acknowledgements, backpressure, and explicit
reattachment. Restore and fork require fresh authentication, renegotiation,
and `ResumeNotify` before readiness. See
[ADR-0003](docs/adr/0003-host-guest-agent-protocol-contract.md).

The [protocol robustness test suite](docs/robustness) validates the
protocol boundary against malformed, stale, replayed, and adversarial
messages. A [misuse-resistance checklist](docs/robustness/misuse-resistance-checklist.md)
documents the required test coverage for every new RPC.

Core RPCs include:

- `Ping`
- `Exec`
- `Signal`
- `Cancel`
- `Quiesce`
- `PrepareSnapshot`
- `ResumeNotify`
- `MountWorkspace`
- `PutFile`
- `GetFile`
- `Stats`
- `Health`
- `Shutdown`

### Per-Sandbox Networking

The adopted networking model is defined by
[ADR-0005](docs/adr/0005-per-sandbox-networking-model.md).
Every sandbox receives an independent logical network identity and Linux
network namespace, using TAP for microVMs and veth attachment for
container-backed sandboxes.

Networking features:

- routed layer-3 isolation with no shared tenant layer-2 network
- nftables anti-spoofing, deny-by-default policy, NAT, and accounting
- policy-aware DNS with protected destination filtering
- access-lease-controlled egress exceptions and gateway-based port forwarding
- stable logical identity across resume with fresh identity on fork
- receipt-based cleanup, reconciliation, quarantine, and network metrics

Approved CNI integrations must preserve the same Capsule contract.
Proxy-only networking is an explicit limited profile, and Open vSwitch is
deferred until measured requirements justify its additional operational
surface.

### Guest Image Pipeline

Capsule images are reproducible, signed, validated, and compatible with
runtime backends. The normative format, manifest, verification, and promotion
contract is defined by
[ADR-0008](docs/adr/0008-guest-image-format-and-build-pipeline.md).

The canonical Capsule Guest Image Bundle is an OCI image index consumed by
digest. It contains per-architecture and backend-compatible variants:
deterministic ext4 rootfs, kernel, init, and guest-agent artifacts for
Firecracker and QEMU, plus OCI filesystem variants for gVisor. Every rendering
comes from one normalized filesystem tree and is promoted as part of one
tested release graph.

Image pipeline features:

- Capsule JSON manifests with bounded backend, protocol, mount, and snapshot
  compatibility metadata
- reproducible rootfs pipeline
- workspace and secret mount layout
- minimal kernel/init path
- guest-agent injection
- backend boot-to-authenticated-handshake validation
- SPDX SBOMs, SLSA/in-toto provenance, vulnerability results, signatures, and
  promotion attestations attached as OCI referrers
- immutable `built`, `validated`, `candidate`, and `production` promotion
  stages
- separately signed, backend-bound warm snapshot generation

Production hosts verify the exact bundle and variant digests, trusted build
identity, production promotion, supply-chain evidence, revocation state, and
local runtime compatibility before caching or booting an image.

### Snapshot, Resume, and Fork

Capsule supports stateful workflows through snapshots and forkable workspaces.
The normative consistency model is defined by
[ADR-0007](docs/adr/0007-snapshot-resume-fork-consistency-model.md).

The portable v1 contract is filesystem-first. Snapshot and fork drain active
execs, quiesce the guest, commit an immutable workspace point, and fail closed
when quiescence or excluded-state validation cannot complete. Memory
preservation is an explicit backend capability rather than the default.

Snapshot features:

- filesystem and capability-gated memory state profiles
- cooperative quiescence with no forced fallback
- explicit active exec and stream behavior
- snapshot metadata and lineage
- base snapshot restore
- copy-on-write workspace branching
- filesystem COW fork
- memory snapshot restore
- snapshot encryption and integrity checks
- lazy memory restore prototype
- snapshot cache tiering and garbage collection

Resume preserves sandbox and workspace lineage while replacing boot,
protocol, credential, host-local, and network authority. Fork creates an
independent child sandbox, workspace layer, policy, network identity, quota,
and credential scope. Backend-native snapshot formats are not exposed as the
user-facing contract. Lifecycle suspend/resume requires the memory profile;
filesystem-only restore is a boot path rather than a resume transition.

### Security Hardening

Security is a first-class project track, not a final cleanup phase.
The normative production baseline is defined by
[ADR-0006](docs/adr/0006-production-security-posture-for-sandbox-isolation.md).
The detailed assets, actors, trust boundaries, abuse cases, risk trees,
failure modes, controls, and residual risks are maintained in the
[Capsule threat model](docs/security/threat-model.md).
Stage thresholds, blocking gate evidence, owner responsibilities, and the
current launch disposition are defined in the
[Capsule production readiness model](docs/security/production-readiness.md).

Security features:

- workload-class isolation floors and production security gates
- maintained risk and threat model with control and evidence mapping
- [production readiness model](docs/security/production-readiness.md)
- seccomp and capability minimization
- runtime process hardening
- cgroup v2 resource controls
- runtime secrets broker integration
- credential exclusion from snapshots
- isolation boundary validation
- side-channel and covert-channel risk assessment
- security assurance case

### Observability and Reliability

Capsule is designed to be debuggable and operable under production load.
The normative signal, correlation, cardinality, redaction, audit, dashboard,
and alert contract is defined by
[ADR-0009](docs/adr/0009-observability-and-reliability-signals.md).

Capsule uses OpenTelemetry APIs, OTLP export, W3C Trace Context, and structured
JSON platform logs for operational telemetry. Metrics use bounded,
tenant-safe dimensions and enforce a hard per-instrument cardinality limit.
Protected traces and logs carry operation correlation without treating trace
context as authority or exposing tenant data through metric labels.

Security and authoritative decisions use a separate durable audit plane.
Audit records are immutable, unsampled, durably enqueued before affected
mutations report success, delivered at least once, and deduplicated by event
identity. Audit or required telemetry gaps affect readiness and can block
mutations, drain hosts, or trigger production alerts.

Observability features:

- shared operation, phase, outcome, and reason taxonomy
- lifecycle, scheduling, host, runtime, network, snapshot, and cleanup metrics
- full lifecycle traces with failure, latency, and security-aware sampling
- source-redacted structured platform logs separated from workload output
- durable audit delivery with retry, dead-letter, ordering, and integrity
  evidence
- service-level dashboards, SLO burn views, and readiness signals
- host health, quarantine, audit, telemetry, and security alert categories
- dashboard-linked [operational runbooks](docs/runbooks/README.md) and
  [SLO error-budget policy](docs/observability/slo-error-budget-policy.md)

### Scale Testing and Production Readiness

Production rollout is gated by evidence.
The normative strategy is
[ADR-0012](docs/adr/0012-production-scale-validation-strategy.md):
phased environments, workload mixes, launch proven operating points, and
class-A/B/C failure rules. Architecture section 14.1 numbers remain design
targets. Stage quotas must stay at or below the measured LPOP for the exact
deployment profile.

Scale-readiness features:

- [production scale validation strategy](docs/adr/0012-production-scale-validation-strategy.md)
- platform load validation harness
- [active sandbox capacity model](docs/capacity/active-sandbox-defaults.md)
- [cell unavailability handling](docs/capacity/cell-unavailability.md)
- [snapshot restore pressure](docs/capacity/checkpoint-load.md)
- [image cache validation](docs/capacity/image-cache.md)
- [cost and capacity planning model](docs/capacity/cost-model.md)
- [control plane production readiness](docs/control-plane/prod-readiness-report.md)
- production rollout checklist

## Sandbox lifecycle

Capsule uses an explicit lifecycle state model:

```text
Pending -> Scheduled -> Preparing -> Booting -> Running
Running -> Suspending -> Suspended -> Resuming -> Running
Running -> Stopped -> Running
Running | Suspended | Stopped | Failed -> Destroying -> Destroyed
Any non-terminal state -> Failed
```

Guest-agent readiness completes the `Booting -> Running` transition. Exec
activity is an observed attribute while the sandbox remains `Running`; it does
not create `Executing` or `Idle` lifecycle states. Fork creates a child that
follows the normal `Pending -> Running` path without changing the source
sandbox state. See
[ADR-0001](docs/adr/0001-control-plane-ownership-lifecycle-state-model.md).

The authenticated `POST /rpc/v1/boot` host RPC accepts a fenced `BootCommand`
with the sandbox and operation IDs, assigned host and cell, assignment fencing
token, policy epoch, and timeout. `host-agent` validates this envelope before
side effects. `sandboxd` then runs backend boot, transport attachment, and
guest readiness under one durable deadline. Failed preparation or boot
triggers bounded cleanup, and unresolved resources produce a review-required
cleanup outcome. Replaying the same operation ID returns the persisted result
without repeating backend work.

Boot telemetry emits `boot_start`, `boot_ready`, `boot_not_ready`, and
`boot_cleanup` events, plus `capsule_boot_latency_seconds` and
`capsule_boot_events_total` metrics.

## Example lifecycle API

The public API is expected to support operations such as:

- `CreateSandbox`
- `GetStatus`
- `Exec`
- `Signal`
- `AttachStream`
- `PutFile`
- `GetFile`
- `ExposePort`
- `UpdatePolicy`
- `Suspend`
- `Resume`
- `Fork`
- `Destroy`

## Security model

Capsule assumes:

- workloads may be untrusted
- network location is not a trust boundary
- credentials must be short-lived and scoped
- snapshots must not capture secrets
- every privileged decision should be auditable
- host cleanup must be reliable and idempotent
- production readiness must be evidence-based

Default security posture:

- Firecracker microVMs for public untrusted workloads, with QEMU as the
  only fallback
- gVisor only through explicit tenant and platform approval for a trusted
  fast path
- dedicated tenancy until the shared-host profile passes the
  side-channel assessment
- minimized runtime identities, namespaces, seccomp, capabilities, devices,
  mounts, sockets, and cgroup v2 resources
- no Docker socket exposure
- no privileged containers
- no host namespace sharing
- no shared writable filesystem across tenants
- default-deny networking with no ambient platform, metadata, host, or peer
  access
- brokered, short-lived credentials that are revoked and excluded from
  snapshots
- no production readiness before every required control and validation gate
  passes for the exact deployed profile

The complete posture, hard invariants, risk mapping, and mandatory launch
evidence are defined by
[ADR-0006](docs/adr/0006-production-security-posture-for-sandbox-isolation.md).

## Repository layout

The workspace is organized as a set of Rust crates under `crates/`, each with a
focused responsibility (API gateway, sandbox lifecycle, networking, image
builds, telemetry, etc.). Tests live alongside their crate. Infrastructure
templates, CI definitions, docs, and agent configurations sit at the top level.

See [ARCHITECTURE.md §16](ARCHITECTURE.md#16-repository-layout) for the full tree.

## Project status

Capsule is currently in the architecture and development phase.

The implementation plan is organized into these tracks:

1. Control Plane
2. Host Runtime and Sandbox Lifecycle
3. Isolation Backends
4. Guest Agent Protocol
5. Per-Sandbox Networking
6. Guest Image Pipeline
7. Snapshot, Resume, and Fork
8. Security Hardening
9. Observability and Reliability
10. Scale Testing and Production Readiness

## Development

### Nix Development Environment

This project provides a Nix flake for reproducible development environments.

#### Setup

```bash
#Enter the development shell (auto-activated with direnv)
nix develop

#Or use direnv (recommended)
direnv allow
```

#### Included Tools

- Rust 1.98.1 + rustfmt, clippy, rust-analyzer, rust-src
- cargo-nextest, cargo-hack, cargo-sort, cargo-watch
- clang, mold (Linux), lld (Linux)
- pkg-config, openssl, protobuf, cmake, gnumake
- PostgreSQL (for sqlx)
- Terraform, Docker
- jq, curl, openssh, git, opencode

#### Platform Support

- `aarch64-linux` - Primary development and production
- `x86_64-linux` - Linux x86 development and production
- `aarch64-darwin` - macOS development only

## Development principles

- Build one production-quality path before adding backend breadth.
- Prefer explicit state machines over implicit lifecycle behavior.
- Make policy decisions auditable.
- Do not treat network locality as trust.
- Keep secrets out of images, logs, workspaces, and snapshots.
- Make cleanup idempotent and restart-safe.
- Require conformance tests for every backend.
- Treat dashboards, runbooks, SLOs, and validation reports as part of the product.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
