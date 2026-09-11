# Capsule domain context

Working glossary for architecture and implementation. Prefer these names in code, docs, and reviews. Use hyphen not em dash.

## Core lifecycle

| Term | Meaning |
|------|---------|
| Sandbox | Isolated agent compute instance with a lifecycle from admission through destroy |
| SandboxMetadata | Control-plane record of desired lifecycle state, fencing, policy epoch, placement (ADR-0001) |
| commit | Sole mutation for desired lifecycle state: `commit(from, to, token)` on `SandboxMetadata`. Host writes go through this; observation never invents a transition |
| Observed state | What the host has actually created or seen; recorded in the sandboxd ledger, not a second authority over desired state |
| Host-agent | Host lifecycle coordinator: admits commands, checks fencing/policy, talks to sandboxd over RPC, reports observations, serves API/cell surface |
| sandboxd | Durable local supervisor process: sole owner of runtime backends, host resource materialization, guest I/O, local ledger, stream supervision |
| RuntimeBackend | Trait for one isolation backend (Firecracker, QEMU, gVisor,...); only sandboxd holds implementations |
| Command envelope | HostRuntimeCommand fields: sandbox_id, operation_id, assignment_fencing_token, policy_epoch, absolute deadline, payload (ADR-0002) |
| Resource receipt | Durable proof a named host resource was created or released; ledger-backed for reconcile/cleanup |

## Process split (host-agent/sandboxd)

| Term | Meaning |
|------|---------|
| Sole runtime owner | Only sandboxd may hold RuntimeBackend handles and call prepare/boot/exec/suspend/resume/destroy on them |
| Observation cache | Host-agent in-memory mirror of sandboxd observations; never invents transitions; rehydrates after host-agent restart |
| Port target | Upstream SocketAddr (or backend-managed hint) published by sandboxd for a guest port; host port proxy resolves only via GetPortTarget |
| Watch + reconcile | Hybrid invalidation: sandboxd pushes observation diffs; host also periodic full reconcile; proxy fail-closed on unknown target |
| Guest session | Framed operational session to guest-agent; owned only by sandboxd (handshake, exec, files, secrets inject, quiesce, streams) |
| Destroy resume | A Destroy retried after a sandboxd restart finishes host cleanup from ledger receipts when durable evidence proves destroy intent (Destroying/Destroyed, or Failed when the ledger's latest operation is destroy); other states refuse teardown without a runtime handle |

## Access and network

| Term | Meaning |
|------|---------|
| Access lease | Bounded capability issued from policy (port forward, egress, credentials,...); enforced on compute plane |
| Port proxy | Host-agent component that binds host ports and TCP-proxies to port targets from sandboxd |
| network-agent | Library/helper for per-sandbox network mechanics (identity, TAP/veth, egress, NAT, DNS attach); sandboxd is the only caller of the provision pipeline |
| DNS attach | Per-sandbox DNS redirect/policy attachment; receipts and attach live with sandboxd |

## Intentional residual split

| Term | Meaning |
|------|---------|
| Ingress on host | Port proxy and lease validation remain on host-agent; not a RuntimeBackend. Destroy/reaper and guest path do not. See ADR-0011. |

## Ready and secrets

| Term | Meaning |
|------|---------|
| Running (observed) | sandboxd reports Running only after backend start, transport attach, and **fail-closed** guest handshake; host-agent never invents Running |
| Secrets inject path | Lease-checked credential material is written in-guest only via sandboxd-owned guest session; host does not hold GuestConnection |
| Secrets broker client | Outbound fetch of short-lived credentials; may run inside sandboxd until a dedicated helper exists; secrets never enter the ledger |

## Scale validation

| Term | Meaning |
|------|---------|
| LPOP | Launch proven operating point: measured rate/count/concurrency at which a profile meets SLOs plus class-A safety (ADR-0012) |
| Class-A/B/C | A blocks the launch stage; B is follow-up with a quota cap; C is an unproven architecture design-target gap |

## Related ADRs

- ADR-0001: control-plane lifecycle ownership
- ADR-0002: host-agent coordinates; sandboxd supervises
- ADR-0003: host/guest protocol contract
- ADR-0005: per-sandbox networking model
- ADR-0009: observability and reliability signals
- ADR-0011: sandboxd process boundary, sole runtime owner, ingress on host
- ADR-0012: production scale validation strategy
