# Airgap Update Delivery — Design Document

> **Status:** Approved (rev 2, 2026-07-28).  Design-gate round 1 complete; all
> findings folded in (see [Design-gate round 1 summary](#design-gate-round-1-summary)).
>
> **Scope:** Design only.  Per-phase implementation plans are separate artifacts.

---

## 1. Executive summary

Greentic's update platform is live and connected-only: DSSE-signed update plans
on `updates.greentic.cloud`, verified against per-environment local
`trust-root.json`, applied via the staging FSM and `env_apply`, with binary
self-update.  Enterprise and defense customers need updates in **airgapped**
environments where no outbound network exists.

This document describes how the same staging FSM and trust model extend to
airgapped delivery.  The design adds an **export/import** pipeline that packages
a signed plan and its referenced artifacts into a self-contained `.gtupdate`
archive, transfers it across the gap on removable media, and feeds it into the
existing staging state machine.  Airgapped and connected paths **converge** on
the same FSM from the `Inbox` stage onward — there is no airgap fork of the
client protocol.

Key properties: deterministic (no autonomous agents), transport-independent
(no hard dependency on any server inside the gap), signed end-to-end (one
vendor signature, never re-signed in the gap), fail-closed on missing or
tampered data, and incrementally deployable across four phases (A-D), each
independently shippable.

---

## 2. Problem statement

Connected update delivery requires outbound HTTPS to the plan server and to
artifact registries (OCI, direct HTTPS).  Airgapped environments — common in
defense, critical infrastructure, and regulated enterprise — have no outbound
network.  The update platform must support these environments without
duplicating the trust model, the staging state machine, or the apply path.

Specific gaps today:

1. `src/envelope.rs` is a Phase 5 stub (lines 1-9): the module doc specifies
   the exact design but the implementation is empty.
2. The artifact fetcher in `greentic-deployer` hard-errors on `source=None`
   (`greentic-deployer/src/cli/updates.rs:1763`); the runtime binary
   self-update in `greentic-start` skips `source=None` binaries
   (`greentic-start/src/revision_serve.rs:2071-2082`).
3. No export/import CLI verbs, no in-gap serving story, no offline/insecure-
   registry CLI surface, and no key-rotation object for crossing the gap.

---

## 3. Industry landscape

| System | Mechanism | What Greentic borrows |
|--------|-----------|----------------------|
| **Replicated** | `.airgap` bundle uploaded to on-prem admin console; console pushes to local registry. License-gated exports. | Self-contained signed archive format; import-to-local-serving pattern. Greentic does NOT adopt license-gated exports (trust is key-based; see [Risks R-License](#risks-and-open-questions)). |
| **Zarf / Hauler** | Declarative package (`ZarfPackage`) with embedded OCI images + Helm charts + manifests; `zarf package deploy` into the gap. Hauler adds content-addressed stores. | Content-addressed blob layout; single-archive-to-deploy path; declarative manifest. |
| **TUF (The Update Framework)** | Offline transfer of signed metadata; delegated trust with threshold signatures; expiry-based freshness. | Offline trust anchors; threshold-based key rotation; advisory staleness (not hard expiry by default — TUF's mandatory expiry would brick long-offline envs). Greentic's trust model is simpler (flat key list with roles, not TUF's full delegation tree). |

---

## 4. Design principles

1. **One signature, end-to-end.**  The vendor signs the plan once.  It is never
   re-signed inside the gap.  Source overrides (mirrors, `blob_base_url`) are
   client config, not signed content — the TUF principle that mirrors are
   untrusted transport.

2. **Converge, don't fork.**  Airgapped and connected paths share the staging
   FSM from `Inbox` onward.  The apply path (`materialize_bundles`,
   `env_apply`) is identical.

3. **Fail closed.**  Missing blobs, bad signatures, tampered digests, and
   malformed archives are hard errors.  A partial import never leaves a
   half-staged plan.

4. **Transport-independent.**  The trust anchor is the local `trust-root.json`,
   not a network service.  `did:web` has no airgap role.  Anti-rollback is
   client-side monotonic sequence (`ensure_not_downgrade`,
   `src/plan.rs:419`).

5. **Deny by default.**  No `update-channel.json` means no phoning home
   (`greentic-start/src/revision_serve.rs:1655-1734`).  Updates config cannot
   ride inside a signed plan.

6. **Deterministic.**  No autonomous agents, no ambient authority.  The
   operator runs explicit export/import/apply verbs.

---

## 5. Architecture overview

### Connected path (today)

```
plan-server ──GET plan+sig──► op updates get ──► staging FSM
                                                    │
artifacts ──HTTPS/OCI fetch──► put_artifact ────────┘
                                                    │
                                              ┌─────▼─────┐
                                              │Downloading │
                                              └─────┬──────┘
                                                    ▼
                                              ┌───────────┐
                                              │   Inbox    │
                                              └─────┬──────┘
                                                    ▼
                                              ┌───────────┐
                                              │  Staged    │
                                              └─────┬──────┘
                                                    ▼
                                              ┌───────────┐
                                              │ Applying   │
                                              └─────┬──────┘
                                                    ▼
                                              ┌───────────┐
                                              │  Applied   │
                                              └───────────┘
```

### Airgapped path (this design)

```
                    CONNECTED SIDE                    │ GAP │        AIRGAPPED SIDE
                                                      │     │
op updates export ──► .gtupdate archive               │     │
  (plan+sig+blobs,    (tar+zstd, signed manifest)     │     │
   content-addressed) ─────── removable media ────────┼─────┼──► op updates import
                                                      │     │       │
                                                      │     │       ▼
                                                      │     │   scan_envelope
                                                      │     │   (verify sigs,
                                                      │     │    quarantine,
                                                      │     │    digest checks)
                                                      │     │       │
                                                      │     │       ▼
                                                      │     │   staging FSM ◄── SAME FSM
                                                      │     │   (Inbox → Staged
                                                      │     │    → Applying → Applied)
```

Both paths converge at the staging FSM.  The apply path
(`greentic-deployer/src/cli/updates.rs:831` `materialize_bundles` at line 1636)
rewrites bundle references to content-addressed staged blobs — it does not
care whether those blobs arrived over the network or from an envelope import.

---

## 6. `.gtupdate` format specification

### Container

**tar + zstd** (streamable, multi-GB-capable).  Extension: `.gtupdate`.

### Entry grammar

Fixed entry order.  Scanner rejects violations before authentication completes
(the scanner is a DoS surface — metadata parses before authentication).

```
manifest.json                          # REQUIRED, FIRST entry
manifest.json.sig                      # REQUIRED (DSSE sidecar)
plan.json                              # REQUIRED
plan.json.sig                          # REQUIRED (DSSE sidecar)
blobs/sha256-<64hex>/blob              # 0..N content-addressed artifact blobs
trust-rotation.json                    # OPTIONAL (Phase D)
trust-rotation.json.sig               # OPTIONAL (Phase D, DSSE sidecar)
```

**Strict rules** (violations are hard errors):
- `manifest.json` MUST be the first tar entry.
- Only the paths listed above are permitted (exact allowlist).
- Regular files only — no symlinks, hardlinks, sparse files, device nodes,
  FIFOs, or directories-as-entries.
- No duplicate paths.
- Bounded: max entry count (10,000), max per-entry size (4 GiB), max total
  expanded bytes (64 GiB), max manifest size (1 MiB), max compression ratio
  (100:1).
- Extraction into a quarantine directory; atomic commit to the staging tree
  only after full verification.
- Disk-space reservation checked before extraction begins.

**Test battery** (Phase A ship criteria): decompression bomb, duplicate-entry,
hardlink, sparse, special-file, oversized-manifest, path-traversal, symlink,
bad-manifest-sig, bad-plan-sig, tampered-blob, manifest-not-first,
unknown-path, oversized-total, too-many-entries.

### Manifest schema

Schema identifier: `greentic.update-envelope.v1`.

```json
{
  "schema": "greentic.update-envelope.v1",
  "plan_id": "<plan-id>",
  "env_id": "<environment-id>",
  "created_at": "<RFC 3339>",
  "entries": [
    {
      "path": "blobs/sha256-<hex>/blob",
      "digest": "sha256:<hex>",
      "size": 12345678,
      "media_type": "application/vnd.greentic.bundle",
      "target": null
    },
    {
      "path": "blobs/sha256-<hex>/blob",
      "digest": "sha256:<hex>",
      "size": 98765,
      "media_type": "application/vnd.greentic.binary",
      "target": "x86_64-unknown-linux-gnu"
    }
  ]
}
```

Signed as a DSSE envelope (`manifest.json.sig`) using the same `sign_statement`
path as `build_update_plan`.

### Binary payload representation

Blobs carry the **raw inner executable**, content-addressed by the existing
`BinaryArtifact.digest` field (`src/plan.rs:121-124`), which hashes the inner
binary.  Release archives (the tar.gz/zip files that `source` URLs point at)
are **never** carried in-band.

Manifest entries carry `media_type` (distinguishing bundles from binaries) and
an optional `target` triple.  Consumers (binswap, import) take the executable
directly, skipping the archive-unpack path.

This resolves the representation ambiguity identified in design-gate finding 2:
the digest in the plan matches the blob in the envelope without any
intermediate unpacking step.

---

## 7. Tension resolutions

### T1. Signed source URLs

Keep ONE vendor-signed plan end-to-end — never re-sign in the gap.

**Primary (Tier 1):** in-band envelope artifacts with `source=None` for both
bundles and binaries.  The export tool filters binary target triples via
`--targets`.

**Secondary (Tier 2):** client-side source overrides (`blob_base_url` /
registry mirror in `update-channel.json`).  Mirrors are client config, not
signed content (TUF principle).  Digest pinning keeps it safe.

### T2. Envelope format

Plain tar+zstd (see [format specification](#6-gtupdate-format-specification)).
Content-addressed blobs deduplicate; import is idempotent, so a full export
is always a safe fallback.

### T3. Delta exports are inventory-based, not sequence-based

Staged blobs live under `<env>/<plan_id>/artifacts` and `apply_retention`
evicts terminal plan directories (`src/staging.rs:797-836`), so "applied
sequence N" proves nothing about blob possession.

Resolution: import maintains a durable content-addressed **import CAS**
(refcounted, retention-independent) and writes a signed **import receipt**
(env, root version, held digests).  Export takes `--base-receipt <file>`
(carried back out of the gap) or `--base-envelope <digest>` instead of
`--since-sequence`.

Import preflight resolves EVERY digest the plan references (envelope + local
CAS) BEFORE admission and fails closed listing missing digests — a delta can
never verify yet be unapplyable.

### T4. Deployment tiers

See [Deployment tiers](#10-deployment-tiers).

### T5. Trust across the gap

See [Trust model](#8-trust-model).

### T6. Freshness

See [Freshness and anti-rollback](#9-freshness-and-anti-rollback).

### T7. Auto-apply safety

Import stages to `Inbox`, not `Staged`.  An `on_update: apply` runtime must
not auto-apply mid-import.  The `--stage` flag is an opt-in promotion.

### T8. Scope boundaries

- **In scope:** bootstrap media (first install into the gap) — same envelope
  format, special case (see [Bootstrap media](#12-bootstrap-media)).
- **Out of scope:** license/entitlement-gated exports (Replicated-style).
  Trust is key-based, not license-based.  Documented as a product decision,
  not a security gap.

---

## 8. Trust model

### Existing trust infrastructure (reused as-is)

- Trust anchor is the LOCAL `trust-root.json` — fail-closed when missing.
  `did:web` is NOT resolved on the client update path.
- `op trust-root bootstrap|add|list|remove` is fully offline from PEM files.
- Plan verification is 1-of-N over one flat key list
  (`greentic-distributor-client/src/signing.rs:258-322`): iterate all
  signatures, verify against trusted keys, accept if at least one matches.

### Key roles (new, Phase D)

The flat key list gains **key roles**:

| Role | Purpose | Who holds it |
|------|---------|--------------|
| `update` | Signs update plans. Day-to-day CI/CD automation. | Build infrastructure |
| `rotation` | Signs trust-rotation objects. Offline ceremony keys. | Key custodians (multi-holder) |

Rotation objects MUST NOT be signable by everyday `update` keys.  A single
compromised update key must not be able to rewrite the trust root.

### Rotation-key threshold from first release

There is no "single-signer first" phase.  The rotation threshold is
established from the very first release of the `greentic.trust-rotation.v1`
schema.  This prevents a window where a single key compromise could
bootstrap a rogue root.

### Two-phase verify-then-atomic-commit

When an envelope carries a `trust-rotation.json`:

1. **Verify the entire envelope under the OLD trust root** — the rotation
   object's DSSE signature must verify against rotation-role keys in the
   current root.
2. **Verify the plan under the CANDIDATE root** — the new root produced by
   applying the rotation.
3. **Atomic commit:** root change + plan admission together.  A quarantined
   blob can never leave a half-rotated trust root behind.

### Monotonic root_version + journal

Each trust root carries a monotonic `root_version`.  A recovery journal
records each rotation step, enabling rollback diagnosis without rollback
(the system never automatically reverts a rotation — diagnosis is manual).

---

## 9. Freshness and anti-rollback

### Anti-rollback (existing, reused)

Client-side monotonic `sequence` enforced by `ensure_not_downgrade`
(`src/plan.rs:414-429`).  Re-applying an already-applied plan (equal
sequence) is refused.  This survives imports naturally — the sequence
travels inside the signed plan.

### Freshness (new)

- **Advisory staleness warning** by default: `plan.created_at` age exceeds a
  configurable threshold (default 30 days).  Import logs a warning but
  proceeds.
- **Never hard expiry by default.**  Hard expiry would brick long-offline
  environments — the defining characteristic of airgapped deployments.
- **Optional hard-reject mode** for customers who want it (Phase D):
  `--staleness-reject` or a per-env config flag.

---

## 10. Deployment tiers

### Tier 1 — Sneakernet (Phases A + B)

```
op updates export ──► .gtupdate ──► removable media ──► op updates import
                                                              │
                                                              ▼
                                                         staging FSM
                                                              │
                                                              ▼
                                                        op updates apply
```

No server required inside the gap.  The operator runs explicit CLI verbs.
Binary self-update is consumed from staged in-band blobs via binswap.

### Tier 2 — In-gap serving (Phase C)

Import tool additionally pushes to in-gap serving infrastructure:

- **Static content-addressed directory** served by any HTTP server (nginx,
  caddy — layout documented):
  ```
  plan/plan.json
  plan/plan.json.sig
  plan/meta
  blobs/sha256-<hex>
  ```
- Monotonic enforcement in the import tool (never overwrites a newer plan).
- **`blob_base_url`** + insecure-registries CLI surface in deploy-spec /
  deployer for client-side mirror configuration.
- **greentic-start blob-mirror fallback** for plan/binary fetch.

Content updates need no client changes.  **Binary self-update requires
`greentic-start` at or above the Phase C version** — today's runtimes skip
`source=None` binaries (`greentic-start/src/revision_serve.rs:2071-2082`)
and have no blob-mirror config.  A one-time out-of-band fleet upgrade is
required to enroll (same precedent as the `_`-broadcast bootstrap).

Optional turnkey `greentic-plan-server` (public crate, file-backed, SSE) is
a later Phase C deliverable.  It does NOT depend on the private in-memory
`greentic-updates-server`.

---

## 11. Client-protocol invariant

**There is no airgap fork of the client protocol.**

The staging FSM, the apply path, the trust verification, and the anti-rollback
checks are identical for connected and airgapped delivery.  The only difference
is how blobs arrive at the staging tree:

| Path | Blob source | Entry point |
|------|-------------|-------------|
| Connected | HTTPS / OCI fetch | `op updates get` |
| Airgap Tier 1 | `.gtupdate` envelope | `op updates import` |
| Airgap Tier 2 | In-gap HTTP mirror | `op updates get` (with `blob_base_url`) |

From `Inbox` onward, the paths are indistinguishable.

---

## 12. Bootstrap media

First install into the gap uses the same `.gtupdate` envelope format with a
special case: the envelope carries the **bootstrap trust root** (the initial
`trust-root.json`) in addition to the plan and artifacts.

Bootstrap flow:
1. Operator generates bootstrap media on the connected side:
   `op updates export --bootstrap --env-id <new-env>`.
2. Media is carried into the gap.
3. `op trust-root bootstrap --from-envelope <file>` extracts and installs the
   trust root (offline, from PEM — existing CLI).
4. `op updates import <file>` proceeds as normal.

Bootstrap is a one-time operation per environment.  After the initial trust
root is installed, subsequent imports use the normal envelope flow.

---

## 13. Phased roadmap

Each phase is independently shippable.  Cross-phase dependencies are explicit.

### Phase A — Envelope library + `op updates export`

**Repos:** `greentic-update`, `greentic-deployer`.

- Implement `src/envelope.rs`: `EnvelopeBuilder`, `scan_envelope_to_dir`,
  `ScanLimits`, strict archive grammar enforcement.
- Binary-blob staging trio in `src/staging.rs` (mirroring the artifact trio at
  lines 906/920/951): `put_binary_blob`, `binary_blob_path`,
  `verify_binary_on_disk`.
- `op updates export` verb in `greentic-deployer`.
- Promote `assert_no_symlink_ancestors` (line 1142) and
  `read_regular_file_in` (line 1172) to `pub(crate)` for reuse by the
  envelope scanner.

**Ship criteria:** exported `.gtupdate` passes `scan_envelope()`; round-trip,
tamper, and traversal tests PLUS the full hostile-archive test battery.

### Phase B — `op updates import` (Tier 1 complete)

**Repos:** `greentic-update`, `greentic-deployer`, `greentic-start`.

- Durable import CAS (per-env, content-addressed, retention-independent).
- Signed import receipt (`greentic.import-receipt.v1`).
- Import preflight: resolve EVERY digest before admission, fail closed.
- `op updates import` verb: `scan_envelope_to_dir` (quarantine) ->
  `verify_update_plan` -> staleness advisory -> preflight ->
  CAS population -> staging FSM admission -> optional `--stage` promotion ->
  receipt generation.
- `ImportFetcher` accepts `source=None`; `DistArtifactFetcher` rejection
  (`greentic-deployer/src/cli/updates.rs:1763`) is UNCHANGED (regression-tested).
- `greentic-start` in-band binary consumption: extract swap+marker logic into
  a shared helper, `source=None` branch reads from staged binary blob via
  `verify_binary_on_disk`.
- `op updates cas-gc` (design risk R8): evict orphaned CAS blobs, rewrite
  import receipt after eviction.
- Receipt-based delta export.

**Ship criteria:** zero-network export -> USB -> import -> apply round-trip
including binary swap, restart, rollback, with all existing rollback
guarantees.

### Phase C — In-gap fleet serving (Tier 2)

**Repos:** `greentic-deployer`, `greentic-start`, `greentic-deploy-spec`.

- `op updates import --push-to` / static-dir writer.
- `blob_base_url` + insecure-registries fields on `UpdateChannelConfig`
  (additive via `#[non_exhaustive]` + flatten catch-all).
- `greentic-start` mirror fallback in poll loop + binary fetch.
- nginx/caddy serving layout documentation.
- Optional turnkey `greentic-plan-server` public crate (file-backed, SSE).

**Ship criteria:** fleet runtimes at or above Phase C version converge
(content AND binaries) from one import point; minimum client version
documented.

### Phase D — Trust rotation + hardening

**Repos:** `greentic-update`, `greentic-distributor-client`, `greentic-trust`.

- `greentic.trust-rotation.v1` schema (key roles, rotation threshold, two-phase
  verify-then-atomic-commit, `root_version` + journal) — complete from first
  release.
- Multi-holder ceremony tooling in `greentic-trust`.
- Envelope SBOM.
- Hard-reject staleness mode.
- Full E2E including rotation, quarantine-mid-rotation, and receipt-based
  re-import.

**Ship criteria:** key rotation ceremony end-to-end; quarantine-mid-rotation
recovery tested; hard-reject staleness mode functional.

---

## 14. Risks and open questions

### Risks

| ID | Risk | Mitigation |
|----|------|------------|
| R1 | Multi-GB envelopes vs removable media size limits | Receipt-based delta exports; full export always safe (idempotent import). |
| R2 | `source=None` paths untested in production | Audit every `artifact.source` consumer in Phase B; content-addressed staging makes blob origin invisible downstream. |
| R3 | Import receipt lost or never carried back out of the gap | Export falls back to full envelope; deltas are an optimization, never a correctness dependency. |
| R4 | Rotation ceremony practicality | Threshold-of-rotation-keys is required from day one (finding 1), so the offline multi-holder ceremony must be well-tooled; rotations are rare, and Phase D owns the ceremony UX. |
| R5 | Heterogeneous target triples in the gap | Default: all targets. `--targets` flag to slim the export. |
| R6 | Private `greentic-updates-server` must not become a dependency | Static files + new public crate only. |
| R7 | Fleet binary convergence needs `greentic-start` at or above Phase C version | One-time out-of-band upgrade to enroll; document the floor version (same shape as the `_`-broadcast bootstrap deadlock). |
| R8 | Durable import CAS adds disk pressure inside the gap | Refcount/GC rules + `op updates cas-gc` verb in Phase B scope. |
| R-License | License/entitlement-gated exports are out of scope | Trust is key-based, not license-based. This is a product decision, not a security gap. Replicated-style license gating can be layered on later without changing the envelope format. |

### Open questions

| ID | Question | Status |
|----|----------|--------|
| Q | `_` broadcast channel semantics in-gap: one shared plan directory vs per-environment directories? | **Resolved: per-environment.** The `_` broadcast channel on the connected side fans out to per-env staging directories. In-gap import targets a specific `--env-id`, so the per-env model is preserved. The import tool handles `_`-targeted plans by requiring the operator to specify the target env explicitly — broadcast semantics are a connected-side concern. |

---

## 15. Design-gate round 1 summary

Adversarial design-gate review conducted 2026-07-28 (Codex).  All 4 findings
CONFIRMED and folded into the design.

### Finding 1 (high): Single-signature rotation

**Problem:** Plan verification is 1-of-N over a flat key list
(`greentic-distributor-client/src/signing.rs:258-322`).  The original proposal
("rotation co-signed by current keys, applied before plan verify,
single-signer first") would let one compromised update key rewrite the root.

**Resolution:** Key roles (`update` vs `rotation`), rotation-key threshold
from first release, two-phase verify-then-atomic-commit, monotonic
`root_version` + journal.  See [Trust model](#8-trust-model).

### Finding 2 (high): Binary blob representation undefined

**Problem:** `BinaryArtifact.digest` hashes the inner executable
(`src/plan.rs:121-124`) while `source` points at an archive (tar.gz/zip).
Today's `greentic-start` skips `source=None`
(`greentic-start/src/revision_serve.rs:2071-2082`).

**Resolution:** Raw-executable blobs keyed by the existing digest.  Media
types in the manifest.  `greentic-start` modifications in Phases B/C.
Tier 2 minimum client version requirement.  See
[Binary payload representation](#binary-payload-representation).

### Finding 3 (medium): Sequence-based deltas unsound

**Problem:** Staged blobs are per-plan and retention-evicted
(`src/staging.rs:797-836`).  "Applied sequence N" proves nothing about
blob possession.

**Resolution:** Durable import CAS, signed import receipts as delta basis,
import preflight fails closed on missing digests.  See
[T3. Delta exports](#t3-delta-exports-are-inventory-based-not-sequence-based).

### Finding 4 (medium): Scanner DoS surface

**Problem:** No archive-grammar or resource bounds were specified in the
original proposal.

**Resolution:** Strict grammar + bounds + quarantine extraction +
hostile-archive test battery in Phase A ship criteria.  See
[Entry grammar](#entry-grammar).

---

## Appendix A: Wire contracts

### A.1 Envelope manifest — `greentic.update-envelope.v1`

```json
{
  "schema": "greentic.update-envelope.v1",
  "plan_id": "string",
  "env_id": "string",
  "created_at": "RFC 3339 timestamp",
  "entries": [
    {
      "path": "string (tar entry path)",
      "digest": "sha256:<hex>",
      "size": "integer (bytes)",
      "media_type": "string (IANA media type or vnd.*)",
      "target": "string | null (Rust target triple, for binaries)"
    }
  ]
}
```

DSSE-signed as `manifest.json.sig`.  Verified on import before any blob
extraction.

### A.2 Import receipt — `greentic.import-receipt.v1`

```json
{
  "schema": "greentic.import-receipt.v1",
  "env_id": "string",
  "root_version": "integer (monotonic trust-root version)",
  "created_at": "RFC 3339 timestamp",
  "held_digests": ["sha256:<hex>", "..."],
  "last_plan_id": "string",
  "last_sequence": "integer"
}
```

DSSE-signed by the import operator's signing key.  Carried back out of the
gap to enable delta exports (`op updates export --base-receipt <file>`).

The receipt reflects actual CAS holdings.  `op updates cas-gc` rewrites the
receipt after eviction to keep it truthful.

### A.3 Trust rotation — `greentic.trust-rotation.v1`

```json
{
  "schema": "greentic.trust-rotation.v1",
  "root_version": "integer (must be current + 1)",
  "supersedes_root_version": "integer (must equal current)",
  "changes": {
    "add": [
      {
        "key_id": "string",
        "public_key_pem": "string",
        "role": "update | rotation"
      }
    ],
    "remove": ["key_id", "..."]
  },
  "rationale": "string (human-readable reason)"
}
```

DSSE-signed by a **threshold of rotation-role keys** from the current trust
root.  Carried inside the `.gtupdate` envelope as `trust-rotation.json` +
`trust-rotation.json.sig`.  Applied via two-phase verify-then-atomic-commit
(see [Trust model](#8-trust-model)).

### A.4 Plan-server routes (existing, unchanged)

The plan-server wire contract is small and unchanged by this design:

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/v1/environments/<env>/plan` | Anonymous | Fetch current plan |
| `GET` | `/v1/environments/<env>/plan.sig` | Anonymous | Fetch plan signature |
| `GET` | `/v1/environments/<env>/plan/meta` | Anonymous | Fetch plan metadata |
| `GET` | `/v1/environments` | Anonymous | List environments |
| `POST` | `/v1/environments/<env>/plan` | Authenticated | Publish plan (monotonic 409 on downgrade) |
| `GET` | `/v1/environments/<env>/events` | Anonymous | SSE stream (optional) |

In-gap Tier 2 serving uses the same routes.  The static-dir layout maps
directly to these paths.  The optional turnkey `greentic-plan-server` binary
(Phase C) implements the same contract as the production CF Worker and the
private in-memory Rust server.

---

## Appendix B: Code references

All citations verified against `develop` branch as of 2026-07-28.

| Claim | Location | Line(s) |
|-------|----------|---------|
| Envelope stub | `greentic-update/src/envelope.rs` | 1-9 |
| `pub mod envelope` | `greentic-update/src/lib.rs` | 28 |
| `BinaryArtifact.digest` doc | `greentic-update/src/plan.rs` | 121-124 |
| `BinaryArtifact.source` is `Option<String>` | `greentic-update/src/plan.rs` | 125-128 |
| `ensure_not_downgrade` | `greentic-update/src/plan.rs` | 419 |
| `apply_retention` evicts terminal plan dirs | `greentic-update/src/staging.rs` | 797-836 |
| Artifact blob path (content-addressed) | `greentic-update/src/staging.rs` | 906 |
| `verify_artifact_on_disk` | `greentic-update/src/staging.rs` | 920 |
| `put_artifact` | `greentic-update/src/staging.rs` | 951 |
| `assert_no_symlink_ancestors` | `greentic-update/src/staging.rs` | 1142 |
| `read_regular_file_in` | `greentic-update/src/staging.rs` | 1172 |
| `DistArtifactFetcher` rejects `source=None` | `greentic-deployer/src/cli/updates.rs` | 1763 |
| `materialize_bundles` rewrites to staged blobs | `greentic-deployer/src/cli/updates.rs` | 1636 |
| greentic-start skips `source=None` binaries | `greentic-start/src/revision_serve.rs` | 2071-2082 |
| 1-of-N `verify_envelope` | `greentic-distributor-client/src/signing.rs` | 258-322 |
| Deny-by-default: no update-channel = no poll | `greentic-start/src/revision_serve.rs` | 1655-1734 |
