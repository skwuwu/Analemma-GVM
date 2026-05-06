# External Security Audit — Preparation

> Snapshot for an external auditor. Last updated 2026-05-06.
>
> Companion to [security-model.md](../security-model.md) (public) and
> [GVM_CODE_STANDARDS.md](GVM_CODE_STANDARDS.md) (internal). This doc
> is the auditor-facing scope, threat-model summary, and known-gap
> inventory — designed to bootstrap a 1–2 week engagement without
> the auditor having to reconstruct the system from source.

---

## 1. Scope

### In scope (must be reviewed)

| Area | Surface | Files |
|------|---------|-------|
| HTTP request handling | proxy_handler step 0 → SRR → enforcement → upstream forward | `src/proxy/mod.rs`, `src/proxy/headers.rs`, `src/proxy/connect.rs` |
| TLS MITM (HTTPS interception) | per-sandbox CA, hyper handler, body buffering | `src/tls_proxy_hyper.rs`, `src/tls_proxy.rs`, `crates/gvm-sandbox/src/ca.rs` |
| Identity & authentication | JWT issuance/verification, sandbox-peer fallback | `src/auth.rs`, `src/proxy/mod.rs::resolve_identity_from_peer`, `src/api.rs::auth_token` |
| WAL & audit chain | event hashing, Merkle batching, integrity context, anchor signing | `src/ledger.rs`, `crates/gvm-types/src/lib.rs` |
| Credential injection | header strip + managed key injection | `src/proxy/headers.rs::inject_credentials` |
| Sandbox isolation | namespace + seccomp + veth + TC filter | `crates/gvm-sandbox/src/{namespace,network,seccomp,tc_filter,heartbeat}.rs` |
| Vault encryption | AES-256-GCM, key zeroize | `src/vault.rs` |
| Hot-reload | SRR rule reloading, config integrity context chain | `src/api.rs::reload_srr`, `src/integrity_context.rs` |
| DNS governance | tier-based delay/alert | `src/dns_governance.rs` |
| Token budget | per-agent + per-org sliding window | `src/token_budget.rs` |
| IC-3 approval flow | hold-and-release, approver isolation | `src/proxy/mod.rs::ApprovalGuard` + admin port |

### Explicitly out of scope

- The Wasm runtime (`--features wasm`) — opt-in, not part of v1 default surface.
- The `--contained` Docker mode — marked EXPERIMENTAL in user docs;
  in-container DNAT/CA-injection is documented as not-yet-wired.
- Any agent-side SDK code outside this repo.
- The optional Anthropic/OpenAI client SDK code paths.
- Docs themselves (markdown only — no executable claims).

### What "auditing" means here

- Find vulnerabilities in the request-handling, authentication, and
  audit chain code paths.
- Verify that documented security properties (fail-close, secret
  hygiene, JWT identity mandatory in production) are enforced by
  code, not just by convention.
- Identify gaps between what `docs/security-model.md` claims and what
  the code does.
- Look for cases where a malicious agent inside a sandbox can bypass
  the proxy, escalate privileges, exfiltrate data, or evade the audit
  chain.

---

## 2. Threat model

### Adversary

The primary adversary is **a compromised or malicious AI agent running
inside a GVM sandbox**, with the ability to:

- Make arbitrary HTTP/HTTPS requests via any client library
- Read its own environment (env vars, including `GVM_JWT_TOKEN`)
- Modify its own filesystem (within the sandbox overlay)
- Spawn subprocesses (within seccomp policy)
- Read/write its agent-id-scoped vault entries

The adversary CANNOT (by sandbox guarantee):

- Break out of the network namespace (would require kernel exploit)
- Read another agent's vault entries
- Write to the proxy's WAL directly
- Forge an HMAC-signed JWT without `GVM_JWT_SECRET`
- Spoof its source IP at the veth level

### Trust boundaries

```
   ┌────────────────────────────────────────────────────────────┐
   │ Operator host (root)                                       │
   │  ┌─────────────┐    ┌─────────────────────┐               │
   │  │ gvm-proxy   │◄──►│ /var/lib/gvm/wal.log│  (durable     │
   │  │ (uid=gvm)   │    │ + anchor signing key│   audit)      │
   │  └────┬────────┘    └─────────────────────┘               │
   │       │ veth-host:8080                                    │
   │  ┌────▼─────────────────────────────────────────┐         │
   │  │ Sandbox NS  (uid=agent, no-new-privileges)   │         │
   │  │  ┌────────────┐                              │         │
   │  │  │ Agent code │  ← TRUST BOUNDARY            │         │
   │  │  └────────────┘                              │         │
   │  └──────────────────────────────────────────────┘         │
   └────────────────────────────────────────────────────────────┘
```

### Top-priority attack scenarios for the auditor

1. **Audit-chain tamper**: agent or insider modifies WAL after the
   fact such that `gvm audit verify` still reports a valid chain.
2. **Identity spoof**: agent A causes an event to be attributed to
   agent B (cross-agent contamination, audit-trail false-flag).
3. **Sandbox escape**: agent breaks out of namespace/seccomp jail.
4. **Credential exfiltration**: agent observes managed credentials
   that the proxy is supposed to inject opaquely.
5. **Egress bypass**: agent reaches an external host without going
   through the proxy (DNS-tunnel, hardcoded IP, raw socket).
6. **DoS the proxy**: agent crashes/wedges the proxy and forces
   fail-open behavior.
7. **Race against config reload**: agent slips a request through
   during the window between rule edit and rule activation.

---

## 3. Crypto inventory

| Use | Algorithm | Library | Reviewed |
|-----|-----------|---------|----------|
| JWT signing | HMAC-SHA256 | `hmac`, `sha2` | ✅ alg:none, RS256 confusion, future iat all rejected with tests |
| Vault sealing | AES-256-GCM (12-byte random nonce) | `aes-gcm` | ✅ tampered/truncated ciphertext, nonce uniqueness tested |
| Audit-chain hashing | SHA-256 with domain-separation prefix | `sha2` | ✅ prefix per leaf type prevents collision across leaf classes |
| Anchor signing | Ed25519 (optional via `[anchor] enabled = true`) | `ed25519-dalek` | ✅ wired into `Ledger::with_config_and_signer`; fail-close on missing/malformed key file; `tests/anchor_signing.rs` covers round-trip verify; not yet load-tested at scale |
| Sandbox CA | ECDSA P-256, RAM-only, 8h TTL | `rcgen` | ✅ per-sandbox isolation tested |
| Random | `OsRng` everywhere | `rand_core` | — |

Key handling:
- All long-lived keys are wiped via `zeroize::ZeroizeOnDrop` on drop.
- `GVM_SECRETS_KEY` is read once at startup, held in `JwtSecret`
  with `zeroize` impl, never logged, never serialized.
- Anchor signing key, when `[anchor] enabled = true`, lives at the
  operator-chosen `key_path` (production template recommends
  `/etc/gvm/anchor.key`, mode 0600, owned by the proxy uid). The
  matching public key is at `<key_path>.pub` (mode 0644). Both
  files are produced atomically by `gvm anchor keygen --out
  <path> --key-id <label>`, which embeds `key_id` in both files
  so a verifier can map signature → public key without out-of-band
  metadata. Loss of the secret forces rotation to a new `key_id`
  (existing signed anchors stay verifiable; new anchors require
  the auditor to add the new public key to their registry).

---

## 4. Known limitations & accepted residual risk

These are documented in `docs/security-model.md` and are NOT bugs —
they are explicit accepted risks that the audit should evaluate but
not treat as findings.

| ID | Limitation | Status | Rationale |
|----|-----------|--------|-----------|
| L1 | GraphQL alias bypass | Documented | Body-level operationName matching only; URL-level Deny rules are the recommended defense for high-value GraphQL endpoints. |
| L2 | Body-level credential injection | Out of scope | Proxy injects at HTTP header layer; GraphQL variables / form data are not rewritten. SRR rules govern these flows. |
| L3 | Low-and-slow exfil (1KB × 1000) | Documented | WAL records every event; post-hoc forensic detection via `gvm audit list`. Real-time cumulative-volume tracking is roadmap. |
| L4 | LLM SDK key handling | Out of scope | LLM SDKs need the key at client construction. Use env var `ANTHROPIC_API_KEY`; proxy governs subsequent tool-API calls. |
| L5 | Token issuance endpoint unauth | Single-host scope | `POST /gvm/auth/token` is loopback-only; co-located with proxy. Network-exposed deployments must front with mTLS gateway. |
| L6 | Wasm runtime | `--features wasm` | Opt-in only; v1 production runs without it. |
| L7 | `--contained` Docker mode | Cargo feature `contained` (default OFF) | CLI surface gated as of `84ace18`. The default `cargo build` produces a binary without `--contained`; `cargo build --features contained` opts in. |

---

## 5. Recently fixed (v0.5.0 → present)

For each: brief description, root cause, fix commit, test that pins
the fix.

| Fix | Commit | Test |
|-----|--------|------|
| Anchor signing wired up — runtime had a `SelfSignedSigner` impl + `with_config_and_signer` constructor but `main.rs` never called it, so production anchors landed unsigned. Added `[anchor]` config section, `gvm anchor keygen` CLI, fail-close on missing/malformed key file, AUDIT_PREP/proxy.production docs aligned with reality. | (this commit) | `crates/gvm-cli/src/anchor.rs` 4 unit tests (keygen round-trip, refuse-clobber, key_id validation); `tests/anchor_signing.rs` covers signer round-trip |
| NATS / Redis ghost integrations advertised in `proxy.toml` but the runtime only emitted a "NATS publish (stub)" debug line — never connected. Removed the config sections, struct fields, and event field; external streaming is now explicitly operator-managed (tail the WAL with rsync/fluentd/etc.) | `f3d274c` | All 800 workspace tests; backward-compat for legacy proxy.toml verified by `proxy_config_load_from_file` |
| Concurrent veth slot allocation race — every `gvm run --sandbox` started its own atomic counter at zero, causing concurrent launches to all pick slot 0; 19/20 sandboxes silently lost network. | `fc6f7c3` | `scripts/multi-agent-load.sh --agents 20` (verified on EC2 — 0 missed transport events) |
| `--contained` advertised in default CLI surface despite documented EXPERIMENTAL status | `84ace18` | `cargo build` produces binary that bails on `--contained` with a clear error; `cargo build --features contained` opts in |
| MITM JWT bypass — HTTPS path skipped JWT verification | `ba47501` | `tests/multi_agent_isolation.rs::mitm_path_enforces_jwt` |
| Sandbox-peer identity for SDK-less agents | `3ec17bd` | `tests/api_handlers.rs::resolve_identity_from_peer_*` (3 cases) |
| Test 76 secrets.toml duplicate-key accumulation | `c03878a` | `scripts/ec2-e2e-test.sh` Test 76 idempotency assertion |
| Plateau-aware memory regression check | `7ae1582` | `scripts/stress-test.sh` plateau assertion |
| Replay determinism (no Utc::now() fallback) | `6b3958c` | `crates/gvm-cli/src/replay.rs::EventClass::MissingTimestamp` |
| 12 cleanup gaps from prior audit (heartbeat, ip_forward, proxy.log rotation, EmergencyWAL cap, iptables substring, …) | `9fb036a` | `tests/cleanup_*.rs` (suite) |

---

## 6. What we'd most like the auditor to look at

Highest-value review targets, in priority order:

1. **`src/ledger.rs::Ledger::append_durable` and the group commit
   batch path.** This is where every audit guarantee is realized.
   Look for: race between event append and shutdown, race between
   batch close and config reload, off-by-one in Merkle leaf
   ordering, fsync ordering relative to durability claim.

2. **`src/proxy/mod.rs::proxy_handler` step 0.** The new sandbox-peer
   identity fallback (commit `3ec17bd`). Review the soundness
   argument: is `peer_ip → sandbox_id → agent_id` truly no weaker
   than namespace isolation? Are there edge cases (IPv4-mapped IPv6,
   loopback aliasing, cgroup-net escape) we missed?

3. **`crates/gvm-sandbox/src/network.rs::lookup_sandbox_id_by_ip`.**
   This trusted lookup is now part of the identity trust path.
   Verify the on-disk state file format cannot be forged by the
   sandbox itself (file is on tmpfs at `/run/gvm/`, owned root, but
   confirm).

4. **`src/auth.rs::decode_jwt`.** Manual JWT parser (vs. a library).
   Review for alg-confusion, base64 edge cases, signature
   constant-time comparison.

5. **`src/intent_store.rs` (Shadow Mode strict).** Intent declaration
   → request match. The TTL window and the matching predicate are
   the surface area for replay-style attacks.

6. **The `--sandbox` cleanup state machine** (`crates/gvm-sandbox/src/network.rs::cleanup_state_resources` + the parent-mount overlay pattern). Compare claimed cleanup invariants in CLAUDE.md to the actual code paths under SIGKILL of each PID in the chain (parent `gvm`, sandbox-init child, agent grandchild).

---

## 7. How to run the test suite

```bash
# Clean unit + integration tests (all platforms)
cargo test --workspace --all-targets

# Linux-only stress / sandbox suite (requires sudo + tmux)
sudo bash scripts/ec2-e2e-test.sh
sudo bash scripts/stress-test.sh
sudo bash scripts/multi-agent-load.sh --agents 5 --requests 30

# Fuzz (auditor option, time-boxed)
cargo +nightly fuzz run fuzz_srr  -- -max_total_time=300
cargo +nightly fuzz run fuzz_jwt_auth -- -max_total_time=300
cargo +nightly fuzz run fuzz_wal_parse -- -max_total_time=300
```

WAL chain verification (offline, on a copied WAL):
```bash
gvm audit verify --wal /path/to/wal.log
```
Should report 0 hash mismatches and a valid integrity chain back to genesis.

---

## 8. Reporting findings

We accept findings via:
- GitHub Security Advisory (preferred)
- Encrypted email to the security contact (separate channel; we'll
  share the GPG key with the auditor)

Severity scale: CVSS v3.1.

For each finding we ask for: reproducer, affected version range,
attacker preconditions, and a suggested mitigation. We will respond
with: triage class (true positive / accepted risk / out of scope),
fix ETA, and a backport plan if applicable.

---

## 9. Pre-engagement checklist (auditor-facing)

When the engagement starts, the auditor receives:

- [ ] Read access to this repo
- [ ] A pre-built `gvm-proxy` + `gvm` binary (release profile)
  for the target platform
- [ ] A populated WAL from a 1-hour load run (for offline analysis)
- [ ] A clean Linux test box with sudo (for live testing)
- [ ] This document and `docs/security-model.md`
- [ ] `docs/internal/CHANGELOG.md` for full history
- [ ] Threat-model walkthrough call (60 min) before they start
