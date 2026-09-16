# ADH (Android DecryptHub) — Threat Model & Use Policy

> Scope of use, access control, and sensitive-data handling for the workbench.

## Authorized use only

ADH is a **general-purpose Android runtime reverse-analysis** tool intended for
**authorized reverse investigation** — analyzing apps you own or are authorized to
examine (e.g., investigating evasive gray-market apps). It is **not** for:

- legal evidence/forensics (no chain-of-custody guarantees — this is investigation tooling);
- circumventing protections on apps you are not authorized to analyze;
- redistribution of extracted/unpacked copyrighted apps.

The anti-analysis **neutralization** capability (e.g., suppressing `ptrace(PTRACE_TRACEME)`)
is a survival/observation aid for authorized analysis of hostile targets — it is off by
default per-op and is not a general evasion product.

## Trust boundaries

- **Agent ↔ adhd**: NDJSON over TCP `127.0.0.1:8761`, reached from the device via
  `adb reverse` (USB). Not exposed on the network by default.
- **adhd HTTP/WS/MCP**: binds `0.0.0.0:8088` so phones and other PCs on a **trusted LAN**
  can share one Host (same port as iOS `idh`). **Do not expose adhd to an untrusted network.**
  It can dump target memory, read files, and hook APIs — treat it as privileged.

## Recommended hardening (deployment)

- Keep the Host on a trusted LAN (or USB `adb reverse`); do not port-forward to the public internet.
- If the LAN is not fully trusted: add a bearer token (env gate) + IP allowlist before enabling.
- Dangerous operations (full-memory dump, instruction trace, cross-app reads) should be
  gated behind explicit confirmation in any multi-user deployment.

## Sensitive data handling

- **Captures** (crypto/TLS plaintext, keys) live in-memory in the agent (bounded buffers)
  and are returned only on explicit tool/endpoint calls.
- **Dumps** are written under `captures/` (git-ignored) — never commit target data.
- **Diagnostic export** (`GET /api/export/report`) is **metadata only** (agent identity,
  dump hashes/sizes, capability inventory). It never includes captured key/plaintext content.
- The Web console shows captured plaintext only on the Capture tab, on demand.

## Residual risks / limitations (honest)

- GOT/PLT hooks miss **direct syscalls** (mitigation: `svc` scan surfaces these sites) and
  statically-linked/stripped crypto (mitigation: constant-signature scan + inline-hook target).
- Method-body recovery is **passive** (dump the decrypted in-memory dex); per-method
  controlled-trigger recovery is a device-side follow-up.
- No hard guarantee of defeating all commercial packers/anti-debug; the compat probe
  reports what is usable so the operator can choose a minimal-footprint configuration.
