# Security boundaries

ADH is intended for authorized reverse investigation. Its runtime hooks and dump tools can read sensitive data from the target process. Operators are responsible for choosing targets they are permitted to analyze and for protecting the resulting data.

## Network exposure

The Host ADH Daemon currently binds HTTP/WebSocket/MCP on `0.0.0.0:8088` and the agent TCP listener on `0.0.0.0:8761`. Neither listener has authentication. Run ADH on a trusted, isolated network or restrict the listeners with a host firewall. Do not publish either port to the internet. The Android agent normally reaches the host through `adb reverse`.

## Captured data

Crypto/TLS events may include keys, plaintext, and identifiers. Memory and DEX dumps may contain copyrighted or personal information. Keep `captures/`, `dumps/`, and `adhd-data/` private; they are excluded from Git by default. Never attach target captures to public issues or pull requests.

## Capability limits

- No guarantee of full visibility across every ROM, packer, or custom algorithm.
- Crypto-to-TLS correlation is currently a same-thread, time-window clue rather than content proof.
- High-rate capture can drop events; completeness and loss counters must be checked.
- ART structural resolution is validated mainly on SDK 35/36 and the agent ships for `arm64-v8a` only.
- This workbench does not implement legal evidence chain-of-custody controls.

For security reports, use a private GitHub vulnerability report if the repository has that feature enabled. Do not put secrets or target data in a public issue.
