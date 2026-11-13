# Security Policy

Notary runs close to network infrastructure, so we take security reports seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| `main` branch | Yes (best effort) |
| Older releases | No, please upgrade |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for security problems.**

Report privately through GitHub Security Advisories:

1. Go to [https://github.com/LLCForge/Notary/security/advisories/new](https://github.com/LLCForge/Notary/security/advisories/new).
2. Describe the issue, affected version or commit, and steps to reproduce.
3. Include a proof of concept if you have one. Strip any real customer data, IP addresses or credentials from captures and logs.

What to expect:

- Acknowledgement within **3 business days**.
- An initial assessment and severity rating within **10 business days**.
- A fix or mitigation plan, coordinated disclosure date, and credit in the advisory (unless you prefer to stay anonymous).

## In scope

- Incorrect validation results (a route reported `Valid` that RFC 6811 says is `Invalid`, or a wrong ASPA verdict).
- Remote crash or memory exhaustion through crafted RTR PDUs (including ASPA), JSON exports, SLURM files, or responses from RIPEstat, Pathology, bgp.tools, the RIPE DB or whois servers.
- TLS certificate or SSH host key verification bypass on `tls://` / `ssh://` RTR transports.
- Query API exposure beyond its read-only contract: bearer-token bypass on `/v1/*`, the batch endpoint, history or ASPA queries, or the admin routes (`/v1/silences`, `POST /v1/reload`).
- Script injection or data exfiltration through the embedded web UI.
- Secrets (tokens, passwords, SSH passphrases, webhook URLs) leaking into logs, metrics or API responses.
- Dependency vulnerabilities that are reachable from Notary's code paths.

## Out of scope

- Vulnerabilities in third-party services or protocols themselves (report those upstream).
- Issues that require an attacker to already control the host or the config file.
- Denial of service by volumetric flooding of the network the tool runs on.

## Hardening recommendations

- Run as an unprivileged user; grant only the capabilities the tool needs.
- Bind management and API listeners to localhost or a management network.
- Keep secrets in environment variables or your secret manager, never in the config file or in version control.
- Use `tls://` or `ssh://` for RTR across any network you do not fully control; plain TCP RTR is unauthenticated. Always set `ssh_host_key` from a fingerprint you verified out of band.
- Set `[api] token_env` when the API is reachable by anyone but you. The API has no per-connection header timeout; put a reverse proxy in front if it must face untrusted clients.
- Set separate, long (>= 16 bytes) tokens for `[silences] api_token_env` and `[health] admin_token_env`; they allow muting alerts and reloading the configuration.
- The data directory holds the alert queue (alert contents), silences and VRP history; keep it readable only by the service account (the shipped systemd unit, Windows installer and container already do).

## Attack surface added in 0.2

| Surface | Mitigation |
|---|---|
| `POST /v1/validity` batch | 4 MiB body cap, `max_batch` routes (default 10000), per-entry errors, optional bearer token |
| `/v1/history`, `/v1/aspa` | Bounded parameters (prefix 64 bytes, path 4096 bytes, limit <= 1000), file reads off the async runtime, optional bearer token |
| Web UI (`/`, `/ui/*`) | Static files compiled into the binary, CSP `script-src 'self'`, no inline script, `textContent` only, `frame-ancestors 'none'` |
| RTR over TLS / SSH | rustls with verified server certificates; SSH host key pinned, RSA disabled (RUSTSEC-2023-0071), credentials from env |
| RTR v2 ASPA PDUs | Strict length and provider-list validation, 64 KiB PDU cap |
| Outbound calls (Pathology, bgp.tools, RIPE DB, whois) | Fixed hosts or configured URLs only, response size caps, timeouts, never on the alert path |
