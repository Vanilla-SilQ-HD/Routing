# Routing — selective routing for sing-box and AWG Manager

Auto-updated rule sets for **sing-box** and **AWG Manager**: blocked and unavailable-in-Russia resources go through VPN, everything else goes direct.

[Russian README](README.md) · [Latest release](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest) · [Routing Dashboard](https://vanilla-silq-hd.github.io/Routing/) · [Monitoring](https://vanilla-silq-hd.github.io/Routing/monitoring.html) · [Catalog](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/catalog.json)

## What it is

A build pipeline that merges 13 public blocklists and service-dependency lists into validated sing-box rule sets (SRS, source format v3). Everything is published through GitHub Releases with SHA-256 checksums, a semantic coverage diff and an interactive dashboard. No router access, no personal rules — just public data.

## Rule sets

| Set | Purpose | URL |
| --- | --- | --- |
| **Full domains** | Complete domain base for routing and DNS | `https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs` |
| **Compact domains** | Without the two largest registries, for low-RAM devices | `https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains-core.srs` |
| **Smart domains** | Compact + popular registrable domains from Full (Tranco top-1M) | `https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains-smart.srs` |
| **App networks** | Verified Telegram networks | `https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-services-ip.srs` |
| **Exact IPs** | Public `/32` and `/128` only, never merged into subnets | `https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-registry-ip.srs` |
| **Wide CIDR (optional)** | Broader ranges with a warning | `https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-registry-ip-cidr.srs` |
| **Direct exceptions** | Priority rules that must bypass VPN | `https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/routing-direct-exceptions.srs` |

Backup URLs on GitHub Pages use the same file names under `https://vanilla-silq-hd.github.io/Routing/`.

## Quick start (AWG Manager)

Requires **sing-box 1.14+** and an existing VPN outbound.

1. Add each set as a **Remote** rule set, **Binary** format, **6h** update interval. Use `direct` download detour when GitHub is reachable, otherwise your VPN.
2. Route `routing` (or `routing-core` / `routing-smart`), `routing-services` and `routing-registry-ip` to your VPN outbound.
3. Add `routing-direct-exceptions` with the **Direct** action **above** the VPN rule.
4. Keep the default (final) route **Direct**.

Ready-made presets are in `presets.user.json` and the AWG Manager Catalog; they only add VPN sets, so the Direct-exception rule must still be added separately with higher priority.

## Profiles: which one to choose

- **Full** — maximum coverage; large (about 10 MB SRS, hundreds of MB RSS on weak routers).
- **Compact** — drops the two largest registries; much lighter.
- **Smart** — Compact plus every popular registrable domain from Full (via the Tranco top-1M list). Compact is always a strict subset of Smart, so Smart never demotes a Compact VPN decision to Direct.

## How it is verified

- Ruff, strict mypy, Bandit, CodeQL; Python 3.11–3.14 matrix.
- JSON Schema for every config and every build artifact.
- Unit and integration tests with branch coverage ≥ 75%, including an offline end-to-end build.
- Mandatory VPN/Direct probes, compile/decompile roundtrip of every SRS, `sing-box check`.
- Semantic diff that distinguishes minimization from real coverage loss.
- SHA-256 and re-download of every release asset; draft-then-publish with rollback.

Updates run four times a day. Conditional downloads (ETag/Last-Modified) and a persisted source cache keep the builds fast and gentle on upstreams. A large coverage growth is staged as a reviewable candidate pre-release instead of replacing Latest.

## License

- **Code** — [MIT](LICENSE).
- **Data sets** — [CC0](LICENSE-DATA). Upstream sources keep their own licenses (see the table in the [Russian README](README.md#лицензии)).
