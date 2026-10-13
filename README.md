# LegacyWG experimental client

Research AppKit client for Intel macOS 10.13.6. The full product is not ready. Current native CI has verified IPv4/IPv6 split tunnels, simultaneous dual stack, routed OS DNS over UDP/TCP, authenticated Mach helper, Keychain, crash cleanup and a fresh unsigned research package on Intel macOS 15.7.9.

Hostname bootstrap is added for a new native check. It uses the existing system resolver before tunnel changes, a five-second total deadline and typed route overlap checks. Validation performs no lookup. It selects one address, prefers IPv4 and supports IPv6-only answers; protected reconnect and automatic fallback are not implemented.

Full tunnel, kill switch, durable recovery journal, sleep/network reconnect, GUI uninstall/update, High Sierra runtime and Developer ID distribution remain unfinished. Ad-hoc components and unsigned research pkg are not a trusted end-user installer. Do not disable Gatekeeper, SIP or quarantine.

Run the manually dispatched free standard macOS feasibility workflow. Official unmodified WireGuard/toolchains are pinned with SHA256 in deps.lock.json; third-party licenses are retained. Candidate commit is unsigned; the older upstream baseline tag signature was verified against the key linked on the maintainer site. The project is independent of official WireGuard. Own-code license remains undecided.

[Current scope](Docs/READINESS.md), [verified native evidence](Docs/CLIENT_RESEARCH.md), [hostname limits](Docs/ENDPOINT_RESOLUTION.md).

Only reviewed source files are published. Private specification, original Git history, local tools/caches and user configuration/keys are excluded.
