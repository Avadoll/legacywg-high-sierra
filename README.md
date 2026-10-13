# LegacyWG experimental client

Research AppKit client for Intel macOS 10.13.6. The full product is not ready. Current native CI has verified IPv4/IPv6 split tunnels, simultaneous dual stack, routed OS DNS over UDP/TCP, authenticated Mach helper, Keychain, crash cleanup and a fresh unsigned research package on Intel macOS 15.7.9.

Native checks have verified bounded hostname bootstrap/encrypted localhost, independently encrypted peers and statistics, menu bar/live window launch/close, Keychain label rename and sanitized diagnostic preview/export. Hostname bootstrap uses the existing system resolver before tunnel changes with a five-second total deadline; validation performs no lookup. One address is selected, IPv4 preferred, IPv6-only answers supported. Protected reconnect and automatic fallback are not implemented.

The worker captures initial endpoint paths using kernel RTM_GET and closes a split session when its path changes or cannot be checked. This bounded monitor is not traffic protection, persistent route ownership. A root-only utun/DNS journal now records intent/interface/configuration, refuses unsafe ACL/identity/corrupt records and passed five controlled SIGKILL checkpoints on modern CI. It cannot undo physical routes/PF; see RECOVERY_JOURNAL.md. Current proof and limits are recorded in NETWORK_CHANGE.md.

Full tunnel, kill switch, physical route/PF journal and GUI/startup recovery, sleep/network reconnect, GUI uninstall/update, High Sierra runtime and Developer ID distribution remain unfinished. Ad-hoc components and unsigned research pkg are not a trusted end-user installer. Do not disable Gatekeeper, SIP or quarantine.

Run the manually dispatched free standard macOS feasibility workflow. Official unmodified WireGuard/toolchains are pinned with SHA256 in deps.lock.json; third-party licenses are retained. Candidate commit is unsigned; the older upstream baseline tag signature was verified against the key linked on the maintainer site. The project is independent of official WireGuard. Own-code license remains undecided.

[Current scope](Docs/READINESS.md), [verified native evidence](Docs/CLIENT_RESEARCH.md), [hostname limits](Docs/ENDPOINT_RESOLUTION.md).

Only reviewed source files are published. Private specification, original Git history, local tools/caches and user configuration/keys are excluded.
