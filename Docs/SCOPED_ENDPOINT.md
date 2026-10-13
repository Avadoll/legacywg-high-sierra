# Scoped endpoint socket candidate

Research checkpoint 13 October 2026. Product still uses the unmodified official default Bind and rejects full tunnels. This experiment is a candidate for the endpoint escape layer, not an implemented product feature.

High Sierra-era Apple source handles socket interface binding for [IPv4 IP_BOUND_IF](https://github.com/apple-oss-distributions/xnu/blob/xnu-4570.71.2/bsd/netinet/ip_output.c) and [IPv6 IPV6_BOUND_IF](https://github.com/apple-oss-distributions/xnu/blob/xnu-4570.71.2/bsd/netinet6/ip6_output.c). This establishes an implementation reference; it is not a target runtime or API maintenance guarantee. The pinned WireGuard public `conn.Bind` interface permits transport implementations, but its default Darwin transport exposes neither the socket descriptors nor an interface binding method. No reflection, linkname, FD enumeration, vendor modification, own cryptography or replacement engine was introduced.

## Actual kernel experiment

[Run 38455001863](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38455001863), source `2b98b1cff3e1ae2334e567cec5c58d3860ccfb68`, disposable Intel `macos-15-intel` runner, pinned Go1.24.13/Xcode16.4: native cross-build/vet and actual root kernel experiment PASS.

Separate developer executable `Engine/scopedfixture` creates two owned utun interfaces and uses the pinned official netstack as a UDP echo server behind the first interface. Wildcard native UDP listeners match the default transport's local binding behavior. The bound listener applies and reads back the family-specific socket option. A test prefix has both an unscoped route and an explicit route in the first interface's scope. A more-specific host route on the second interface then competes with it. These are synthetic benchmark routes on owned virtual interfaces; no physical/default route or PF setting is changed.

Both families separately proved:

- Ordinary and bound baseline UDP round trips.
- A fresh ordinary listener loses its round trip and packets reach the second interface. The conflicting host route is confirmed selected by the ordinary kernel query.
- Four bound round trips still traverse the first interface; the second interface receives zero bound packets during that measured phase.
- Closing the first interface stops bound traffic without packets falling back to the second interface.
- Closing the second interface restores the original gateway/interface result for the synthetic destination. Final native interface name/index set matches the baseline.

Reports are sanitized and source/artifact hashes verified in `Evidence/ScopedEndpoint/38455001863`. Raw packet data, route tables and interface identities are not published. This is plaintext UDP routing evidence, not encrypted WireGuard or physical Wi-Fi/Ethernet proof.

## Failed experiments retained

Run38454068254/source43d5b2fbab49bf3608282de3da23e8de06cea7cb failed because the intended more-specific conflict was not confirmed selected; it supplies no conflict/bound/loss guarantee. The subsequent fixture configured a source address on the second interface and switched both listeners to wildcard binding. Do not describe the initial interface as down: the successful later run measured newly created decoy interfaces already UP.

Run38454481637/sourcebf7b9e02921f495b6de6e32577f9aee5bff5d65a confirmed the wildcard baseline and ordinary negative control, then the bound round trip failed under the conflict without an explicit scoped prefix route. Its original reason text says "captured", but that branch only observed a missing reply; it did not export the bound phase packet counter and cannot prove where bound traffic went. The successful run added an explicit scoped prefix route, preserving the failed evidence rather than treating socket binding alone as sufficient.

## Remaining decision and proof

The encrypted prototype below supplies one-peer traffic and a bounded close/reopen proof for each family separately. It does not justify switching the product transport yet. Remaining transport work includes source/interface lifetime checks, scoped kernel path queries, simultaneous dual-stack/multi-peer/hostname/roaming/cancel behavior and measurable transport/resource performance. There is still no proof for physical gateways, existing scoped defaults, physical interface replacement/index reuse, sleep/DHCP, roaming, packet capture or High Sierra.

If the physical interface already has a usable scoped route, socket lifetime might avoid creating a persistent endpoint host route. If it does not, the product must refuse before mutation or implement and prove owned durable physical route recovery. The surrogate test explicitly adds its scoped prefix and does not establish that every physical interface has one.

PF protection, all-traffic DNS/IPv6 leak prevention, protected GUI/helper/engine crash lifetime and durable ownership remain required. Full profiles stay rejected, `protection_ready=false`, research pkg remains unsigned. No new client artifact or release approval was produced by this experiment.

## Encrypted official-device prototype

[Run 38456456242](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38456456242), exact source `640ad7331ded5f610903eec8fc7d2a70b8893a7d`, pinned Go1.24.13 on Intel macos-15-intel: native build/vet and experiment PASS. The dedicated report does not export an OS patch version. Evidence and verified source/artifact hashes are in `Evidence/ScopedEndpoint/38456456242`.

The separate fixture implements the exported `conn.Bind` contract with a thin packet adapter. Official device, crypto, endpoint and netstack sources remain unmodified. The client uses a wildcard native UDP socket with the family-specific interface binding option; the peer lives in the official netstack behind an owned kernel utun. Two official encrypted devices and an inner UDP echo are exercised for IPv4 and IPv6 separately. Ephemeral keys are generated locally, core dumps disabled, UAPI never exported and loggers silent.

Each family completed six encrypted round trips: one baseline, four with a competing host route on the second owned interface, one after actual official Device.Down/Up reopened the bound transport. Both devices reported nonzero authenticated handshake timestamp and RX/TX counters. Zero packets for the endpoint reached the second interface during the encrypted phase. A separate callback lease check confirmed the old receive function remains closed after a new socket opens. Closing the first interface prevented further plain and encrypted round trips with zero fallback packets on the second interface. Synthetic destination gateway/interface and the native interface name/index set returned to baseline.

This still requires an explicit synthetic scoped prefix. It is one-peer sequential-family virtual-topology evidence. It does not prove physical Wi-Fi/Ethernet, a usable existing physical scoped route, simultaneous dual-stack, multi-peer/hostname/roaming, interface index reuse, scoped BSD query/lifetime enforcement, DHCP/sleep, transport process crash, resource/performance or High Sierra. The adapter is developer-only, excluded from app/pkg. Product transport is unchanged, `protection_ready=false`; no new client artifact was generated.
