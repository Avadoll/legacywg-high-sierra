package session

import (
	"context"
	"net/netip"

	networkcore "legacywg/NetworkCore"
)

// Both installed unscoped monitoring and private guarded scoped admission use
// NetworkCore's single process-wide RTM_GET allocator. Independent counters in
// this process can match another query's broadcast PID/sequence reply.
func nativeEndpointPath(ctx context.Context, address netip.Addr) (endpointPath, error) {
	path, err := networkcore.EndpointRoute(ctx, address)
	if err != nil {
		return endpointPath{}, err
	}
	// Preserve the existing comparable identity and optional-source semantics.
	// Scoped prefix/route-class observations do not change split monitoring.
	return endpointPath{
		InterfaceIndex: path.InterfaceIndex,
		InterfaceName:  path.InterfaceName,
		Gateway:        path.Gateway,
		GatewayZone:    path.GatewayZone,
		Direct:         path.Direct,
		Source:         path.Source,
		SourceZone:     path.SourceZone,
	}, nil
}
