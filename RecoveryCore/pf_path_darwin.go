package recoverycore

import (
	"context"
	"sync/atomic"
	"time"

	networkcore "legacywg/NetworkCore"
)

type pfScopedEndpoint struct {
	escape pfUDPEscape
	route  networkcore.ScopedPath
}

// The snapshot is a bounded observation, not a route ownership/incarnation
// token. Interface-bound sockets and exact PF tuples remain necessary during
// the observation gap. Numeric roaming requires a fresh explicit admission.
type pfScopedAdmission struct {
	paths  []pfScopedEndpoint
	lost   atomic.Bool
	loss   chan struct{}
	done   chan struct{}
	cancel context.CancelFunc
	err    error // Published by closing done; never exported as network metadata.
}

// Capture before installing tunnel/default routes. The existing route is
// borrowed: this controller never adds, changes or deletes physical routes.
// Installed protected sessions must use this admission layer, not the lower
// level socket/PF primitive newPFGuardBind used by isolated lifecycle tests.
func newPFScopedGuardBind(ctx context.Context, store *Store, template pfPolicy) (*pfGuardBind, error) {
	policy, err := template.frozen()
	if err != nil || ctx == nil || ctx.Err() != nil || len(policy.escapes) == 0 {
		return nil, ErrRecoveryRequired
	}
	check, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	admission := &pfScopedAdmission{loss: make(chan struct{}), done: make(chan struct{})}
	for _, escape := range policy.escapes {
		// Scoped socket addresses with zones are not implemented. A link-local
		// route gateway/IFA may still be valid; the shared decoder checks its zone.
		if escape.source.IsLinkLocalUnicast() || escape.endpoint.Addr().IsLinkLocalUnicast() ||
			(policy.tunnel != nil && escape.path == *policy.tunnel) || validatePFDatagramSource(escape.path, escape.source) != nil {
			return nil, ErrRecoveryRequired
		}
		before, err := networkcore.EndpointRoute(check, escape.endpoint.Addr())
		if err != nil || before.InterfaceName != escape.path.name || before.InterfaceIndex != escape.path.index {
			return nil, ErrRecoveryRequired
		}
		scoped, err := networkcore.ScopedRoute(check, escape.endpoint.Addr(), escape.path.index)
		if err != nil || scoped.Path != before || validatePFDatagramSource(escape.path, scoped.Source) != nil || check.Err() != nil {
			return nil, ErrRecoveryRequired
		}
		// RTAX_IFA is the address associated with the route, not necessarily
		// the source of an explicitly bound UDP socket (notably for IPv6).
		admission.paths = append(admission.paths, pfScopedEndpoint{escape, scoped})
	}
	bind, err := newPFGuardBind(ctx, store, policy)
	if err != nil {
		return nil, err
	}
	bind.scoped = admission
	monitor, cancel := context.WithCancel(context.Background())
	admission.cancel = cancel
	go admission.observe(monitor, bind)
	return bind, nil
}

func (admission *pfScopedAdmission) verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || admission.lost.Load() {
		return ErrRecoveryRequired
	}
	for _, path := range admission.paths {
		if validatePFDatagramSource(path.escape.path, path.escape.source) != nil {
			return ErrRecoveryRequired
		}
		after, err := networkcore.ScopedRoute(ctx, path.escape.endpoint.Addr(), path.escape.path.index)
		if err != nil || after != path.route || validatePFDatagramSource(path.escape.path, after.Source) != nil || ctx.Err() != nil {
			return ErrRecoveryRequired
		}
	}
	if admission.lost.Load() || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	return nil
}

func (admission *pfScopedAdmission) refuse(bind *pfGuardBind) {
	if !admission.lost.Swap(true) {
		close(admission.loss)
	}
	// Do not wait for the PF operation mutex before stopping packet callbacks.
	// Open also checks the loss latch after its effectful update, before publish.
	if lease := bind.current.Load(); lease != nil {
		_ = lease.retire()
	}
}

func (admission *pfScopedAdmission) observe(ctx context.Context, bind *pfGuardBind) {
	defer close(admission.done)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-admission.loss:
			admission.err = bind.Close()
			return
		case <-ticker.C:
			check, stop := context.WithTimeout(ctx, 2*time.Second)
			err := admission.verify(check)
			stop()
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				admission.refuse(bind)
				admission.err = bind.Close()
				return
			}
		}
	}
}

func (admission *pfScopedAdmission) stop() error {
	admission.cancel()
	select {
	case <-admission.done:
		return nil
	case <-time.After(3 * time.Second):
		return ErrRecoveryRequired
	}
}

func (bind *pfGuardBind) verifyScoped(ctx context.Context) error {
	if bind.scoped == nil {
		return nil
	}
	check, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if bind.scoped.verify(check) != nil {
		bind.scoped.refuse(bind)
		return ErrRecoveryRequired
	}
	return nil
}
