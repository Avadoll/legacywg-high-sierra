// Developer-only simultaneous-family transport. Official engine unchanged.
package main

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

type dualPacketBind struct {
	mutex    sync.Mutex
	bindings [2]*packetBind
	opened   bool
	opens    atomic.Int64
}

var _ conn.Bind = (*dualPacketBind)(nil)

func (bind *dualPacketBind) refused() bool {
	return bind.bindings[0].refused.Load() || bind.bindings[1].refused.Load()
}
func (bind *dualPacketBind) BatchSize() int            { return 1 }
func (bind *dualPacketBind) SetMark(mark uint32) error { return bind.bindings[0].SetMark(mark) }
func (bind *dualPacketBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	return bind.bindings[0].ParseEndpoint(text)
}
func (bind *dualPacketBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.refused() {
		return nil, 0, errors.New("experimental dual transport lifetime ended")
	}
	if bind.opened {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	four, actual, err := bind.bindings[0].Open(port)
	if err != nil {
		return nil, 0, err
	}
	six, same, err := bind.bindings[1].Open(actual)
	if err != nil || same != actual || bind.refused() {
		bind.bindings[0].Close()
		bind.bindings[1].Close()
		return nil, 0, errors.New("experimental dual-family opening refused")
	}
	bind.opened = true
	bind.opens.Add(1)
	return append(four, six...), actual, nil
}
func (bind *dualPacketBind) Close() error {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	bind.opened = false
	return errors.Join(bind.bindings[0].Close(), bind.bindings[1].Close())
}
func (bind *dualPacketBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	if bind.refused() {
		return net.ErrClosed
	}
	remote, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	address := remote.AddrPort.Addr()
	if !address.IsValid() || address.Is4In6() || address.Zone() != "" {
		return errors.New("experimental dual endpoint refused")
	}
	index := 0
	if address.Is6() {
		index = 1
	}
	return bind.bindings[index].Send(buffers, endpoint)
}

func dualLeaseProof(factories [2]func(uint16) (net.PacketConn, error)) error {
	bind := &dualPacketBind{bindings: [2]*packetBind{{factory: factories[0]}, {factory: factories[1]}}}
	defer bind.Close()
	old, port, err := bind.Open(0)
	if err != nil || len(old) != 2 || port == 0 {
		return errors.New("dual lease baseline failed")
	}
	if bind.Close() != nil {
		return errors.New("dual lease close failed")
	}
	closed := func() bool {
		for _, receive := range old {
			_, err := receive([][]byte{make([]byte, 65535)}, make([]int, 1), make([]conn.Endpoint, 1))
			if !errors.Is(err, net.ErrClosed) {
				return false
			}
		}
		return true
	}
	if !closed() {
		return errors.New("dual old callback did not close")
	}
	if _, _, err = bind.Open(0); err != nil {
		return err
	}
	if !closed() {
		return errors.New("dual old callback revived")
	}
	if bind.Close() != nil {
		return errors.New("dual second close failed")
	}
	// An actual first-family native socket must close when the second family
	// refuses to open; no receive callback/port is exposed to the engine.
	var first net.PacketConn
	broken := &dualPacketBind{bindings: [2]*packetBind{
		{factory: func(port uint16) (net.PacketConn, error) {
			var err error
			first, err = factories[0](port)
			return first, err
		}},
		{factory: func(uint16) (net.PacketConn, error) { return nil, errors.New("intentional second-family refusal") }},
	}}
	defer broken.Close()
	fns, actual, err := broken.Open(0)
	if err == nil || len(fns) != 0 || actual != 0 || first == nil || broken.opened || broken.opens.Load() != 0 {
		return errors.New("dual partial open was exposed")
	}
	_, _, err = first.ReadFrom(make([]byte, 1))
	if !errors.Is(err, net.ErrClosed) {
		return errors.New("dual partial socket was not closed")
	}
	return nil
}
