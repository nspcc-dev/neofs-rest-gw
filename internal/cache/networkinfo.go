package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
)

type (
	// NetworkInfo is cache wrapper for the network info.
	NetworkInfo struct {
		p   *pool.Pool
		ttl time.Duration

		mu         *sync.Mutex
		validUntil time.Time
		ni         netmap.NetworkInfo
	}
)

func NewNetworkInfoCache(p *pool.Pool) *NetworkInfo {
	return &NetworkInfo{
		p:  p,
		mu: &sync.Mutex{},
	}
}

func (n *NetworkInfo) NetworkInfo(ctx context.Context) (netmap.NetworkInfo, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.validUntil.After(time.Now()) {
		return n.ni, nil
	}

	ni, err := n.p.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil {
		return netmap.NetworkInfo{}, fmt.Errorf("get network info: %w", err)
	}

	n.update(ni)

	return ni, nil
}

func (n *NetworkInfo) update(ni netmap.NetworkInfo) {
	n.ttl = time.Duration(int64(ni.EpochDuration())/2*ni.MsPerBlock()) * time.Millisecond
	n.validUntil = time.Now().Add(n.ttl)
	n.ni = ni
}

func (n *NetworkInfo) StoreNetworkInfo(ni netmap.NetworkInfo) {
	n.mu.Lock()
	n.update(ni)
	n.mu.Unlock()
}
