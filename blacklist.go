package botdetect

import (
	"context"
	"net"
	"sync"
	"time"

	sll "github.com/emirpasic/gods/lists/singlylinkedlist"
	"github.com/emirpasic/gods/maps/hashmap"
)

// Blacklist contains all blacklisted IP addresses as key
type Blacklist struct {
	ttl            time.Duration
	expireInterval time.Duration
	data           *hashmap.Map
	expiry         *sll.List

	dataMutex   sync.RWMutex
	expiryMutex sync.RWMutex

	ctx context.Context
}

type blacklistIP struct {
	IP      string
	Expires time.Time
}

// NewBlacklist creates a new Blacklist
func NewBlacklist(ctx context.Context, ttl, expireInterval time.Duration) *Blacklist {
	bl := Blacklist{
		ctx:            ctx,
		ttl:            ttl,
		expireInterval: expireInterval,
		data:           hashmap.New(),
		expiry:         sll.New(),
		dataMutex:      sync.RWMutex{},
		expiryMutex:    sync.RWMutex{},
	}

	go bl.expireLoop()

	return &bl
}

// Set adds an IP to the blacklist if it doesn't already exist
func (bl *Blacklist) Set(ip net.IP) {
	ipstr := ip.To16().String()

	bl.dataMutex.RLock()
	_, ok := bl.data.Get(ipstr)
	bl.dataMutex.RUnlock()
	if ok {
		return
	}

	bl.dataMutex.Lock()
	bl.data.Put(ipstr, true)
	bl.dataMutex.Unlock()

	bl.expiryMutex.Lock()
	bl.expiry.Add(blacklistIP{
		IP:      ipstr,
		Expires: time.Now().Add(bl.ttl),
	})
	bl.expiryMutex.Unlock()
}

func (bl *Blacklist) Size() int {
	bl.dataMutex.RLock()
	defer bl.dataMutex.RUnlock()
	return bl.data.Size()
}

// IsBlacklisted determines whether a given IP is on the blacklist
func (bl *Blacklist) IsBlacklisted(ip net.IP) bool {
	bl.dataMutex.Lock()
	defer bl.dataMutex.Unlock()

	_, exists := bl.data.Get(ip.To16().String())
	return exists
}

func (bl *Blacklist) expireLoop() {
	for {
		select {
		case <-bl.ctx.Done():
			return
		case <-time.After(bl.expireInterval):
			bl.expire()
		}
	}
}

func (bl *Blacklist) expire() {
	now := time.Now()

	for {
		bl.expiryMutex.RLock()
		item, ok := bl.expiry.Get(0)
		bl.expiryMutex.RUnlock()

		if !ok {
			break
		}

		blip := item.(blacklistIP)
		if blip.Expires.Before(now) {
			// remove IP from expiry
			bl.expiryMutex.Lock()
			bl.expiry.Remove(0)
			bl.expiryMutex.Unlock()

			// remove IP from data
			bl.dataMutex.Lock()
			bl.data.Remove(blip.IP)
			bl.dataMutex.Unlock()
		} else {
			break
		}
	}
}
