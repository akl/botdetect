package botdetect

import (
	"context"
	"math/rand"
	"net"
	"testing"
	"time"
)

func TestBlacklist(t *testing.T) {
	b := NewBlacklist(context.Background(), 50*time.Millisecond, 10*time.Millisecond)

	ipbytes := make([]byte, 4)
	rand.Read(ipbytes)
	ip := net.IP(ipbytes)

	b.Set(ip)
	if !b.IsBlacklisted(ip) {
		t.Errorf("IP %s should be blacklisted", ip)
	}

	time.Sleep(150 * time.Millisecond)
	if b.IsBlacklisted(ip) {
		t.Errorf("IP %s should not be blacklisted after it has expired", ip)
	}
}
