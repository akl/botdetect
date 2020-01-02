/*
  botdetect, a program that detects bad bots by the HTML/asset ratio per IP over a given time frame
	Copyright (C) 2019 Tobias von Dewitz

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package botdetect

import (
	"container/list"
	"context"
	"net"
	"regexp"
	"sync"
	"time"
)

// IPHistory counts requests per IP for a given time window
type IPHistory struct {
	options          *IPHistoryOptions
	data             map[string]*list.List
	blacklist        *Blacklist
	reqChan          chan *Request
	ctx              context.Context
	mutex            sync.RWMutex
	tsmutex          sync.RWMutex
	blmutex          sync.RWMutex
	currentSlot      time.Time
	currentTimestamp string
	assetRegexp      *regexp.Regexp
	updatedIPs       map[string]bool
	updatedIPsMutex  sync.RWMutex
}

// IPHistoryItem contains the request count for a given period of time denoted by Timestamp
type IPHistoryItem struct {
	Timestamp time.Time
	Count     uint64
	App       uint64
	Other     uint64
}

// IPHistoryOptions configures the behaviour of History
type IPHistoryOptions struct {
	TimestampFormat string
	TimeSlot        time.Duration
	Window          time.Duration
	Interval        time.Duration
	ExpireInterval  time.Duration
	BlacklistTTL    time.Duration
	MaxRequests     uint64
	MaxRatio        float64
}

// Request contains information the history needs about an HTTP request
type Request struct {
	URL string
	IP  net.IP
}

// NewIPHistory creates a new History item
func NewIPHistory(ctx context.Context, options *IPHistoryOptions) *IPHistory {
	h := &IPHistory{
		options:         options,
		data:            make(map[string]*list.List),
		updatedIPs:      make(map[string]bool),
		blacklist:       NewBlacklist(ctx, options.BlacklistTTL, options.ExpireInterval),
		reqChan:         make(chan *Request),
		ctx:             ctx,
		mutex:           sync.RWMutex{},
		tsmutex:         sync.RWMutex{},
		blmutex:         sync.RWMutex{},
		updatedIPsMutex: sync.RWMutex{},
		assetRegexp:     regexp.MustCompile(`\.(jpg|png|css|js|gif|ico)`),
	}

	go h.setTimestamp(h.options.TimeSlot)
	go h.process()
	go h.calculate(h.options.Interval)
	go h.expire(h.options.ExpireInterval)

	return h
}

// RequestChannel returns the channel through which IPs are fed to the history
func (h *IPHistory) RequestChannel() chan *Request {
	return h.reqChan
}

func (h *IPHistory) setTimestamp(slot time.Duration) {
	h.tsmutex.Lock()
	h.currentSlot = time.Now().Truncate(slot)
	h.currentTimestamp = h.currentSlot.Format(h.options.TimestampFormat)
	h.tsmutex.Unlock()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(h.currentSlot.Add(h.options.TimeSlot).Sub(h.currentSlot)):
			h.tsmutex.Lock()
			h.currentSlot = time.Now().Truncate(slot)
			h.currentTimestamp = h.currentSlot.Format(h.options.TimestampFormat)
			h.tsmutex.Unlock()
		}

	}
}

// NumIPs returns the number of IPs in the history
func (h *IPHistory) NumIPs() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	return len(h.data)
}

// Size returns the number of items in all IP lists
func (h *IPHistory) Size() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	c := 0

	for _, l := range h.data {
		c += l.Len()
	}

	return c
}

// NumBL returns the number of blacklisted IPs
func (h *IPHistory) NumBL() int {
	return h.blacklist.Size()
}

// IsBlacklisted determines whether a given IP address is on the blacklist
func (h *IPHistory) IsBlacklisted(ip net.IP) bool {
	h.blmutex.RLock()
	defer h.blmutex.RUnlock()

	return h.blacklist.IsBlacklisted(ip)
}

func (h *IPHistory) timestamp() string {
	h.tsmutex.RLock()
	defer h.tsmutex.RUnlock()

	return h.currentTimestamp
}

func (h *IPHistory) process() {
	for {
		select {
		case <-h.ctx.Done():
			return
		case req := <-h.reqChan:
			ip := req.IP
			ipstr := ip.To16().String()

			// remember which IP was modified
			h.updatedIPsMutex.Lock()
			h.updatedIPs[ipstr] = true
			h.updatedIPsMutex.Unlock()

			h.mutex.Lock()

			if _, ok := h.data[ipstr]; !ok {
				h.data[ipstr] = list.New()
			}

			head := h.data[ipstr].Front()
			if head == nil || head.Value.(*IPHistoryItem).Timestamp != h.currentSlot {
				hi := IPHistoryItem{
					Timestamp: h.currentSlot,
					Count:     0,
					App:       0,
					Other:     0,
				}
				head = h.data[ipstr].PushFront(&hi)
			}

			hi := head.Value.(*IPHistoryItem)
			hi.Count++
			if h.assetRegexp.MatchString(req.URL) {
				hi.Other++
			} else {
				hi.App++
			}
			h.mutex.Unlock()
		}
	}
}

func (h *IPHistory) expire(expireInterval time.Duration) {
	for {
		cutoff := time.Now().Add(-1 * h.options.Window)

		select {
		case <-h.ctx.Done():
			return
		case <-time.After(expireInterval):
			h.mutex.Lock()
			for ip, counts := range h.data {
			INNER:
				// expire old requests
				for back := counts.Back(); back != nil; back = counts.Back() {
					if back.Value.(*IPHistoryItem).Timestamp.After(cutoff) {
						break INNER
					}
					// log.Printf("removing old requests %v\n", *(back.Value.(*HistoryItem)))
					counts.Remove(back)
					back.Value = nil
					back = nil
				}

				if counts.Len() <= 0 {
					counts = nil
					delete(h.data, ip)
				}
			}
			h.mutex.Unlock()
		}
	}
}

func (h *IPHistory) calculate(updateInterval time.Duration) {
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(updateInterval):
			cutoff := time.Now().Add(-1 * h.options.Window)
			// blacklist := Blacklist{}

			h.updatedIPsMutex.Lock()
			updated := h.updatedIPs
			h.updatedIPs = make(map[string]bool)
			h.updatedIPsMutex.Unlock()

			// pretty.Println(h.data)
			h.mutex.Lock()
			for ip := range updated {
				counts := h.data[ip]

				if counts == nil {
					continue
				}

			INNER:

				// expire old requests
				for back := counts.Back(); back != nil; back = counts.Back() {
					if back.Value.(*IPHistoryItem).Timestamp.After(cutoff) {
						break INNER
					}
					// log.Printf("removing old requests %v\n", *(back.Value.(*HistoryItem)))
					counts.Remove(back)
					back.Value = nil
					back = nil
				}

				// remove the data for an IP if all requests have expired
				if counts.Len() <= 0 {
					delete(h.data, ip)
				}

				// count requests per IP
				var total, app uint64
				for node := counts.Front(); node != nil; node = node.Next() {
					// fmt.Printf("[%s] total: %d, app: %d\n", node.Value.(*HistoryItem).Timestamp, node.Value.(*HistoryItem).Count, node.Value.(*HistoryItem).App)
					total += node.Value.(*IPHistoryItem).Count
					app += node.Value.(*IPHistoryItem).App
				}

				// fmt.Printf("app: %d/%d, ratio: %.2f/%.2f\n", app, h.options.MaxRequests, float64(total)/float64(app), h.options.MaxRatio)
				if app > h.options.MaxRequests && float64(total)/float64(app) > h.options.MaxRatio {
					h.blacklist.Set(net.ParseIP(ip))
				}
			}
			h.mutex.Unlock()

		}
	}
}
