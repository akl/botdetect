package botdetect

import (
	"container/list"
	"context"
	"net"
	"regexp"
	"sync"
	"time"
)

// Blacklist contains all blacklisted IP addresses as key
type Blacklist map[string]bool

// History counts requests per IP for a given time window
type History struct {
	options          *HistoryOptions
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
}

// HistoryItem contains the request count for a given period of time denoted by Timestamp
type HistoryItem struct {
	Timestamp time.Time
	Count     uint64
	App       uint64
	Other     uint64
}

// HistoryOptions configures the behaviour of History
type HistoryOptions struct {
	TimestampFormat string
	TimeSlot        time.Duration
	Window          time.Duration
	Interval        time.Duration
	MaxRequests     uint64
	MaxRatio        float64
}

// Request contains information the history needs about an HTTP request
type Request struct {
	URL string
	IP  net.IP
}

// NewHistory creates a new History item
func NewHistory(ctx context.Context, options *HistoryOptions) *History {
	h := &History{
		options:     options,
		data:        make(map[string]*list.List),
		blacklist:   new(Blacklist),
		reqChan:     make(chan *Request),
		ctx:         ctx,
		mutex:       sync.RWMutex{},
		tsmutex:     sync.RWMutex{},
		blmutex:     sync.RWMutex{},
		assetRegexp: regexp.MustCompile(`\.(jpg|png|css|js|gif|ico)`),
	}

	go h.setTimestamp(h.options.TimeSlot)
	go h.process()
	go h.calculate(options.Interval)

	return h
}

// RequestChannel returns the channel through which IPs are fed to the history
func (h *History) RequestChannel() chan *Request {
	return h.reqChan
}

// Blacklist returns an array of IP addresses that are blacklisted
func (h *History) Blacklist() Blacklist {
	h.blmutex.RLock()
	defer h.blmutex.RUnlock()

	return *(h.blacklist)
}

func (h *History) setTimestamp(slot time.Duration) {
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

// IsBlacklisted determines whether a given IP address is on the blacklist
func (h *History) IsBlacklisted(ip string) bool {
	h.blmutex.RLock()
	defer h.blmutex.RUnlock()

	_, blacklisted := (*h.blacklist)[ip]
	return blacklisted
}

func (h *History) timestamp() string {
	h.tsmutex.RLock()
	defer h.tsmutex.RUnlock()

	return h.currentTimestamp
}

func (h *History) process() {
	for {
		select {
		case <-h.ctx.Done():
			return
		case req := <-h.reqChan:
			ip := req.IP
			h.mutex.Lock()

			if _, ok := h.data[ip.String()]; !ok {
				h.data[ip.To16().String()] = list.New()
			}

			head := h.data[ip.String()].Front()
			if head == nil || head.Value.(*HistoryItem).Timestamp != h.currentSlot {
				hi := HistoryItem{
					Timestamp: h.currentSlot,
					Count:     0,
					App:       0,
					Other:     0,
				}
				head = h.data[ip.String()].PushFront(&hi)
			}

			hi := head.Value.(*HistoryItem)
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

func (h *History) calculate(updateInterval time.Duration) {
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(updateInterval):
			cutoff := time.Now().Add(-1 * h.options.Window)
			blacklist := new(Blacklist)

			// pretty.Println(h.data)
			h.mutex.Lock()
			for ip, counts := range h.data {

			INNER:

				// expire old requests
				for back := counts.Back(); back != nil; back = counts.Back() {
					if back.Value.(*HistoryItem).Timestamp.After(cutoff) {
						break INNER
					}
					// log.Printf("removing old requests %v\n", *(back.Value.(*HistoryItem)))
					counts.Remove(back)
				}

				// remove the data for an IP if all requests have expired
				if counts.Len() <= 0 {
					delete(h.data, ip)
				}

				// count requests per IP
				var total, app uint64
				for node := counts.Front(); node != nil; node = node.Next() {
					// fmt.Printf("[%s] total: %d, app: %d\n", node.Value.(*HistoryItem).Timestamp, node.Value.(*HistoryItem).Count, node.Value.(*HistoryItem).App)
					total += node.Value.(*HistoryItem).Count
					app += node.Value.(*HistoryItem).App
				}

				// fmt.Printf("app: %d/%d, ratio: %.2f/%.2f\n", app, h.options.MaxRequests, float64(total)/float64(app), h.options.MaxRatio)
				if app > h.options.MaxRequests && float64(total)/float64(app) > h.options.MaxRatio {
					(*blacklist)[ip] = true
				}
			}
			h.mutex.Unlock()

			h.blmutex.Lock()
			h.blacklist = blacklist
			h.blmutex.Unlock()
		}
	}
}
