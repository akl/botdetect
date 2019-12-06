package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/elcamino/botdetect"

	"net"

	"github.com/namsral/flag"
)

var (
	timeout          = flag.Duration("timeout", 10*time.Millisecond, "wait this long for a redis response")
	ignorePrivateIPs = flag.Bool("ignore-private-ips", true, "igore private IPs when building the checksum")
	timestampFormat  = flag.String("timestamp-format", "15:04", "the key by which to group requests (golang time format, default: hour:minute)")
	timeSlot         = flag.Duration("timeslot", time.Minute, "the duration to use to group requests")
	timeWindow       = flag.Duration("window", time.Hour, "the time window to observe")
	interval         = flag.Duration("interval", 5*time.Second, "build a new blacklist after this much time")
	maxRequests      = flag.Int("max-requests", 30, "maximum number of requests to allow")
	maxRatio         = flag.Float64("max-ratio", 0.85, "blacklist IPs if the app/assets ratio is above this threshold")
	showVersion      = flag.Bool("version", false, "Show the program version")
	trace            = flag.Bool("trace", false, "trace the decisions the program makes")

	privateIPBlocks []*net.IPNet
	cookieKeyBin    []byte

	// Version contains the program version
	Version string

	// BuildDate contains the program build date
	BuildDate string

	// BuildHost contains the host on which the program was built
	BuildHost string
)

const callsign = "[botdetect]"
const ok = "OK"
const block = "BLOCK"

func traceLog(msg string, args ...interface{}) {
	if !*trace {
		return
	}

	log.Printf("%s %s\n", callsign, fmt.Sprintf(msg, args...))
}

func main() {
	flag.Parse()

	traceLog(strings.Join(os.Environ(), "\n"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	history := botdetect.NewHistory(ctx, &botdetect.HistoryOptions{
		TimestampFormat: *timestampFormat,
		TimeSlot:        *timeSlot,
		Window:          *timeWindow,
		Interval:        *interval,
		MaxRequests:     uint64(*maxRequests),
		MaxRatio:        *maxRatio,
	})
	privIP := botdetect.NewIP()

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := scanner.Text()
		traceLog("processing '%s'", line)

		fields := strings.Split(scanner.Text(), "|")
		if len(fields) < 2 {
			traceLog("invalid input: %s. Letting it pass.", line)
			os.Stdout.Write([]byte(ok + "\n"))
			continue
		}
		remote := fields[0]
		xff := fields[1]

		ips := []string{}
		if remote := parseIP(remote); remote != nil && !privIP.IsPrivate(remote) {
			traceLog("adding remote IP: %s", remote.String())
			ips = append(ips, remote.String())
		}

		for _, xff := range strings.Split(xff, ",") {
			if parsedIP := parseIP(strings.TrimSpace(xff)); parsedIP != nil && !privIP.IsPrivate(parsedIP) {
				ips = append(ips, parsedIP.String())
				traceLog("adding X-Forwarded-For IP: %s", parsedIP.String())
			}
		}

		decision := ok
		for i, ip := range ips {
			blacklisted := history.IsBlacklisted(ip)
			traceLog("[%d] ip: %s, blacklisted: %v", i, ip, blacklisted)

			if blacklisted {
				decision = block
				break
			}
		}

		traceLog("decision for %s: %s", line, decision)

		os.Stdout.Write([]byte(decision + "\n"))
	}
}

func parseIP(ip string) net.IP {
	return net.ParseIP(ip).To16()
}
