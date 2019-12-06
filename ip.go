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

import "net"

var privateNetworks = []string{
	"127.0.0.0/8",    // IPv4 loopback
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"::1/128",        // IPv6 loopback
	"fe80::/10",      // IPv6 link-local
	"fc00::/7",       // IPv6 unique local addr
}

// IP is a utility to check whether an IP address is private
type IP struct {
	IP              net.IP
	privateNetworks []*net.IPNet
}

// NewIP creates a new IP structure
func NewIP() *IP {
	var ipnet *net.IPNet
	privnets := make([]*net.IPNet, len(privateNetworks), len(privateNetworks))
	for i, n := range privateNetworks {
		_, ipnet, _ = net.ParseCIDR(n)
		privnets[i] = ipnet
	}

	return &IP{privateNetworks: privnets}
}

// IsPrivate checks whether a given IP address is privte
func (i *IP) IsPrivate(ip net.IP) bool {
	for _, net := range i.privateNetworks {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// Network returns the private network in which the IP lies
func (i *IP) Network(ip net.IP) *net.IPNet {
	for _, n := range i.privateNetworks {
		if n.Contains(ip) {
			return n
		}
	}
	return nil
}
