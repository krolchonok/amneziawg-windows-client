package manager

import (
	"context"
	"errors"
	"log"
	"math/bits"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/tunnel/winipcfg"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
)

type dnsProxy struct {
	manager *domainRoutingManager
	udp     *dns.Server
	tcp     *dns.Server
}

func newDNSProxy(mgr *domainRoutingManager) (*dnsProxy, error) {
	// Use ListenConfig with SO_REUSEADDR to avoid conflicts
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	udpConn, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:53")
	if err != nil {
		log.Printf("domain routing: failed to listen UDP on 127.0.0.1:53: %v", err)
		return nil, err
	}
	tcpListener, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:53")
	if err != nil {
		log.Printf("domain routing: failed to listen TCP on 127.0.0.1:53: %v", err)
		udpConn.Close()
		return nil, err
	}

	proxy := &dnsProxy{
		manager: mgr,
		udp: &dns.Server{
			PacketConn: udpConn,
			Handler:    dns.HandlerFunc(mgr.handleDNSQuery),
		},
		tcp: &dns.Server{
			Listener: tcpListener,
			Handler:  dns.HandlerFunc(mgr.handleDNSQuery),
		},
	}
	go func() {
		if err := proxy.udp.ActivateAndServe(); err != nil {
			log.Printf("domain routing: UDP DNS server stopped: %v", err)
		}
	}()
	go func() {
		if err := proxy.tcp.ActivateAndServe(); err != nil {
			log.Printf("domain routing: TCP DNS server stopped: %v", err)
		}
	}()
	return proxy, nil
}

func (p *dnsProxy) Shutdown() {
	// Shutdown with timeout to prevent blocking
	done := make(chan struct{})
	go func() {
		if p.udp != nil {
			_ = p.udp.Shutdown()
		}
		if p.tcp != nil {
			_ = p.tcp.Shutdown()
		}
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(2 * time.Second):
		// Force close if shutdown takes too long
		log.Printf("domain routing: DNS proxy shutdown timeout, forcing close")
		if p.udp != nil && p.udp.PacketConn != nil {
			_ = p.udp.PacketConn.Close()
		}
		if p.tcp != nil && p.tcp.Listener != nil {
			_ = p.tcp.Listener.Close()
		}
	}
}

func (m *domainRoutingManager) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	logEntry := DNSLogEntry{
		Timestamp: startTime,
	}

	log.Printf("domain routing: DNS query received")

	if r == nil || len(r.Question) == 0 {
		log.Printf("domain routing: empty question")
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		logEntry.Error = "empty question"
		logEntry.Latency = time.Since(startTime)
		dnsLogger.Log(logEntry)
		return
	}

	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	logEntry.Domain = name
	logEntry.QueryType = dns.TypeToString[q.Qtype]

	// Check local DNS records first
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		if localIP := LookupLocalDNS(name); localIP != "" {
			ip := net.ParseIP(localIP)
			if ip != nil {
				resp := new(dns.Msg)
				resp.SetReply(r)
				resp.Authoritative = true

				if q.Qtype == dns.TypeA && ip.To4() != nil {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   ip.To4(),
					})
				} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: ip,
					})
				}

				if len(resp.Answer) > 0 {
					logEntry.Target = "local"
					logEntry.ResponseIPs = []string{localIP}
					logEntry.Latency = time.Since(startTime)
					dnsLogger.Log(logEntry)
					_ = w.WriteMsg(resp)
					return
				}
			}
		}
	}

	target := m.decideRoute(name)
	logEntry.Target = routeTargetToString(target)

	upstreams := m.pickUpstreams()
	mode := m.GetMode()

	log.Printf("domain routing: query %s, upstreams: %v, target: %s", name, upstreams, logEntry.Target)

	if len(upstreams) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(resp)
		logEntry.Error = "no upstreams"
		logEntry.Latency = time.Since(startTime)
		dnsLogger.Log(logEntry)
		return
	}

	dialer := m.dialerForDefault()
	resp, err := exchangeWithUpstreams(r, upstreams, dialer)
	if err != nil {
		failed := new(dns.Msg)
		failed.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(failed)
		logEntry.Error = err.Error()
		logEntry.Latency = time.Since(startTime)
		dnsLogger.Log(logEntry)
		return
	}

	// Collect response IPs
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			logEntry.ResponseIPs = append(logEntry.ResponseIPs, a.A.String())
		} else if aaaa, ok := ans.(*dns.AAAA); ok {
			logEntry.ResponseIPs = append(logEntry.ResponseIPs, aaaa.AAAA.String())
		}
	}

	// Применяем роуты только когда режим включён И туннель активен И не DNS Only
	if mode != DomainRoutingOff && mode != DomainRoutingDNSOnly && target != routeTargetNone && m.hasTunnel() {
		if err := m.applyRoutesFromResponse(resp, target); err != nil && mode == DomainRoutingStrict {
			failed := new(dns.Msg)
			failed.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(failed)
			logEntry.Error = "route error: " + err.Error()
			logEntry.Latency = time.Since(startTime)
			dnsLogger.Log(logEntry)
			return
		}
	}

	logEntry.Latency = time.Since(startTime)
	dnsLogger.Log(logEntry)
	_ = w.WriteMsg(resp)
}

func routeTargetToString(t routeTarget) string {
	switch t {
	case routeTargetTunnel:
		return "tunnel"
	case routeTargetDirect:
		return "direct"
	default:
		return "default"
	}
}

func (m *domainRoutingManager) applyRoutesFromResponse(resp *dns.Msg, target routeTarget) error {
	var routeErr error
	for _, ans := range resp.Answer {
		a, ok := ans.(*dns.A)
		if !ok {
			continue
		}
		if err := m.addRouteForIP(a.A, target, a.Hdr.Ttl); err != nil && routeErr == nil {
			routeErr = err
		}
	}
	return routeErr
}

func (m *domainRoutingManager) pickUpstreams() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.dnsUpstreams) > 0 {
		custom := normalizeUpstreamList(m.dnsUpstreams)
		if len(custom) > 0 {
			return custom
		}
		log.Printf("domain routing: custom DNS upstreams invalid, falling back to defaults")
	}

	// Без активного туннеля всегда используем публичные DNS
	if m.activeTunnel == "" {
		return []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	servers := filterIPv4(m.defaultDNS)
	if len(servers) == 0 {
		servers = filterIPv4(m.tunDNS)
	}
	if len(servers) == 0 {
		// Используем кэшированные системные DNS (без loopback)
		servers = m.cachedSystemDNS
	}
	if len(servers) == 0 {
		// Fallback to public DNS if no servers found
		log.Printf("domain routing: no DNS servers found, using fallback")
		return []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	upstreams := make([]string, 0, len(servers))
	for _, server := range servers {
		if server.IsLoopback() {
			continue
		}
		upstreams = append(upstreams, net.JoinHostPort(server.String(), "53"))
	}
	if len(upstreams) == 0 {
		// All servers were loopback, use fallback
		log.Printf("domain routing: all DNS servers are loopback, using fallback")
		return []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	return upstreams
}

func normalizeUpstreamList(servers []string) []string {
	out := make([]string, 0, len(servers))
	for _, server := range servers {
		upstream, ok := normalizeUpstream(server)
		if !ok {
			continue
		}
		out = append(out, upstream)
	}
	return out
}

func normalizeUpstream(server string) (string, bool) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", false
	}
	if strings.Contains(server, ":") {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			return "", false
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			return "", false
		}
		if port == "" {
			return "", false
		}
		return net.JoinHostPort(ip.String(), port), true
	}
	ip := net.ParseIP(server)
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	return net.JoinHostPort(ip.String(), "53"), true
}

// getSystemDNSAndInterface retrieves DNS servers and default interface index
func getSystemDNSAndInterface() ([]net.IP, uint32) {
	interfaces, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeAll)
	if err != nil {
		log.Printf("domain routing: failed to get adapters: %v", err)
		return nil, 0
	}

	var servers []net.IP
	var bestIfIndex uint32
	var bestMetric uint32 = 0xFFFFFFFF

	for _, iface := range interfaces {
		if iface.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		// Пропускаем туннельные интерфейсы
		if iface.IfType == 131 { // IF_TYPE_TUNNEL
			continue
		}

		// Ищем интерфейс с лучшей метрикой (наименьшей)
		if iface.Ipv4Metric < bestMetric {
			bestMetric = iface.Ipv4Metric
			bestIfIndex = iface.IfIndex
		}

		for dns := iface.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if ip4.IsLoopback() || ip4.IsUnspecified() {
				continue
			}
			servers = append(servers, ip4)
		}
	}
	return servers, bestIfIndex
}

func exchangeWithUpstreams(req *dns.Msg, upstreams []string, dialer *net.Dialer) (*dns.Msg, error) {
	var lastErr error
	for _, upstream := range upstreams {
		resp, err := exchangeDNS(req, upstream, dialer, false)
		if err != nil {
			log.Printf("domain routing: upstream %s UDP error: %v", upstream, err)
			lastErr = err
			continue
		}
		if resp.Truncated {
			resp, err = exchangeDNS(req, upstream, dialer, true)
			if err != nil {
				log.Printf("domain routing: upstream %s TCP error: %v", upstream, err)
				lastErr = err
				continue
			}
		}
		log.Printf("domain routing: upstream %s success, answers=%d", upstream, len(resp.Answer))
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream response")
	}
	return nil, lastErr
}

func exchangeDNS(req *dns.Msg, upstream string, dialer *net.Dialer, tcp bool) (*dns.Msg, error) {
	client := &dns.Client{
		Timeout: 4 * time.Second,
	}
	if tcp {
		client.Net = "tcp4"
		client.Dialer = dialer
	} else {
		client.Net = "udp4"
		// For UDP, we need to create a custom connection with interface binding
		if dialer != nil && dialer.Control != nil {
			conn, err := dialer.Dial("udp4", upstream)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			client.Net = ""
			resp, _, err := client.ExchangeWithConn(req, &dns.Conn{Conn: conn})
			return resp, err
		}
	}
	resp, _, err := client.Exchange(req, upstream)
	return resp, err
}

func htonl(value uint32) uint32 {
	return bits.ReverseBytes32(value)
}

func (m *domainRoutingManager) dialerForDefault() *net.Dialer {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Привязка к интерфейсу нужна только когда туннель активен с 0.0.0.0/0
	// Без туннеля просто используем обычный dialer
	if m.activeTunnel == "" {
		return nil
	}

	var ifIndex uint32
	if m.dnsRouteMode == DNSRouteTunnel {
		ifIndex = m.tunIfIndex
		if ifIndex == 0 {
			log.Printf("domain routing: no tunnel interface index, using default routing")
			return nil
		}
		log.Printf("domain routing: creating DNS dialer bound to tunnel ifIndex=%d", ifIndex)
	} else {
		// Используем интерфейс из defaultRoute (физический интерфейс, не туннель)
		ifIndex = m.defaultRoute.InterfaceIndex
		if ifIndex == 0 {
			log.Printf("domain routing: no default interface index, using default routing")
			return nil
		}
		log.Printf("domain routing: creating DNS dialer bound to ifIndex=%d", ifIndex)
	}
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				// IP_UNICAST_IF expects interface index in network byte order
				controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(htonl(ifIndex)))
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}
}

const ipUnicastIf = 31
