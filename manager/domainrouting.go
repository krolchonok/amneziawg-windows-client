package manager

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/amnezia-vpn/amneziawg-windows/conf"
	"github.com/amnezia-vpn/amneziawg-windows/tunnel/winipcfg"
)

type DomainRoutingMode int

const (
	DomainRoutingOff DomainRoutingMode = iota
	DomainRoutingRelaxed
	DomainRoutingStrict
	DomainRoutingDNSOnly // DNS proxy only, no routing through tunnel
)

func (m DomainRoutingMode) String() string {
	switch m {
	case DomainRoutingRelaxed:
		return "relaxed"
	case DomainRoutingStrict:
		return "strict"
	case DomainRoutingDNSOnly:
		return "dnsonly"
	default:
		return "off"
	}
}

func parseDomainRoutingMode(s string) DomainRoutingMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "relaxed":
		return DomainRoutingRelaxed
	case "strict":
		return DomainRoutingStrict
	case "dnsonly":
		return DomainRoutingDNSOnly
	default:
		return DomainRoutingOff
	}
}

// DomainListMode определяет как интерпретировать список доменов
type DomainListMode int

const (
	// ListModeDisabled - использовать отдельные списки tunnel/direct
	ListModeDisabled DomainListMode = iota
	// ListModeWhitelist - только домены из списка идут через туннель, остальное напрямую
	ListModeWhitelist
	// ListModeBlacklist - всё через туннель, кроме доменов из списка
	ListModeBlacklist
)

func (m DomainListMode) String() string {
	switch m {
	case ListModeWhitelist:
		return "whitelist"
	case ListModeBlacklist:
		return "blacklist"
	default:
		return "disabled"
	}
}

func parseListMode(s string) DomainListMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "whitelist":
		return ListModeWhitelist
	case "blacklist":
		return ListModeBlacklist
	default:
		return ListModeDisabled
	}
}

type domainRoutingConfig struct {
	Mode            string   `json:"mode"`
	ListMode        string   `json:"listMode"`
	Domains         []string `json:"domains"`
	Tunnel          []string `json:"tunnel"`
	Direct          []string `json:"direct"`
	ExcludeLoopback bool     `json:"excludeLoopback"`
	DNSUpstreams    []string `json:"dnsUpstreams"`
	DNSRouteMode    string   `json:"dnsRouteMode"`
	RouteTunnel     string   `json:"routeTunnel"`
}

type interfaceDNSState struct {
	luid    winipcfg.LUID
	servers []net.IP
	search  []string
}

type routeTarget int

const (
	routeTargetNone routeTarget = iota
	routeTargetTunnel
	routeTargetDirect
)

type routeEntry struct {
	ip      string
	target  routeTarget
	luid    winipcfg.LUID
	nextHop net.IP
	metric  uint32
	expires time.Time
}

type domainRoutingManager struct {
	mu sync.Mutex

	mode         DomainRoutingMode
	listMode     DomainListMode
	dnsRouteMode DNSRouteMode
	routeTunnel  string
	config       domainRoutingConfig
	rules        domainRoutingRules

	configPath    string
	configModTime time.Time

	activeTunnel string
	tunLUID      winipcfg.LUID
	tunIfIndex   uint32

	defaultRoute winipcfg.MibIPforwardRow2
	defaultDNS   []net.IP

	tunDNS       []net.IP
	tunSearch    []string
	dnsUpstreams []string

	defaultDNSState *interfaceDNSState
	tunDNSState     *interfaceDNSState

	routeEntries map[string]*routeEntry

	// cachedSystemDNS - DNS серверы, полученные при старте до изменений
	cachedSystemDNS []net.IP
	// cachedDefaultIfIndex - индекс интерфейса по умолчанию для DNS запросов
	cachedDefaultIfIndex uint32

	// excludeLoopback - исключать 127.0.0.1 из туннеля (для DNS proxy)
	excludeLoopback    bool
	loopbackRouteAdded bool

	proxy *dnsProxy
	stop  chan struct{}
}

type DNSRouteMode int

const (
	DNSRouteDirect DNSRouteMode = iota
	DNSRouteTunnel
)

func (m DNSRouteMode) String() string {
	switch m {
	case DNSRouteTunnel:
		return "tunnel"
	default:
		return "direct"
	}
}

func parseDNSRouteMode(s string) DNSRouteMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tunnel":
		return DNSRouteTunnel
	default:
		return DNSRouteDirect
	}
}

// DomainRoutingDNSSettings describes DNS upstreams and routing mode for DNS lookups.
type DomainRoutingDNSSettings struct {
	Upstreams []string
	RouteMode string
	Tunnel    string
}

type domainRoutingRules struct {
	domains []string // для whitelist/blacklist режима
	tunnel  []string
	direct  []string
}

var domainRouting = &domainRoutingManager{
	routeEntries: make(map[string]*routeEntry),
	stop:         make(chan struct{}),
}

func InitDomainRouting() error {
	return domainRouting.init()
}

func (m *domainRoutingManager) init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.configPath = domainRoutingConfigPath()
	if err := m.loadConfigLocked(); err != nil {
		log.Printf("domain routing: failed to load config: %v", err)
	}

	// Кэшируем системные DNS и интерфейс ДО запуска proxy
	m.cachedSystemDNS, m.cachedDefaultIfIndex = getSystemDNSAndInterface()
	log.Printf("domain routing: cached system DNS: %v, ifIndex: %d", m.cachedSystemDNS, m.cachedDefaultIfIndex)

	// Запускаем DNS proxy сразу при старте
	if err := m.startProxyLocked(); err != nil {
		log.Printf("domain routing: failed to start DNS proxy at init: %v", err)
		// Не возвращаем ошибку - приложение может работать без DNS proxy
	}

	// Периодическая верификация маршрутов — переставляем удалённые системой
	go m.routeVerificationLoop()
	return nil
}

func (m *domainRoutingManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Автоматическая очистка отключена
			// m.cleanupExpiredRoutes()
		case <-m.stop:
			return
		}
	}
}

// routeVerificationLoop периодически проверяет, что маршруты из routeEntries
// действительно присутствуют в системной таблице маршрутизации.
// Windows может удалять маршруты при смене сети, выходе из спящего режима и т.д.
func (m *domainRoutingManager) routeVerificationLoop() {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.verifyAndRepairRoutes()
		case <-m.stop:
			return
		}
	}
}

// verifyAndRepairRoutes проверяет все маршруты из карты и переустанавливает
// те, которые были удалены из системной таблицы маршрутизации.
func (m *domainRoutingManager) verifyAndRepairRoutes() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeTunnel == "" || m.mode == DomainRoutingOff || m.mode == DomainRoutingDNSOnly {
		return
	}

	if len(m.routeEntries) == 0 {
		return
	}

	// Получаем текущую таблицу маршрутов из системы
	systemRoutes := m.getSystemRouteSet()

	repaired := 0
	for ipStr, entry := range m.routeEntries {
		if _, exists := systemRoutes[ipStr]; !exists {
			// Маршрут пропал из системной таблицы — переустанавливаем
			if err := addRoute(entry); err != nil {
				if !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
					log.Printf("domain routing: failed to re-add route for %s: %v", ipStr, err)
				}
			} else {
				repaired++
			}
		}
	}

	if repaired > 0 {
		log.Printf("domain routing: re-added %d missing routes", repaired)
	}
}

// getSystemRouteSet возвращает множество IP-адресов (/32), для которых
// существуют маршруты в системной таблице через наши интерфейсы.
func (m *domainRoutingManager) getSystemRouteSet() map[string]bool {
	result := make(map[string]bool)

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		log.Printf("domain routing: failed to get route table for verification: %v", err)
		return result
	}

	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 32 {
			continue
		}
		// Проверяем только маршруты через наши интерфейсы
		if route.InterfaceLUID != m.tunLUID && route.InterfaceLUID != m.defaultRoute.InterfaceLUID {
			continue
		}
		ip := route.DestinationPrefix.Prefix.IP()
		if ip != nil {
			result[ip.String()] = true
		}
	}
	return result
}

func (m *domainRoutingManager) cleanupExpiredRoutes() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for ip, entry := range m.routeEntries {
		if entry.expires.After(now) {
			continue
		}
		if err := deleteRoute(entry); err != nil {
			log.Printf("domain routing: failed to delete route for %s: %v", ip, err)
		}
		delete(m.routeEntries, ip)
	}
}

// ClearAllRoutes очищает все маршруты (для ручной очистки)
func ClearAllRoutes() {
	domainRouting.clearAllRoutes()
}

func (m *domainRoutingManager) clearAllRoutes() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for ip, entry := range m.routeEntries {
		if err := deleteRoute(entry); err != nil {
			log.Printf("domain routing: failed to delete route for %s: %v", ip, err)
		}
		delete(m.routeEntries, ip)
	}
	log.Printf("domain routing: cleared all routes manually")
}

func (m *domainRoutingManager) OnTunnelStateChange(name string, state TunnelState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch state {
	case TunnelStarted:
		if m.routeTunnel != "" && !strings.EqualFold(name, m.routeTunnel) {
			return
		}
		if err := m.activateTunnelLocked(name); err != nil {
			log.Printf("domain routing: failed to activate tunnel %s: %v", name, err)
		}
	case TunnelStopped:
		if m.activeTunnel == name {
			m.deactivateTunnelLocked()
			if next := m.pickFallbackTunnelLocked(name); next != "" {
				if err := m.activateTunnelLocked(next); err != nil {
					log.Printf("domain routing: failed to activate fallback tunnel %s: %v", next, err)
				}
			}
		}
	}
}

func (m *domainRoutingManager) GetMode() DomainRoutingMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

func (m *domainRoutingManager) hasTunnel() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeTunnel != ""
}

func (m *domainRoutingManager) GetExcludeLoopback() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.excludeLoopback
}

func (m *domainRoutingManager) SetExcludeLoopback(exclude bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if exclude == m.excludeLoopback {
		return nil
	}
	m.excludeLoopback = exclude
	m.config.ExcludeLoopback = exclude
	if err := m.saveConfigLocked(); err != nil {
		return err
	}

	// Обновляем все конфиги туннелей
	go updateAllTunnelConfigs(exclude)

	return nil
}

// updateAllTunnelConfigs обновляет AllowedIPs во всех конфигах туннелей
func updateAllTunnelConfigs(excludeLoopback bool) {
	tunnels, err := conf.ListConfigNames()
	if err != nil {
		log.Printf("domain routing: failed to list tunnels: %v", err)
		return
	}

	for _, name := range tunnels {
		c, err := conf.LoadFromName(name)
		if err != nil {
			continue
		}

		var modified bool
		if excludeLoopback {
			modified = excludeLoopbackFromConfig(c)
		} else {
			modified = RestoreLoopbackToAllowedIPs(c)
		}

		if modified {
			if err := c.Save(true); err != nil {
				log.Printf("domain routing: failed to save config %s: %v", name, err)
			} else {
				log.Printf("domain routing: updated config %s", name)
			}
		}
	}
}

// excludeLoopbackFromConfig модифицирует конфиг без проверки настройки (для внутреннего использования)
func excludeLoopbackFromConfig(c *conf.Config) bool {
	modified := false
	for i := range c.Peers {
		newAllowedIPs := make([]conf.IPCidr, 0, len(c.Peers[i].AllowedIPs)+32)
		for _, ip := range c.Peers[i].AllowedIPs {
			if ip.IP.IsUnspecified() && ip.Cidr == 0 {
				newAllowedIPs = append(newAllowedIPs, allowedIPsExcludingLoopback()...)
				modified = true
			} else {
				newAllowedIPs = append(newAllowedIPs, ip)
			}
		}
		if modified {
			c.Peers[i].AllowedIPs = newAllowedIPs
		}
	}
	return modified
}

func (m *domainRoutingManager) SetMode(mode DomainRoutingMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if mode == m.mode {
		return nil
	}
	m.mode = mode
	m.config.Mode = mode.String()
	if err := m.saveConfigLocked(); err != nil {
		return err
	}
	return m.applyModeLocked()
}

func (m *domainRoutingManager) GetRules() DomainRoutingRulesData {
	m.mu.Lock()
	defer m.mu.Unlock()
	return DomainRoutingRulesData{
		ListMode: m.listMode.String(),
		Domains:  m.config.Domains,
		Tunnel:   m.config.Tunnel,
		Direct:   m.config.Direct,
	}
}

func (m *domainRoutingManager) SetRules(rules DomainRoutingRulesData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.listMode = parseListMode(rules.ListMode)
	m.config.ListMode = rules.ListMode
	m.config.Domains = rules.Domains
	m.config.Tunnel = rules.Tunnel
	m.config.Direct = rules.Direct
	m.rules = domainRoutingRules{
		domains: normalizeRules(rules.Domains),
		tunnel:  normalizeRules(rules.Tunnel),
		direct:  normalizeRules(rules.Direct),
	}
	return m.saveConfigLocked()
}

func (m *domainRoutingManager) GetDNSSettings() DomainRoutingDNSSettings {
	m.mu.Lock()
	defer m.mu.Unlock()
	upstreams := make([]string, len(m.config.DNSUpstreams))
	copy(upstreams, m.config.DNSUpstreams)
	return DomainRoutingDNSSettings{
		Upstreams: upstreams,
		RouteMode: m.dnsRouteMode.String(),
		Tunnel:    m.routeTunnel,
	}
}

func (m *domainRoutingManager) SetDNSSettings(settings DomainRoutingDNSSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	upstreams := sanitizeDNSUpstreams(settings.Upstreams)
	m.dnsUpstreams = upstreams
	m.config.DNSUpstreams = upstreams
	m.dnsRouteMode = parseDNSRouteMode(settings.RouteMode)
	m.config.DNSRouteMode = m.dnsRouteMode.String()
	m.routeTunnel = strings.TrimSpace(settings.Tunnel)
	m.config.RouteTunnel = m.routeTunnel
	if m.routeTunnel != "" && m.activeTunnel != "" && !strings.EqualFold(m.activeTunnel, m.routeTunnel) {
		m.deactivateTunnelLocked()
		if next := m.pickFallbackTunnelLocked(""); next != "" {
			if err := m.activateTunnelLocked(next); err != nil {
				log.Printf("domain routing: failed to activate selected tunnel %s: %v", next, err)
			}
		}
	}
	return m.saveConfigLocked()
}

func (m *domainRoutingManager) applyModeLocked() error {
	if m.mode == DomainRoutingOff {
		m.clearRoutesLocked()
		m.restoreDNSLocked()
		// НЕ останавливаем proxy - он работает всегда как обычный DNS
		return nil
	}
	if m.activeTunnel == "" {
		return nil
	}
	// Proxy уже должен быть запущен при init(), но проверим
	if m.proxy == nil {
		if err := m.startProxyLocked(); err != nil {
			return err
		}
	}
	if err := m.applyDNSLocked(); err != nil {
		log.Printf("domain routing: failed to apply DNS settings: %v", err)
	}
	return nil
}

func (m *domainRoutingManager) activateTunnelLocked(name string) error {
	if m.activeTunnel == name {
		return nil
	}

	m.clearRoutesLocked()
	m.restoreDNSLocked()

	cfg, err := conf.LoadFromName(name)
	if err != nil {
		return err
	}
	tunLUID, tunIfIndex, err := findTunnelInterface(cfg.Name)
	if err != nil {
		return err
	}
	defaultRoute, defaultDNS, err := findDefaultRouteAndDNS(tunLUID)
	if err != nil {
		log.Printf("domain routing: failed to resolve default route/DNS: %v", err)
	}
	log.Printf("domain routing: defaultRoute LUID=%v ifIndex=%d, defaultDNS=%v", defaultRoute.InterfaceLUID, defaultRoute.InterfaceIndex, defaultDNS)

	m.activeTunnel = name
	m.tunLUID = tunLUID
	m.tunIfIndex = tunIfIndex
	m.defaultRoute = defaultRoute
	m.defaultDNS = filterIPv4(defaultDNS)
	m.tunDNS = filterIPv4(cfg.Interface.DNS)
	m.tunSearch = sanitizeSearchList(cfg.Interface.DNSSearch)

	// Добавляем маршрут для loopback если опция включена
	if m.excludeLoopback {
		m.addLoopbackRouteLocked()
	}

	// Proxy уже запущен при init(), только применяем DNS настройки если режим включён
	if m.mode != DomainRoutingOff {
		if err := m.applyDNSLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (m *domainRoutingManager) deactivateTunnelLocked() {
	m.clearRoutesLocked()
	m.restoreDNSLocked()
	m.removeLoopbackRouteLocked()

	// НЕ останавливаем proxy - он работает всегда
	// Просто сбрасываем информацию о туннеле
	m.activeTunnel = ""
	m.tunLUID = 0
	m.tunIfIndex = 0
	m.defaultRoute = winipcfg.MibIPforwardRow2{}
	m.defaultDNS = nil
	m.tunDNS = nil
	m.tunSearch = nil
}

func (m *domainRoutingManager) startProxyLocked() error {
	if m.proxy != nil {
		return nil
	}
	proxy, err := newDNSProxy(m)
	if err != nil {
		log.Printf("domain routing: WARNING - failed to start DNS proxy on port 53: %v (port may be in use by another application)", err)
		return err
	}
	m.proxy = proxy
	log.Printf("domain routing: DNS proxy started on 127.0.0.1:53")
	return nil
}

func (m *domainRoutingManager) stopProxyLocked() {
	if m.proxy == nil {
		return
	}
	m.proxy.Shutdown()
	m.proxy = nil
	log.Printf("domain routing: DNS proxy stopped")
}

func (m *domainRoutingManager) applyDNSLocked() error {
	if m.proxy == nil || m.activeTunnel == "" {
		return nil
	}
	if m.tunLUID == 0 {
		return errors.New("missing tunnel interface")
	}

	if m.tunDNSState == nil {
		search := sanitizeSearchList(m.tunSearch)
		m.tunDNSState = &interfaceDNSState{
			luid:    m.tunLUID,
			servers: filterIPv4(m.tunDNS),
			search:  search,
		}
	}
	if m.defaultRoute.InterfaceLUID != 0 && m.defaultDNSState == nil {
		search := sanitizeSearchList(m.readSearchListForInterface(m.defaultRoute.InterfaceLUID))
		m.defaultDNSState = &interfaceDNSState{
			luid:    m.defaultRoute.InterfaceLUID,
			servers: filterIPv4(m.defaultDNS),
			search:  search,
		}
	}

	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}
	if err := m.tunLUID.SetDNS(windows.AF_INET, loopback, m.tunDNSState.search); err != nil {
		return err
	}
	if m.defaultDNSState != nil {
		if err := m.defaultDNSState.luid.SetDNS(windows.AF_INET, loopback, m.defaultDNSState.search); err != nil {
			return err
		}
	}
	return nil
}

func (m *domainRoutingManager) restoreDNSLocked() {
	if m.tunDNSState != nil {
		_ = m.tunDNSState.luid.SetDNS(windows.AF_INET, m.tunDNSState.servers, m.tunDNSState.search)
		m.tunDNSState = nil
	}
	if m.defaultDNSState != nil {
		_ = m.defaultDNSState.luid.SetDNS(windows.AF_INET, m.defaultDNSState.servers, m.defaultDNSState.search)
		m.defaultDNSState = nil
	}
}

func (m *domainRoutingManager) clearRoutesLocked() {
	for ip, entry := range m.routeEntries {
		if err := deleteRoute(entry); err != nil {
			log.Printf("domain routing: failed to delete route for %s: %v", ip, err)
		}
		delete(m.routeEntries, ip)
	}
}

func (m *domainRoutingManager) decideRoute(domain string) routeTarget {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshConfigIfNeededLocked()
	d := normalizeDomain(domain)
	if d == "" {
		return routeTargetNone
	}

	// Whitelist/Blacklist режим
	switch m.listMode {
	case ListModeWhitelist:
		// Только домены из списка идут через туннель
		if matchDomain(d, m.rules.domains) {
			return routeTargetTunnel
		}
		return routeTargetDirect
	case ListModeBlacklist:
		// Всё через туннель, кроме доменов из списка
		if matchDomain(d, m.rules.domains) {
			return routeTargetDirect
		}
		return routeTargetTunnel
	default:
		// Старая логика с отдельными списками tunnel/direct
		if matchDomain(d, m.rules.direct) {
			return routeTargetDirect
		}
		if matchDomain(d, m.rules.tunnel) {
			return routeTargetTunnel
		}
		return routeTargetNone
	}
}

func (m *domainRoutingManager) addRouteForIP(ip net.IP, target routeTarget, ttl uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ip == nil || ip.To4() == nil {
		return nil
	}
	if m.mode == DomainRoutingOff || m.activeTunnel == "" {
		return nil
	}

	ttlSeconds := int(ttl)
	// Минимальный TTL 5 минут (300 секунд) - браузеры часто кэшируют DNS дольше,
	// чем TTL из DNS ответа, поэтому маршрут должен жить достаточно долго
	const minTTL = 300
	if ttlSeconds < minTTL {
		ttlSeconds = minTTL
	}
	expires := time.Now().Add(time.Duration(ttlSeconds) * time.Second)

	ipStr := ip.String()
	entry, ok := m.routeEntries[ipStr]
	if ok {
		entry.expires = expires
		// Проверяем, что маршрут реально существует в системе.
		// Windows может удалить его (спящий режим, смена сети и т.д.).
		if !m.routeExistsInSystemLocked(ipStr, entry.luid) {
			log.Printf("domain routing: route for %s missing in system, re-adding", ipStr)
			if err := addRoute(entry); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
				log.Printf("domain routing: failed to re-add route for %s: %v", ipStr, err)
			}
		}
		return nil
	}

	newEntry, err := m.buildRouteEntry(ip, target, expires)
	if err != nil {
		return err
	}
	if err := addRoute(newEntry); err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			m.routeEntries[ipStr] = newEntry
			return nil
		}
		return err
	}
	m.routeEntries[ipStr] = newEntry
	return nil
}

func (m *domainRoutingManager) buildRouteEntry(ip net.IP, target routeTarget, expires time.Time) (*routeEntry, error) {
	var entry routeEntry
	entry.ip = ip.String()
	entry.expires = expires
	entry.target = target

	switch target {
	case routeTargetTunnel:
		if m.tunLUID == 0 {
			return nil, errors.New("missing tunnel interface")
		}
		entry.luid = m.tunLUID
		entry.nextHop = net.IPv4zero
		entry.metric = 0
	case routeTargetDirect:
		if m.defaultRoute.InterfaceLUID == 0 {
			return nil, errors.New("missing default route interface")
		}
		entry.luid = m.defaultRoute.InterfaceLUID
		entry.nextHop = m.defaultRoute.NextHop.IP()
		if entry.nextHop == nil {
			return nil, errors.New("missing default route next hop")
		}
		entry.metric = m.defaultRoute.Metric
	default:
		return nil, nil
	}
	return &entry, nil
}

func (m *domainRoutingManager) refreshConfigIfNeededLocked() {
	if m.configPath == "" {
		return
	}
	info, err := os.Stat(m.configPath)
	if err != nil {
		return
	}
	if info.ModTime().After(m.configModTime) {
		if err := m.loadConfigLocked(); err != nil {
			log.Printf("domain routing: failed to reload config: %v", err)
		}
	}
}

func (m *domainRoutingManager) loadConfigLocked() error {
	cfg := domainRoutingConfig{
		Mode:            DomainRoutingOff.String(),
		ExcludeLoopback: true,
		DNSRouteMode:    DNSRouteDirect.String(),
		RouteTunnel:     "",
	} // По умолчанию включено
	info, err := os.Stat(m.configPath)
	if err == nil {
		data, readErr := os.ReadFile(m.configPath)
		if readErr == nil {
			_ = json.Unmarshal(data, &cfg)
			m.configModTime = info.ModTime()
		}
	}
	m.config = cfg
	m.mode = parseDomainRoutingMode(cfg.Mode)
	m.listMode = parseListMode(cfg.ListMode)
	m.excludeLoopback = cfg.ExcludeLoopback
	m.dnsRouteMode = parseDNSRouteMode(cfg.DNSRouteMode)
	m.routeTunnel = strings.TrimSpace(cfg.RouteTunnel)
	m.dnsUpstreams = sanitizeDNSUpstreams(cfg.DNSUpstreams)
	m.config.DNSUpstreams = m.dnsUpstreams
	m.config.DNSRouteMode = m.dnsRouteMode.String()
	m.config.RouteTunnel = m.routeTunnel
	m.rules = domainRoutingRules{
		domains: normalizeRules(cfg.Domains),
		tunnel:  normalizeRules(cfg.Tunnel),
		direct:  normalizeRules(cfg.Direct),
	}
	return nil
}

func (m *domainRoutingManager) pickFallbackTunnelLocked(exclude string) string {
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()

	if m.routeTunnel != "" {
		for name, state := range trackedTunnels {
			if strings.EqualFold(name, m.routeTunnel) && !strings.EqualFold(name, exclude) && state == TunnelStarted {
				return name
			}
		}
		return ""
	}
	for name, state := range trackedTunnels {
		if !strings.EqualFold(name, exclude) && state == TunnelStarted {
			return name
		}
	}
	return ""
}

func (m *domainRoutingManager) saveConfigLocked() error {
	if m.configPath == "" {
		return errors.New("missing config path")
	}
	if err := os.MkdirAll(filepath.Dir(m.configPath), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.configPath, data, 0644); err != nil {
		return err
	}
	info, err := os.Stat(m.configPath)
	if err == nil {
		m.configModTime = info.ModTime()
	}
	m.rules = domainRoutingRules{
		domains: normalizeRules(m.config.Domains),
		tunnel:  normalizeRules(m.config.Tunnel),
		direct:  normalizeRules(m.config.Direct),
	}
	return nil
}

func (m *domainRoutingManager) readSearchListForInterface(luid winipcfg.LUID) []string {
	guid, err := luid.GUID()
	if err != nil {
		return nil
	}
	keyPath := `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + guid.String()
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()

	if v, _, err := key.GetStringValue("SearchList"); err == nil && v != "" {
		return splitSearchList(v)
	}
	if v, _, err := key.GetStringValue("Domain"); err == nil && v != "" {
		return []string{v}
	}
	if v, _, err := key.GetStringValue("DhcpSearchList"); err == nil && v != "" {
		return splitSearchList(v)
	}
	if v, _, err := key.GetStringValue("DhcpDomain"); err == nil && v != "" {
		return []string{v}
	}
	return nil
}

func domainRoutingConfigPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "AmneziaWG", "domain-routing.json")
}

func normalizeDomain(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".")
	return name
}

func normalizeRules(rules []string) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		rule = normalizeDomain(rule)
		rule = strings.TrimPrefix(rule, "*.")
		if rule == "" {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func matchDomain(domain string, rules []string) bool {
	for _, rule := range rules {
		if domain == rule || strings.HasSuffix(domain, "."+rule) {
			return true
		}
	}
	return false
}

func splitSearchList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func sanitizeSearchList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func sanitizeDNSUpstreams(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func filterIPv4(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			// Skip unspecified (0.0.0.0) and loopback addresses
			if v4.IsUnspecified() || v4.IsLoopback() {
				continue
			}
			out = append(out, v4)
		}
	}
	return out
}

func findTunnelInterface(name string) (winipcfg.LUID, uint32, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return 0, 0, err
	}
	for _, adapter := range adapters {
		if adapter.FriendlyName() == name {
			ifrow, err := adapter.LUID.Interface()
			if err != nil {
				return adapter.LUID, 0, nil
			}
			return adapter.LUID, ifrow.InterfaceIndex, nil
		}
	}
	return 0, 0, errors.New("tunnel interface not found")
}

func findDefaultRouteAndDNS(tunLUID winipcfg.LUID) (winipcfg.MibIPforwardRow2, []net.IP, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return winipcfg.MibIPforwardRow2{}, nil, err
	}
	var best winipcfg.MibIPforwardRow2
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		if route.InterfaceLUID == tunLUID || route.Loopback {
			continue
		}
		if best.InterfaceLUID == 0 || route.Metric < best.Metric {
			best = route
		}
	}
	if best.InterfaceLUID == 0 {
		return winipcfg.MibIPforwardRow2{}, nil, errors.New("default route not found")
	}
	dnsServers, err := best.InterfaceLUID.DNS()
	if err != nil {
		return best, nil, err
	}
	return best, dnsServers, nil
}

func addRoute(entry *routeEntry) error {
	if entry == nil {
		return nil
	}
	netmask := net.CIDRMask(32, 32)
	dest := net.IPNet{IP: net.ParseIP(entry.ip).To4(), Mask: netmask}
	return entry.luid.AddRoute(dest, entry.nextHop, entry.metric)
}

// routeExistsInSystemLocked проверяет наличие /32 маршрута для IP в системной таблице.
// Caller must hold m.mu.
func (m *domainRoutingManager) routeExistsInSystemLocked(ipStr string, expectedLUID winipcfg.LUID) bool {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		// При ошибке считаем что маршрут есть (не пытаемся переставить)
		return true
	}
	targetIP := net.ParseIP(ipStr).To4()
	if targetIP == nil {
		return true
	}
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 32 {
			continue
		}
		if route.InterfaceLUID != expectedLUID {
			continue
		}
		rip := route.DestinationPrefix.Prefix.IP()
		if rip != nil && rip.Equal(targetIP) {
			return true
		}
	}
	return false
}

func deleteRoute(entry *routeEntry) error {
	if entry == nil {
		return nil
	}
	netmask := net.CIDRMask(32, 32)
	dest := net.IPNet{IP: net.ParseIP(entry.ip).To4(), Mask: netmask}
	return entry.luid.DeleteRoute(dest, entry.nextHop)
}

// addLoopbackRouteLocked добавляет маршрут для 127.0.0.1 через loopback интерфейс
// чтобы исключить loopback из туннеля (нужно для DNS proxy)
func (m *domainRoutingManager) addLoopbackRouteLocked() {
	if m.loopbackRouteAdded {
		return
	}

	// Находим loopback интерфейс
	loopbackLUID, err := findLoopbackLUID()
	if err != nil {
		log.Printf("domain routing: cannot find loopback interface: %v", err)
		return
	}

	// Добавляем маршрут для 127.0.0.1/32 через loopback интерфейс с метрикой 1
	loopbackIP := net.ParseIP("127.0.0.1").To4()
	dest := net.IPNet{IP: loopbackIP, Mask: net.CIDRMask(32, 32)}

	// nexthop 127.0.0.1 для loopback интерфейса
	err = loopbackLUID.AddRoute(dest, loopbackIP, 1)
	if err != nil {
		if !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			log.Printf("domain routing: failed to add loopback route: %v", err)
			return
		}
	}
	m.loopbackRouteAdded = true
	log.Printf("domain routing: added loopback exclusion route via loopback interface")
}

// removeLoopbackRouteLocked удаляет маршрут для 127.0.0.1
func (m *domainRoutingManager) removeLoopbackRouteLocked() {
	if !m.loopbackRouteAdded {
		return
	}

	loopbackLUID, err := findLoopbackLUID()
	if err != nil {
		m.loopbackRouteAdded = false
		return
	}

	loopbackIP := net.ParseIP("127.0.0.1").To4()
	dest := net.IPNet{IP: loopbackIP, Mask: net.CIDRMask(32, 32)}

	err = loopbackLUID.DeleteRoute(dest, loopbackIP)
	if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		log.Printf("domain routing: failed to remove loopback route: %v", err)
	}
	m.loopbackRouteAdded = false
	log.Printf("domain routing: removed loopback exclusion route")
}

// findLoopbackLUID находит LUID loopback интерфейса
func findLoopbackLUID() (winipcfg.LUID, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
	if err != nil {
		return 0, err
	}
	for _, adapter := range adapters {
		if adapter.IfType == 24 { // IF_TYPE_SOFTWARE_LOOPBACK
			return adapter.LUID, nil
		}
	}
	return 0, errors.New("loopback interface not found")
}

// ExcludeLoopbackFromAllowedIPs модифицирует конфиг, заменяя 0.0.0.0/0 на подсети без 127.0.0.1
// Возвращает true если конфиг был модифицирован
func ExcludeLoopbackFromAllowedIPs(c *conf.Config) bool {
	if !domainRouting.GetExcludeLoopback() {
		return false
	}

	modified := false
	for i := range c.Peers {
		newAllowedIPs := make([]conf.IPCidr, 0, len(c.Peers[i].AllowedIPs)+32)
		for _, ip := range c.Peers[i].AllowedIPs {
			// Проверяем 0.0.0.0/0
			if ip.IP.IsUnspecified() && ip.Cidr == 0 {
				// Заменяем на подсети, исключающие 127.0.0.1
				newAllowedIPs = append(newAllowedIPs, allowedIPsExcludingLoopback()...)
				modified = true
				log.Printf("domain routing: replaced 0.0.0.0/0 with loopback-excluded subnets")
			} else {
				newAllowedIPs = append(newAllowedIPs, ip)
			}
		}
		if modified {
			c.Peers[i].AllowedIPs = newAllowedIPs
		}
	}
	return modified
}

// RestoreLoopbackToAllowedIPs восстанавливает 0.0.0.0/0 из подсетей с исключённым loopback
// Возвращает true если конфиг был модифицирован
func RestoreLoopbackToAllowedIPs(c *conf.Config) bool {
	modified := false
	for i := range c.Peers {
		if hasLoopbackExcludedPattern(c.Peers[i].AllowedIPs) {
			newAllowedIPs := make([]conf.IPCidr, 0, len(c.Peers[i].AllowedIPs))
			// Удаляем все подсети из паттерна и добавляем 0.0.0.0/0
			excludedSet := makeExcludedSet()
			for _, ip := range c.Peers[i].AllowedIPs {
				key := ip.String()
				if _, isExcluded := excludedSet[key]; !isExcluded {
					newAllowedIPs = append(newAllowedIPs, ip)
				}
			}
			// Добавляем 0.0.0.0/0
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{
				IP:   net.IPv4zero,
				Cidr: 0,
			})
			c.Peers[i].AllowedIPs = newAllowedIPs
			modified = true
			log.Printf("domain routing: restored 0.0.0.0/0 from loopback-excluded subnets")
		}
	}
	return modified
}

// hasLoopbackExcludedPattern проверяет, содержит ли список наш паттерн исключения loopback
func hasLoopbackExcludedPattern(ips []conf.IPCidr) bool {
	// Проверяем наличие характерных подсетей: 0.0.0.0/2 и 128.0.0.0/1
	has0002 := false
	has12801 := false
	for _, ip := range ips {
		s := ip.String()
		if s == "0.0.0.0/2" {
			has0002 = true
		}
		if s == "128.0.0.0/1" {
			has12801 = true
		}
	}
	return has0002 && has12801
}

// makeExcludedSet создаёт множество подсетей для исключения loopback
func makeExcludedSet() map[string]bool {
	subnets := []string{
		"0.0.0.0/2",
		"64.0.0.0/3",
		"96.0.0.0/4",
		"112.0.0.0/5",
		"120.0.0.0/6",
		"124.0.0.0/7",
		"126.0.0.0/8",
		"127.0.0.0/32",
		"127.0.0.2/31",
		"127.0.0.4/30",
		"127.0.0.8/29",
		"127.0.0.16/28",
		"127.0.0.32/27",
		"127.0.0.64/26",
		"127.0.0.128/25",
		"127.0.1.0/24",
		"127.0.2.0/23",
		"127.0.4.0/22",
		"127.0.8.0/21",
		"127.0.16.0/20",
		"127.0.32.0/19",
		"127.0.64.0/18",
		"127.0.128.0/17",
		"127.1.0.0/16",
		"127.2.0.0/15",
		"127.4.0.0/14",
		"127.8.0.0/13",
		"127.16.0.0/12",
		"127.32.0.0/11",
		"127.64.0.0/10",
		"127.128.0.0/9",
		"128.0.0.0/1",
	}
	set := make(map[string]bool, len(subnets))
	for _, s := range subnets {
		set[s] = true
	}
	return set
}

// allowedIPsExcludingLoopback возвращает подсети, эквивалентные 0.0.0.0/0 минус 127.0.0.1/32
func allowedIPsExcludingLoopback() []conf.IPCidr {
	// 0.0.0.0/0 минус 127.0.0.1/32 = все подсети кроме 127.0.0.1
	subnets := []string{
		"0.0.0.0/2",
		"64.0.0.0/3",
		"96.0.0.0/4",
		"112.0.0.0/5",
		"120.0.0.0/6",
		"124.0.0.0/7",
		"126.0.0.0/8",
		"127.0.0.0/32",
		"127.0.0.2/31",
		"127.0.0.4/30",
		"127.0.0.8/29",
		"127.0.0.16/28",
		"127.0.0.32/27",
		"127.0.0.64/26",
		"127.0.0.128/25",
		"127.0.1.0/24",
		"127.0.2.0/23",
		"127.0.4.0/22",
		"127.0.8.0/21",
		"127.0.16.0/20",
		"127.0.32.0/19",
		"127.0.64.0/18",
		"127.0.128.0/17",
		"127.1.0.0/16",
		"127.2.0.0/15",
		"127.4.0.0/14",
		"127.8.0.0/13",
		"127.16.0.0/12",
		"127.32.0.0/11",
		"127.64.0.0/10",
		"127.128.0.0/9",
		"128.0.0.0/1",
	}

	result := make([]conf.IPCidr, 0, len(subnets))
	for _, s := range subnets {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		result = append(result, conf.IPCidr{
			IP:   ipnet.IP,
			Cidr: uint8(ones),
		})
	}
	return result
}
