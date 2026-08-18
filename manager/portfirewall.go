package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type PortFirewallMode int

const (
	PortFirewallOff PortFirewallMode = iota
	PortFirewallWhitelist
	PortFirewallBlacklist
)

func (m PortFirewallMode) String() string {
	switch m {
	case PortFirewallWhitelist:
		return "whitelist"
	case PortFirewallBlacklist:
		return "blacklist"
	default:
		return "off"
	}
}

func parsePortFirewallMode(s string) PortFirewallMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "whitelist":
		return PortFirewallWhitelist
	case "blacklist":
		return PortFirewallBlacklist
	default:
		return PortFirewallOff
	}
}

// PortRule is one user-entered rule: a port or port range plus protocol.
// Protocol is "tcp", "udp", or "both".
type PortRule struct {
	Protocol string
	From     uint16
	To       uint16
}

// PortFirewallRulesData is the IPC/config transfer shape.
type PortFirewallRulesData struct {
	Mode  string
	Rules []PortRule
}

type portFirewallConfig struct {
	Mode  string     `json:"mode"`
	Rules []PortRule `json:"rules"`
}

// portFirewallManager blocks/allows TCP/UDP ports for traffic on the
// currently active tunnel's network adapter only, using Windows Firewall
// rules (via PowerShell's NetSecurity module) scoped by -InterfaceAlias.
//
// Only Block rules are ever created: Windows Firewall always lets an
// explicit block win over an explicit allow regardless of rule order or
// specificity, so a naive "block all, allow some" whitelist would never let
// the allowed ports through. Whitelist mode is therefore implemented as
// blocking the complement of the allowed ranges.
type portFirewallManager struct {
	mu sync.Mutex

	mode  PortFirewallMode
	rules []PortRule

	config     portFirewallConfig
	configPath string

	activeTunnel string
}

var portFirewall = &portFirewallManager{}

func InitPortFirewall() error {
	return portFirewall.init()
}

func (m *portFirewallManager) init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.configPath = portFirewallConfigPath()
	if err := m.loadConfigLocked(); err != nil {
		log.Printf("port firewall: failed to load config: %v", err)
	}

	// Windows Firewall rules persist across process crashes/reboots, unlike
	// routes; sweep any leftovers from a previous run before applying the
	// current config to whatever tunnel activates next.
	removeAllPortFirewallRules()
	return nil
}

func (m *portFirewallManager) OnTunnelStateChange(name string, state TunnelState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch state {
	case TunnelStarted:
		m.activeTunnel = name
		if err := m.applyRulesLocked(); err != nil {
			log.Printf("port firewall: failed to apply rules for tunnel %s: %v", name, err)
		}
	case TunnelStopped:
		if m.activeTunnel == name {
			removePortFirewallRulesForTunnel(name)
			m.activeTunnel = ""
		}
	}
}

func (m *portFirewallManager) GetRules() PortFirewallRulesData {
	m.mu.Lock()
	defer m.mu.Unlock()
	return PortFirewallRulesData{
		Mode:  m.mode.String(),
		Rules: append([]PortRule(nil), m.rules...),
	}
}

func (m *portFirewallManager) SetRules(data PortFirewallRulesData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mode = parsePortFirewallMode(data.Mode)
	m.rules = normalizePortRules(data.Rules)
	m.config.Mode = m.mode.String()
	m.config.Rules = m.rules
	if err := m.saveConfigLocked(); err != nil {
		return err
	}
	return m.applyRulesLocked()
}

func (m *portFirewallManager) loadConfigLocked() error {
	cfg := portFirewallConfig{Mode: PortFirewallOff.String()}
	if data, err := os.ReadFile(m.configPath); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	m.config = cfg
	m.mode = parsePortFirewallMode(cfg.Mode)
	m.rules = normalizePortRules(cfg.Rules)
	return nil
}

func (m *portFirewallManager) saveConfigLocked() error {
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
	return os.WriteFile(m.configPath, data, 0644)
}

func portFirewallConfigPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "AmneziaWG", "port-firewall.json")
}

func normalizePortRules(rules []PortRule) []PortRule {
	out := make([]PortRule, 0, len(rules))
	for _, r := range rules {
		proto := strings.ToLower(strings.TrimSpace(r.Protocol))
		if proto != "tcp" && proto != "udp" {
			proto = "both"
		}
		from, to := r.From, r.To
		if from == 0 {
			from = 1
		}
		if to == 0 {
			to = from
		}
		if to < from {
			from, to = to, from
		}
		out = append(out, PortRule{Protocol: proto, From: from, To: to})
	}
	return out
}

type portRange struct{ from, to int }

func mergeRanges(ranges []portRange) []portRange {
	if len(ranges) == 0 {
		return nil
	}
	sorted := append([]portRange(nil), ranges...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].from < sorted[j].from })
	merged := []portRange{sorted[0]}
	for _, r := range sorted[1:] {
		last := &merged[len(merged)-1]
		if r.from <= last.to+1 {
			if r.to > last.to {
				last.to = r.to
			}
		} else {
			merged = append(merged, r)
		}
	}
	return merged
}

// complementRanges returns the gaps of [1, 65535] not covered by ranges.
func complementRanges(ranges []portRange) []portRange {
	merged := mergeRanges(ranges)
	var out []portRange
	cursor := 1
	for _, r := range merged {
		if r.from > cursor {
			out = append(out, portRange{cursor, r.from - 1})
		}
		if r.to+1 > cursor {
			cursor = r.to + 1
		}
	}
	if cursor <= 65535 {
		out = append(out, portRange{cursor, 65535})
	}
	return out
}

// effectiveBlockRangesLocked computes which port ranges must be blocked, per
// protocol, to realize the current mode. Off returns nothing to block.
func (m *portFirewallManager) effectiveBlockRangesLocked() map[string][]portRange {
	var tcp, udp []portRange
	for _, r := range m.rules {
		pr := portRange{int(r.From), int(r.To)}
		if r.Protocol == "tcp" || r.Protocol == "both" {
			tcp = append(tcp, pr)
		}
		if r.Protocol == "udp" || r.Protocol == "both" {
			udp = append(udp, pr)
		}
	}

	switch m.mode {
	case PortFirewallBlacklist:
		return map[string][]portRange{"TCP": mergeRanges(tcp), "UDP": mergeRanges(udp)}
	case PortFirewallWhitelist:
		return map[string][]portRange{"TCP": complementRanges(tcp), "UDP": complementRanges(udp)}
	default:
		return nil
	}
}

func (m *portFirewallManager) applyRulesLocked() error {
	if m.activeTunnel == "" {
		return nil
	}

	group := portFirewallGroupName(m.activeTunnel)
	var script strings.Builder
	fmt.Fprintf(&script, "$ErrorActionPreference = 'SilentlyContinue'; Get-NetFirewallRule | Where-Object { $_.Group -eq %s } | Remove-NetFirewallRule; ", psQuote(group))

	if m.mode != PortFirewallOff {
		ranges := m.effectiveBlockRangesLocked()
		alias := psQuote(m.activeTunnel)
		for _, proto := range []string{"TCP", "UDP"} {
			rs := ranges[proto]
			if len(rs) == 0 {
				continue
			}
			portTokens := make([]string, len(rs))
			for i, r := range rs {
				if r.from == r.to {
					portTokens[i] = psQuote(fmt.Sprintf("%d", r.from))
				} else {
					portTokens[i] = psQuote(fmt.Sprintf("%d-%d", r.from, r.to))
				}
			}
			display := psQuote(fmt.Sprintf("AmneziaWG port firewall (%s, %s)", m.activeTunnel, proto))
			portArray := "@(" + strings.Join(portTokens, ",") + ")"
			fmt.Fprintf(&script,
				"New-NetFirewallRule -DisplayName %s -Group %s -Direction Outbound -Action Block -Protocol %s -RemotePort %s -InterfaceAlias %s -Profile Any | Out-Null; ",
				display, psQuote(group), proto, portArray, alias)
		}
	}

	return runPowerShell(script.String())
}

func removePortFirewallRulesForTunnel(name string) {
	group := portFirewallGroupName(name)
	script := fmt.Sprintf("$ErrorActionPreference = 'SilentlyContinue'; Get-NetFirewallRule | Where-Object { $_.Group -eq %s } | Remove-NetFirewallRule", psQuote(group))
	if err := runPowerShell(script); err != nil {
		log.Printf("port firewall: failed to remove rules for tunnel %s: %v", name, err)
	}
}

func removeAllPortFirewallRules() {
	script := "$ErrorActionPreference = 'SilentlyContinue'; Get-NetFirewallRule | Where-Object { $_.Group -like 'AmneziaWG-PortFW-*' } | Remove-NetFirewallRule"
	if err := runPowerShell(script); err != nil {
		log.Printf("port firewall: startup cleanup failed: %v", err)
	}
}

func portFirewallGroupName(tunnel string) string {
	return "AmneziaWG-PortFW-" + tunnel
}

// psQuote wraps s in a PowerShell single-quoted string literal, escaping any
// embedded single quotes. Values built into a -Command script must always go
// through this — never be concatenated as a bare/double-quoted string — since
// tunnel names are user-controlled.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func runPowerShell(script string) error {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
