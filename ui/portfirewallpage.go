package ui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/lxn/walk"
	"github.com/lxn/win"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

type PortFirewallPage struct {
	*walk.TabPage

	modeGroup   *walk.GroupBox
	modeOff     *walk.RadioButton
	modeWhite   *walk.RadioButton
	modeBlack   *walk.RadioButton
	statusLabel *walk.TextLabel

	rulesGroup *walk.GroupBox
	rulesEdit  *walk.TextEdit

	applyButton *walk.PushButton

	tunnelChangedCB *manager.TunnelChangeCallback

	activeTunnel string
	loading      bool

	disposeOnce sync.Once
}

func NewPortFirewallPage() (*PortFirewallPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	pfp := &PortFirewallPage{}

	if pfp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(pfp)

	pfp.SetTitle(l18n.Sprintf("Port Firewall"))
	mainLayout := walk.NewVBoxLayout()
	mainLayout.SetMargins(walk.Margins{5, 5, 5, 5})
	pfp.SetLayout(mainLayout)

	// === Mode ===
	if pfp.modeGroup, err = walk.NewGroupBox(pfp); err != nil {
		return nil, err
	}
	pfp.modeGroup.SetTitle(l18n.Sprintf("Mode"))
	modeLayout := walk.NewVBoxLayout()
	modeLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	pfp.modeGroup.SetLayout(modeLayout)

	descLabel, _ := walk.NewTextLabel(pfp.modeGroup)
	descLabel.SetText(l18n.Sprintf("Block or allow specific TCP/UDP ports for traffic on the active tunnel only. System-wide traffic outside the tunnel is not affected."))
	descLabel.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	walk.NewHSeparator(pfp.modeGroup)

	radioContainer, _ := walk.NewComposite(pfp.modeGroup)
	radioLayout := walk.NewHBoxLayout()
	radioLayout.SetMargins(walk.Margins{})
	radioContainer.SetLayout(radioLayout)

	if pfp.modeOff, err = walk.NewRadioButton(radioContainer); err != nil {
		return nil, err
	}
	pfp.modeOff.SetText(l18n.Sprintf("Off"))
	pfp.modeOff.SetToolTipText(l18n.Sprintf("Port firewall is disabled. All ports are allowed through the tunnel."))

	if pfp.modeWhite, err = walk.NewRadioButton(radioContainer); err != nil {
		return nil, err
	}
	pfp.modeWhite.SetText(l18n.Sprintf("Whitelist"))
	pfp.modeWhite.SetToolTipText(l18n.Sprintf("Only the listed ports are allowed through the tunnel, everything else is blocked."))

	if pfp.modeBlack, err = walk.NewRadioButton(radioContainer); err != nil {
		return nil, err
	}
	pfp.modeBlack.SetText(l18n.Sprintf("Blacklist"))
	pfp.modeBlack.SetToolTipText(l18n.Sprintf("The listed ports are blocked through the tunnel, everything else is allowed."))

	walk.NewHSpacer(radioContainer)

	statusContainer, _ := walk.NewComposite(pfp.modeGroup)
	statusLayout := walk.NewHBoxLayout()
	statusLayout.SetMargins(walk.Margins{0, 5, 0, 0})
	statusContainer.SetLayout(statusLayout)

	statusTitleLabel, _ := walk.NewTextLabel(statusContainer)
	statusTitleLabel.SetText(l18n.Sprintf("Status:"))

	if pfp.statusLabel, err = walk.NewTextLabel(statusContainer); err != nil {
		return nil, err
	}
	pfp.statusLabel.SetText(l18n.Sprintf("Inactive"))
	walk.NewHSpacer(statusContainer)

	// === Rules ===
	if pfp.rulesGroup, err = walk.NewGroupBox(pfp); err != nil {
		return nil, err
	}
	pfp.rulesGroup.SetTitle(l18n.Sprintf("Ports"))
	rulesLayout := walk.NewVBoxLayout()
	rulesLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	pfp.rulesGroup.SetLayout(rulesLayout)

	rulesLabel, _ := walk.NewTextLabel(pfp.rulesGroup)
	rulesLabel.SetText(l18n.Sprintf("One entry per line: a port or range, optionally prefixed with tcp: or udp: (default: both). Example: 443, 8000-8100, udp:51820-51830"))
	rulesLabel.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	if pfp.rulesEdit, err = newScrollableTextEdit(pfp.rulesGroup); err != nil {
		return nil, err
	}
	pfp.rulesEdit.SetMinMaxSize(walk.Size{0, 60}, walk.Size{0, 0})
	if err := pfp.attachTextEditContextMenu(pfp.rulesEdit); err != nil {
		return nil, err
	}
	rulesLayout.SetStretchFactor(pfp.rulesEdit, 1)

	// === Apply ===
	buttonContainer, _ := walk.NewComposite(pfp)
	buttonLayout := walk.NewHBoxLayout()
	buttonLayout.SetMargins(walk.Margins{})
	buttonContainer.SetLayout(buttonLayout)

	walk.NewHSpacer(buttonContainer)

	if pfp.applyButton, err = walk.NewPushButton(buttonContainer); err != nil {
		return nil, err
	}
	pfp.applyButton.SetText(l18n.Sprintf("Apply"))
	pfp.applyButton.SetMinMaxSize(walk.Size{100, 0}, walk.Size{0, 0})
	pfp.applyButton.Clicked().Attach(pfp.onApply)

	mainLayout.SetStretchFactor(pfp.rulesGroup, 1)

	pfp.modeOff.CheckedChanged().Attach(func() {
		if !pfp.loading {
			pfp.rulesGroup.SetEnabled(true)
		}
	})
	pfp.modeWhite.CheckedChanged().Attach(func() {
		if !pfp.loading {
			pfp.rulesGroup.SetEnabled(true)
		}
	})
	pfp.modeBlack.CheckedChanged().Attach(func() {
		if !pfp.loading {
			pfp.rulesGroup.SetEnabled(true)
		}
	})

	pfp.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(pfp.onTunnelChange)

	pfp.loadCurrentSettingsSync()

	if !IsAdmin {
		pfp.modeOff.SetEnabled(false)
		pfp.modeWhite.SetEnabled(false)
		pfp.modeBlack.SetEnabled(false)
		pfp.rulesEdit.SetReadOnly(true)
		pfp.applyButton.SetEnabled(false)
	}

	disposables.Spare()
	return pfp, nil
}

func (pfp *PortFirewallPage) Dispose() {
	pfp.disposeOnce.Do(func() {
		if pfp.tunnelChangedCB != nil {
			pfp.tunnelChangedCB.Unregister()
			pfp.tunnelChangedCB = nil
		}
	})
	pfp.TabPage.Dispose()
}

func (pfp *PortFirewallPage) loadCurrentSettingsSync() {
	data, err := manager.IPCClientPortFirewallRules()
	if err != nil {
		return
	}
	pfp.applyLoadedSettings(data)
}

func (pfp *PortFirewallPage) applyLoadedSettings(data manager.PortFirewallRulesData) {
	pfp.loading = true
	defer func() { pfp.loading = false }()

	switch strings.ToLower(strings.TrimSpace(data.Mode)) {
	case "whitelist":
		pfp.modeWhite.SetChecked(true)
	case "blacklist":
		pfp.modeBlack.SetChecked(true)
	default:
		pfp.modeOff.SetChecked(true)
	}
	pfp.rulesEdit.SetText(formatPortRulesText(data.Rules))
}

func (pfp *PortFirewallPage) onTunnelChange(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
	pfp.Form().Synchronize(func() {
		pfp.updateStatus(globalState)
	})
}

func (pfp *PortFirewallPage) updateStatus(globalState manager.TunnelState) {
	var mode string
	if pfp.modeWhite.Checked() {
		mode = l18n.Sprintf("Whitelist")
	} else if pfp.modeBlack.Checked() {
		mode = l18n.Sprintf("Blacklist")
	}

	if pfp.modeOff.Checked() {
		pfp.statusLabel.SetText(l18n.Sprintf("Disabled"))
	} else if globalState != manager.TunnelStarted {
		pfp.statusLabel.SetText(l18n.Sprintf("Waiting for tunnel connection..."))
	} else {
		pfp.statusLabel.SetText(l18n.Sprintf("Active (%s mode)", mode))
	}
}

func (pfp *PortFirewallPage) onApply() {
	var mode string
	if pfp.modeWhite.Checked() {
		mode = "whitelist"
	} else if pfp.modeBlack.Checked() {
		mode = "blacklist"
	} else {
		mode = "off"
	}

	rules, err := parsePortRulesText(pfp.rulesEdit.Text())
	if err != nil {
		showErrorCustom(pfp.Form(), l18n.Sprintf("Failed to save port firewall rules"), err.Error())
		return
	}

	if mode == "whitelist" && len(rules) == 0 {
		if walk.MsgBox(pfp.Form(), l18n.Sprintf("Port Firewall"),
			l18n.Sprintf("Whitelist mode with an empty port list blocks all ports through the tunnel. Continue?"),
			walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != win.IDYES {
			return
		}
	}

	data := manager.PortFirewallRulesData{Mode: mode, Rules: rules}

	pfp.applyButton.SetEnabled(false)
	go func() {
		retErr := manager.IPCClientSetPortFirewallRules(data)
		pfp.Form().Synchronize(func() {
			if IsAdmin {
				pfp.applyButton.SetEnabled(true)
			}
			if retErr != nil {
				showErrorCustom(pfp.Form(), l18n.Sprintf("Failed to save port firewall rules"), retErr.Error())
				return
			}
			globalState, _ := manager.IPCClientGlobalState()
			pfp.updateStatus(globalState)
			showInfoCustom(pfp.Form(), l18n.Sprintf("Port Firewall"), l18n.Sprintf("Settings saved successfully."))
		})
	}()
}

func (pfp *PortFirewallPage) attachTextEditContextMenu(edit *walk.TextEdit) error {
	contextMenu, err := walk.NewMenu()
	if err != nil {
		return err
	}
	edit.AddDisposable(contextMenu)

	cutAction := walk.NewAction()
	cutAction.SetText(l18n.Sprintf("Cu&t"))
	cutAction.Triggered().Attach(func() {
		edit.SendMessage(win.WM_CUT, 0, 0)
	})
	contextMenu.Actions().Add(cutAction)

	copyAction := walk.NewAction()
	copyAction.SetText(l18n.Sprintf("&Copy"))
	copyAction.Triggered().Attach(func() {
		edit.SendMessage(win.WM_COPY, 0, 0)
	})
	contextMenu.Actions().Add(copyAction)

	pasteAction := walk.NewAction()
	pasteAction.SetText(l18n.Sprintf("&Paste"))
	pasteAction.Triggered().Attach(func() {
		edit.SendMessage(win.WM_PASTE, 0, 0)
	})
	contextMenu.Actions().Add(pasteAction)

	deleteAction := walk.NewAction()
	deleteAction.SetText(l18n.Sprintf("&Delete"))
	deleteAction.SetShortcut(walk.Shortcut{0, walk.KeyDelete})
	deleteAction.Triggered().Attach(func() {
		edit.SendMessage(win.WM_CLEAR, 0, 0)
	})
	contextMenu.Actions().Add(deleteAction)

	contextMenu.Actions().Add(walk.NewSeparatorAction())

	selectAllAction := walk.NewAction()
	selectAllAction.SetText(l18n.Sprintf("Select &all"))
	selectAllAction.Triggered().Attach(func() {
		edit.SendMessage(win.EM_SETSEL, 0, ^uintptr(0))
	})
	contextMenu.Actions().Add(selectAllAction)

	edit.SetContextMenu(contextMenu)
	return nil
}

// parsePortRulesText parses one rule per line: "443", "8000-8100",
// "tcp:443", "udp:51820-51830". Blank lines and lines starting with # are
// ignored. Returns an error naming the offending line on malformed input.
func parsePortRulesText(text string) ([]manager.PortRule, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")

	var rules []manager.PortRule
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		proto := "both"
		if idx := strings.Index(line, ":"); idx > 0 {
			p := strings.ToLower(strings.TrimSpace(line[:idx]))
			if p == "tcp" || p == "udp" {
				proto = p
				line = strings.TrimSpace(line[idx+1:])
			}
		}

		var from, to uint64
		var err error
		if idx := strings.Index(line, "-"); idx > 0 {
			from, err = strconv.ParseUint(strings.TrimSpace(line[:idx]), 10, 16)
			if err == nil {
				to, err = strconv.ParseUint(strings.TrimSpace(line[idx+1:]), 10, 16)
			}
		} else {
			from, err = strconv.ParseUint(line, 10, 16)
			to = from
		}
		if err != nil || from == 0 || to == 0 || from > 65535 || to > 65535 || to < from {
			return nil, errors.New(l18n.Sprintf("Invalid port entry on line %d: \"%s\"", i+1, raw))
		}

		rules = append(rules, manager.PortRule{Protocol: proto, From: uint16(from), To: uint16(to)})
	}
	return rules, nil
}

func formatPortRulesText(rules []manager.PortRule) string {
	lines := make([]string, 0, len(rules))
	for _, r := range rules {
		var s string
		if r.From == r.To {
			s = strconv.Itoa(int(r.From))
		} else {
			s = fmt.Sprintf("%d-%d", r.From, r.To)
		}
		if r.Protocol == "tcp" || r.Protocol == "udp" {
			s = r.Protocol + ":" + s
		}
		lines = append(lines, s)
	}
	return strings.Join(lines, "\r\n")
}
