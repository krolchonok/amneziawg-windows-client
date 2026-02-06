/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strings"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

type DomainRoutingPage struct {
	*walk.TabPage

	modeGroup   *walk.GroupBox
	modeOff     *walk.RadioButton
	modeRelaxed *walk.RadioButton
	modeStrict  *walk.RadioButton
	modeDNSOnly *walk.RadioButton
	statusLabel *walk.TextLabel

	// Исключить loopback из туннеля
	excludeLoopbackCheck *walk.CheckBox

	// DNS lookup settings
	dnsGroup        *walk.GroupBox
	dnsServersLabel *walk.TextLabel
	dnsServersEdit  *walk.TextEdit
	dnsRouteDirect  *walk.RadioButton
	dnsRouteTunnel  *walk.RadioButton

	// Режим списка (whitelist/blacklist/advanced)
	listModeGroup     *walk.GroupBox
	listModeWhitelist *walk.RadioButton
	listModeBlacklist *walk.RadioButton
	listModeAdvanced  *walk.RadioButton

	// Домены для whitelist/blacklist
	domainsGroup *walk.GroupBox
	domainsLabel *walk.TextLabel
	domainsEdit  *walk.TextEdit

	// Расширенный режим (tunnel/direct)
	advancedGroup     *walk.GroupBox
	tunnelDomainsEdit *walk.TextEdit
	directDomainsEdit *walk.TextEdit

	applyButton *walk.PushButton

	tunnelChangedCB *manager.TunnelChangeCallback
}

func NewDomainRoutingPage() (*DomainRoutingPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	drp := &DomainRoutingPage{}

	if drp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(drp)

	drp.SetTitle(l18n.Sprintf("Domain Routing"))
	drp.SetLayout(walk.NewVBoxLayout())

	// Группа выбора режима
	if drp.modeGroup, err = walk.NewGroupBox(drp); err != nil {
		return nil, err
	}
	drp.modeGroup.SetTitle(l18n.Sprintf("Routing Mode"))
	modeLayout := walk.NewVBoxLayout()
	modeLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	drp.modeGroup.SetLayout(modeLayout)

	// Описание режимов
	descLabel, _ := walk.NewTextLabel(drp.modeGroup)
	descLabel.SetText(l18n.Sprintf("Domain routing allows you to route traffic based on domain names. DNS requests are intercepted and routes are added automatically."))
	descLabel.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	walk.NewVSeparator(drp.modeGroup)

	// Radio buttons для выбора режима
	radioContainer, _ := walk.NewComposite(drp.modeGroup)
	radioLayout := walk.NewHBoxLayout()
	radioLayout.SetMargins(walk.Margins{})
	radioContainer.SetLayout(radioLayout)

	if drp.modeOff, err = walk.NewRadioButton(radioContainer); err != nil {
		return nil, err
	}
	drp.modeOff.SetText(l18n.Sprintf("Off"))
	drp.modeOff.SetToolTipText(l18n.Sprintf("Domain routing is disabled. All traffic goes through the tunnel as configured."))

	if drp.modeRelaxed, err = walk.NewRadioButton(radioContainer); err != nil {
		return nil, err
	}
	drp.modeRelaxed.SetText(l18n.Sprintf("Relaxed"))
	drp.modeRelaxed.SetToolTipText(l18n.Sprintf("Routes are added for matching domains. If route cannot be added, traffic still flows."))

	if drp.modeStrict, err = walk.NewRadioButton(radioContainer); err != nil {
		return nil, err
	}
	drp.modeStrict.SetText(l18n.Sprintf("Strict"))
	drp.modeStrict.SetToolTipText(l18n.Sprintf("Routes are added for matching domains. If route cannot be added, DNS query fails."))

	if drp.modeDNSOnly, err = walk.NewRadioButton(radioContainer); err != nil {
		return nil, err
	}
	drp.modeDNSOnly.SetText(l18n.Sprintf("DNS Only"))
	drp.modeDNSOnly.SetToolTipText(l18n.Sprintf("DNS proxy only. Traffic goes directly without tunnel routing."))

	walk.NewHSpacer(radioContainer)

	// Статус
	statusContainer, _ := walk.NewComposite(drp.modeGroup)
	statusLayout := walk.NewHBoxLayout()
	statusLayout.SetMargins(walk.Margins{0, 5, 0, 0})
	statusContainer.SetLayout(statusLayout)

	statusTitleLabel, _ := walk.NewTextLabel(statusContainer)
	statusTitleLabel.SetText(l18n.Sprintf("Status:"))

	if drp.statusLabel, err = walk.NewTextLabel(statusContainer); err != nil {
		return nil, err
	}
	drp.statusLabel.SetText(l18n.Sprintf("Inactive"))
	walk.NewHSpacer(statusContainer)

	// Галочка для исключения loopback
	loopbackContainer, _ := walk.NewComposite(drp.modeGroup)
	loopbackLayout := walk.NewHBoxLayout()
	loopbackLayout.SetMargins(walk.Margins{0, 5, 0, 0})
	loopbackContainer.SetLayout(loopbackLayout)

	if drp.excludeLoopbackCheck, err = walk.NewCheckBox(loopbackContainer); err != nil {
		return nil, err
	}
	drp.excludeLoopbackCheck.SetText(l18n.Sprintf("Exclude localhost from tunnel (required for DNS proxy)"))
	drp.excludeLoopbackCheck.SetToolTipText(l18n.Sprintf("When enabled, adds a route to prevent 127.0.0.1 traffic from going through the tunnel. Required when using AllowedIPs = 0.0.0.0/0"))
	drp.excludeLoopbackCheck.CheckedChanged().Attach(func() {
		exclude := drp.excludeLoopbackCheck.Checked()
		go manager.IPCClientSetDomainRoutingExcludeLoopback(exclude)
	})
	walk.NewHSpacer(loopbackContainer)

	// === DNS lookup settings ===
	if drp.dnsGroup, err = walk.NewGroupBox(drp); err != nil {
		return nil, err
	}
	drp.dnsGroup.SetTitle(l18n.Sprintf("DNS Lookup"))
	dnsLayout := walk.NewVBoxLayout()
	dnsLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	drp.dnsGroup.SetLayout(dnsLayout)

	if drp.dnsServersLabel, err = walk.NewTextLabel(drp.dnsGroup); err != nil {
		return nil, err
	}
	drp.dnsServersLabel.SetText(l18n.Sprintf("DNS servers for lookup (one per line, IP or IP:port). Empty uses system/tunnel DNS."))

	if drp.dnsServersEdit, err = walk.NewTextEdit(drp.dnsGroup); err != nil {
		return nil, err
	}
	drp.dnsServersEdit.SetMinMaxSize(walk.Size{0, 60}, walk.Size{0, 120})

	dnsRouteContainer, _ := walk.NewComposite(drp.dnsGroup)
	dnsRouteLayout := walk.NewHBoxLayout()
	dnsRouteLayout.SetMargins(walk.Margins{})
	dnsRouteContainer.SetLayout(dnsRouteLayout)

	if drp.dnsRouteDirect, err = walk.NewRadioButton(dnsRouteContainer); err != nil {
		return nil, err
	}
	drp.dnsRouteDirect.SetText(l18n.Sprintf("Send DNS directly (bypass tunnel)"))
	drp.dnsRouteDirect.SetToolTipText(l18n.Sprintf("Bind DNS queries to the physical interface when the tunnel is active."))

	if drp.dnsRouteTunnel, err = walk.NewRadioButton(dnsRouteContainer); err != nil {
		return nil, err
	}
	drp.dnsRouteTunnel.SetText(l18n.Sprintf("Send DNS through tunnel"))
	drp.dnsRouteTunnel.SetToolTipText(l18n.Sprintf("Bind DNS queries to the tunnel interface when the tunnel is active."))

	walk.NewHSpacer(dnsRouteContainer)

	// === Группа выбора режима списка ===
	if drp.listModeGroup, err = walk.NewGroupBox(drp); err != nil {
		return nil, err
	}
	drp.listModeGroup.SetTitle(l18n.Sprintf("List Mode"))
	listModeLayout := walk.NewVBoxLayout()
	listModeLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	drp.listModeGroup.SetLayout(listModeLayout)

	listModeRadioContainer, _ := walk.NewComposite(drp.listModeGroup)
	listModeRadioLayout := walk.NewHBoxLayout()
	listModeRadioLayout.SetMargins(walk.Margins{})
	listModeRadioContainer.SetLayout(listModeRadioLayout)

	if drp.listModeWhitelist, err = walk.NewRadioButton(listModeRadioContainer); err != nil {
		return nil, err
	}
	drp.listModeWhitelist.SetText(l18n.Sprintf("Whitelist"))
	drp.listModeWhitelist.SetToolTipText(l18n.Sprintf("Only listed domains go through tunnel, everything else is direct"))

	if drp.listModeBlacklist, err = walk.NewRadioButton(listModeRadioContainer); err != nil {
		return nil, err
	}
	drp.listModeBlacklist.SetText(l18n.Sprintf("Blacklist"))
	drp.listModeBlacklist.SetToolTipText(l18n.Sprintf("Everything goes through tunnel, except listed domains"))

	if drp.listModeAdvanced, err = walk.NewRadioButton(listModeRadioContainer); err != nil {
		return nil, err
	}
	drp.listModeAdvanced.SetText(l18n.Sprintf("Advanced"))
	drp.listModeAdvanced.SetToolTipText(l18n.Sprintf("Use separate tunnel and direct domain lists"))

	walk.NewHSpacer(listModeRadioContainer)

	// === Группа доменов для whitelist/blacklist ===
	if drp.domainsGroup, err = walk.NewGroupBox(drp); err != nil {
		return nil, err
	}
	drp.domainsGroup.SetTitle(l18n.Sprintf("Domains"))
	domainsLayout := walk.NewVBoxLayout()
	domainsLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	drp.domainsGroup.SetLayout(domainsLayout)

	if drp.domainsLabel, err = walk.NewTextLabel(drp.domainsGroup); err != nil {
		return nil, err
	}
	drp.domainsLabel.SetText(l18n.Sprintf("Domains (one per line):"))

	if drp.domainsEdit, err = walk.NewTextEdit(drp.domainsGroup); err != nil {
		return nil, err
	}
	drp.domainsEdit.SetMinMaxSize(walk.Size{0, 100}, walk.Size{0, 200})

	// Пример для whitelist/blacklist
	domainsExampleLabel, _ := walk.NewTextLabel(drp.domainsGroup)
	domainsExampleLabel.SetText(l18n.Sprintf("Example: google.com (matches google.com and *.google.com)"))
	domainsExampleLabel.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	// === Группа расширенных правил (tunnel/direct) ===
	if drp.advancedGroup, err = walk.NewGroupBox(drp); err != nil {
		return nil, err
	}
	drp.advancedGroup.SetTitle(l18n.Sprintf("Domain Rules (Advanced)"))
	advancedLayout := walk.NewVBoxLayout()
	advancedLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	drp.advancedGroup.SetLayout(advancedLayout)

	// Tunnel domains
	tunnelLabel, _ := walk.NewTextLabel(drp.advancedGroup)
	tunnelLabel.SetText(l18n.Sprintf("Domains to route through tunnel (one per line):"))

	if drp.tunnelDomainsEdit, err = walk.NewTextEdit(drp.advancedGroup); err != nil {
		return nil, err
	}
	drp.tunnelDomainsEdit.SetMinMaxSize(walk.Size{0, 60}, walk.Size{0, 100})

	// Direct domains
	directLabel, _ := walk.NewTextLabel(drp.advancedGroup)
	directLabel.SetText(l18n.Sprintf("Domains to route directly (bypass tunnel, one per line):"))

	if drp.directDomainsEdit, err = walk.NewTextEdit(drp.advancedGroup); err != nil {
		return nil, err
	}
	drp.directDomainsEdit.SetMinMaxSize(walk.Size{0, 60}, walk.Size{0, 100})

	// Пример
	exampleLabel, _ := walk.NewTextLabel(drp.advancedGroup)
	exampleLabel.SetText(l18n.Sprintf("Example: google.com (matches google.com and *.google.com)"))
	exampleLabel.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	// Кнопка применения
	buttonContainer, _ := walk.NewComposite(drp)
	buttonLayout := walk.NewHBoxLayout()
	buttonLayout.SetMargins(walk.Margins{})
	buttonContainer.SetLayout(buttonLayout)

	walk.NewHSpacer(buttonContainer)

	if drp.applyButton, err = walk.NewPushButton(buttonContainer); err != nil {
		return nil, err
	}
	drp.applyButton.SetText(l18n.Sprintf("Apply"))
	drp.applyButton.SetMinMaxSize(walk.Size{100, 0}, walk.Size{100, 0})
	drp.applyButton.Clicked().Attach(drp.onApply)

	walk.NewVSpacer(drp)

	// Установка обработчиков radio buttons
	drp.modeOff.CheckedChanged().Attach(func() {
		if drp.modeOff.Checked() {
			drp.onModeChanged(manager.DomainRoutingOff)
		}
	})
	drp.modeRelaxed.CheckedChanged().Attach(func() {
		if drp.modeRelaxed.Checked() {
			drp.onModeChanged(manager.DomainRoutingRelaxed)
		}
	})
	drp.modeStrict.CheckedChanged().Attach(func() {
		if drp.modeStrict.Checked() {
			drp.onModeChanged(manager.DomainRoutingStrict)
		}
	})
	drp.modeDNSOnly.CheckedChanged().Attach(func() {
		if drp.modeDNSOnly.Checked() {
			drp.onModeChanged(manager.DomainRoutingDNSOnly)
		}
	})

	// Обработчики для режима списка
	drp.listModeWhitelist.CheckedChanged().Attach(func() {
		if drp.listModeWhitelist.Checked() {
			drp.updateListModeUI("whitelist")
		}
	})
	drp.listModeBlacklist.CheckedChanged().Attach(func() {
		if drp.listModeBlacklist.Checked() {
			drp.updateListModeUI("blacklist")
		}
	})
	drp.listModeAdvanced.CheckedChanged().Attach(func() {
		if drp.listModeAdvanced.Checked() {
			drp.updateListModeUI("disabled")
		}
	})

	// Регистрация callback для обновления статуса
	drp.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(drp.onTunnelChange)

	// Синхронная начальная загрузка (в конструкторе Form() ещё не доступна)
	drp.loadCurrentSettingsSync()

	// Отключение редактирования для не-админов
	if !IsAdmin {
		drp.modeOff.SetEnabled(false)
		drp.modeRelaxed.SetEnabled(false)
		drp.modeStrict.SetEnabled(false)
		drp.modeDNSOnly.SetEnabled(false)
		drp.dnsServersEdit.SetReadOnly(true)
		drp.dnsRouteDirect.SetEnabled(false)
		drp.dnsRouteTunnel.SetEnabled(false)
		drp.listModeWhitelist.SetEnabled(false)
		drp.listModeBlacklist.SetEnabled(false)
		drp.listModeAdvanced.SetEnabled(false)
		drp.domainsEdit.SetReadOnly(true)
		drp.tunnelDomainsEdit.SetReadOnly(true)
		drp.directDomainsEdit.SetReadOnly(true)
		drp.applyButton.SetEnabled(false)
	}

	disposables.Spare()
	return drp, nil
}

func (drp *DomainRoutingPage) Dispose() {
	if drp.tunnelChangedCB != nil {
		drp.tunnelChangedCB.Unregister()
		drp.tunnelChangedCB = nil
	}
	drp.TabPage.Dispose()
}

func (drp *DomainRoutingPage) loadCurrentSettings() {
	go func() {
		mode, modeErr := manager.IPCClientDomainRoutingMode()
		excludeLoopback, exclErr := manager.IPCClientDomainRoutingExcludeLoopback()
		rules, rulesErr := manager.IPCClientDomainRoutingRules()
		settings, settingsErr := manager.IPCClientDomainRoutingDNSSettings()
		globalState, _ := manager.IPCClientGlobalState()

		drp.Form().Synchronize(func() {
			drp.applyLoadedSettings(mode, modeErr, excludeLoopback, exclErr, rules, rulesErr, settings, settingsErr, globalState)
		})
	}()
}

// loadCurrentSettingsSync выполняет загрузку синхронно (для использования в конструкторе)
func (drp *DomainRoutingPage) loadCurrentSettingsSync() {
	mode, modeErr := manager.IPCClientDomainRoutingMode()
	excludeLoopback, exclErr := manager.IPCClientDomainRoutingExcludeLoopback()
	rules, rulesErr := manager.IPCClientDomainRoutingRules()
	settings, settingsErr := manager.IPCClientDomainRoutingDNSSettings()
	globalState, _ := manager.IPCClientGlobalState()

	drp.applyLoadedSettings(mode, modeErr, excludeLoopback, exclErr, rules, rulesErr, settings, settingsErr, globalState)
}

func (drp *DomainRoutingPage) applyLoadedSettings(
	mode manager.DomainRoutingMode, modeErr error,
	excludeLoopback bool, exclErr error,
	rules manager.DomainRoutingRulesData, rulesErr error,
	settings manager.DomainRoutingDNSSettings, settingsErr error,
	globalState manager.TunnelState,
) {
	if modeErr != nil {
		mode = manager.DomainRoutingOff
	}
	drp.setModeUI(mode)

	if exclErr == nil {
		drp.excludeLoopbackCheck.SetChecked(excludeLoopback)
	} else {
		drp.excludeLoopbackCheck.SetChecked(true)
	}

	if rulesErr == nil {
		drp.domainsEdit.SetText(strings.Join(rules.Domains, "\r\n"))
		drp.tunnelDomainsEdit.SetText(strings.Join(rules.Tunnel, "\r\n"))
		drp.directDomainsEdit.SetText(strings.Join(rules.Direct, "\r\n"))
		drp.setListModeUI(rules.ListMode)
	} else {
		drp.setListModeUI("disabled")
	}

	if settingsErr == nil {
		drp.dnsServersEdit.SetText(strings.Join(settings.Upstreams, "\r\n"))
		drp.setDNSRouteModeUI(settings.RouteMode)
	} else {
		drp.setDNSRouteModeUI("direct")
	}

	drp.updateStatusFromState(mode, globalState)
}

func (drp *DomainRoutingPage) setModeUI(mode manager.DomainRoutingMode) {
	drp.modeOff.SetChecked(mode == manager.DomainRoutingOff)
	drp.modeRelaxed.SetChecked(mode == manager.DomainRoutingRelaxed)
	drp.modeStrict.SetChecked(mode == manager.DomainRoutingStrict)
	drp.modeDNSOnly.SetChecked(mode == manager.DomainRoutingDNSOnly)
}

func (drp *DomainRoutingPage) setListModeUI(listMode string) {
	switch listMode {
	case "whitelist":
		drp.listModeWhitelist.SetChecked(true)
	case "blacklist":
		drp.listModeBlacklist.SetChecked(true)
	default:
		drp.listModeAdvanced.SetChecked(true)
	}
	drp.updateListModeUI(listMode)
}

func (drp *DomainRoutingPage) setDNSRouteModeUI(routeMode string) {
	switch strings.ToLower(strings.TrimSpace(routeMode)) {
	case "tunnel":
		drp.dnsRouteTunnel.SetChecked(true)
	default:
		drp.dnsRouteDirect.SetChecked(true)
	}
}

func (drp *DomainRoutingPage) updateListModeUI(listMode string) {
	switch listMode {
	case "whitelist":
		drp.domainsLabel.SetText(l18n.Sprintf("Domains to route through TUNNEL (one per line):"))
		drp.domainsGroup.SetVisible(true)
		drp.advancedGroup.SetVisible(false)
	case "blacklist":
		drp.domainsLabel.SetText(l18n.Sprintf("Domains to route DIRECTLY (one per line):"))
		drp.domainsGroup.SetVisible(true)
		drp.advancedGroup.SetVisible(false)
	default:
		drp.domainsGroup.SetVisible(false)
		drp.advancedGroup.SetVisible(true)
	}
}

func (drp *DomainRoutingPage) onModeChanged(mode manager.DomainRoutingMode) {
	drp.setControlsEnabled(false)
	go func() {
		err := manager.IPCClientSetDomainRoutingMode(mode)
		drp.Form().Synchronize(func() {
			drp.setControlsEnabled(true)
			if err != nil {
				showErrorCustom(drp.Form(), l18n.Sprintf("Failed to set routing mode"), err.Error())
				drp.loadCurrentSettings()
				return
			}
			drp.updateStatus()
		})
	}()
}

func (drp *DomainRoutingPage) setControlsEnabled(enabled bool) {
	if !IsAdmin {
		return
	}
	drp.applyButton.SetEnabled(enabled)
	drp.modeOff.SetEnabled(enabled)
	drp.modeRelaxed.SetEnabled(enabled)
	drp.modeStrict.SetEnabled(enabled)
	drp.modeDNSOnly.SetEnabled(enabled)
}

func (drp *DomainRoutingPage) onApply() {
	var listMode string
	if drp.listModeWhitelist.Checked() {
		listMode = "whitelist"
	} else if drp.listModeBlacklist.Checked() {
		listMode = "blacklist"
	} else {
		listMode = "disabled"
	}

	rules := manager.DomainRoutingRulesData{
		ListMode: listMode,
		Domains:  parseDomainsText(drp.domainsEdit.Text()),
		Tunnel:   parseDomainsText(drp.tunnelDomainsEdit.Text()),
		Direct:   parseDomainsText(drp.directDomainsEdit.Text()),
	}

	settings := manager.DomainRoutingDNSSettings{
		Upstreams: parseDNSServersText(drp.dnsServersEdit.Text()),
		RouteMode: drp.dnsRouteModeValue(),
	}

	drp.setControlsEnabled(false)
	go func() {
		var rulesErr, dnsErr error
		rulesErr = manager.IPCClientSetDomainRoutingRules(rules)
		if rulesErr == nil {
			dnsErr = manager.IPCClientSetDomainRoutingDNSSettings(settings)
		}
		drp.Form().Synchronize(func() {
			drp.setControlsEnabled(true)
			if rulesErr != nil {
				showErrorCustom(drp.Form(), l18n.Sprintf("Failed to save rules"), rulesErr.Error())
				return
			}
			if dnsErr != nil {
				showErrorCustom(drp.Form(), l18n.Sprintf("Failed to save DNS settings"), dnsErr.Error())
				return
			}
			showInfoCustom(drp.Form(), l18n.Sprintf("Domain Routing"), l18n.Sprintf("Settings saved successfully."))
		})
	}()
}

func (drp *DomainRoutingPage) onTunnelChange(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
	drp.Form().Synchronize(func() {
		drp.updateStatus()
	})
}

func (drp *DomainRoutingPage) updateStatus() {
	go func() {
		mode, _ := manager.IPCClientDomainRoutingMode()
		globalState, _ := manager.IPCClientGlobalState()
		drp.Form().Synchronize(func() {
			drp.updateStatusFromState(mode, globalState)
		})
	}()
}

func (drp *DomainRoutingPage) updateStatusFromState(mode manager.DomainRoutingMode, globalState manager.TunnelState) {
	var statusText string
	if mode == manager.DomainRoutingOff {
		statusText = l18n.Sprintf("Disabled")
	} else if globalState != manager.TunnelStarted {
		statusText = l18n.Sprintf("Waiting for tunnel connection...")
	} else {
		modeStr := "Relaxed"
		if mode == manager.DomainRoutingStrict {
			modeStr = "Strict"
		}
		statusText = l18n.Sprintf("Active (%s mode)", modeStr)
	}
	drp.statusLabel.SetText(statusText)
}

func parseDomainsText(text string) []string {
	// Нормализуем: разбиваем по переносам, запятым, точкам с запятой, табам, пробелам
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.ReplaceAll(text, ",", "\n")
	text = strings.ReplaceAll(text, ";", "\n")
	text = strings.ReplaceAll(text, "\t", "\n")
	// Пробелы — разделители только если нет точки рядом (чтобы не ломать домены)
	// Простая эвристика: если пробел окружён непробельными символами — разделитель
	text = strings.ReplaceAll(text, " ", "\n")

	lines := strings.Split(text, "\n")
	seen := make(map[string]bool, len(lines))
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Убираем возможные обрамления
		line = strings.Trim(line, "\"'")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Убираем wildcard-префикс, если пользователь его добавил
		line = strings.TrimPrefix(line, "*.")
		line = strings.ToLower(line)
		// Убираем trailing dot
		line = strings.TrimSuffix(line, ".")
		if line == "" {
			continue
		}
		// Дедупликация
		if seen[line] {
			continue
		}
		seen[line] = true
		result = append(result, line)
	}
	return result
}

func parseDNSServersText(text string) []string {
	lines := strings.Split(text, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.ReplaceAll(line, "\r", "")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			result = append(result, part)
		}
	}
	return result
}

func (drp *DomainRoutingPage) dnsRouteModeValue() string {
	if drp.dnsRouteTunnel.Checked() {
		return "tunnel"
	}
	return "direct"
}

func showInfoCustom(owner walk.Form, title, message string) {
	walk.MsgBox(owner, title, message, walk.MsgBoxIconInformation)
}
