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

	modeGroup    *walk.GroupBox
	modeOff      *walk.RadioButton
	modeRelaxed  *walk.RadioButton
	modeStrict   *walk.RadioButton
	statusLabel  *walk.TextLabel

	// Исключить loopback из туннеля
	excludeLoopbackCheck *walk.CheckBox

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

	// Загрузка текущих настроек
	drp.loadCurrentSettings()

	// Отключение редактирования для не-админов
	if !IsAdmin {
		drp.modeOff.SetEnabled(false)
		drp.modeRelaxed.SetEnabled(false)
		drp.modeStrict.SetEnabled(false)
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
	mode, err := manager.IPCClientDomainRoutingMode()
	if err != nil {
		mode = manager.DomainRoutingOff
	}
	drp.setModeUI(mode)

	// Загружаем настройку excludeLoopback
	excludeLoopback, err := manager.IPCClientDomainRoutingExcludeLoopback()
	if err == nil {
		drp.excludeLoopbackCheck.SetChecked(excludeLoopback)
	} else {
		drp.excludeLoopbackCheck.SetChecked(true) // По умолчанию включено
	}

	rules, err := manager.IPCClientDomainRoutingRules()
	if err == nil {
		drp.domainsEdit.SetText(strings.Join(rules.Domains, "\r\n"))
		drp.tunnelDomainsEdit.SetText(strings.Join(rules.Tunnel, "\r\n"))
		drp.directDomainsEdit.SetText(strings.Join(rules.Direct, "\r\n"))
		drp.setListModeUI(rules.ListMode)
	} else {
		// По умолчанию Advanced режим
		drp.setListModeUI("disabled")
	}

	drp.updateStatus()
}

func (drp *DomainRoutingPage) setModeUI(mode manager.DomainRoutingMode) {
	drp.modeOff.SetChecked(mode == manager.DomainRoutingOff)
	drp.modeRelaxed.SetChecked(mode == manager.DomainRoutingRelaxed)
	drp.modeStrict.SetChecked(mode == manager.DomainRoutingStrict)
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
	if err := manager.IPCClientSetDomainRoutingMode(mode); err != nil {
		showErrorCustom(drp.Form(), l18n.Sprintf("Failed to set routing mode"), err.Error())
		drp.loadCurrentSettings()
		return
	}
	drp.updateStatus()
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

	if err := manager.IPCClientSetDomainRoutingRules(rules); err != nil {
		showErrorCustom(drp.Form(), l18n.Sprintf("Failed to save rules"), err.Error())
		return
	}

	showInfoCustom(drp.Form(), l18n.Sprintf("Domain Routing"), l18n.Sprintf("Rules saved successfully."))
}

func (drp *DomainRoutingPage) onTunnelChange(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
	drp.Form().Synchronize(func() {
		drp.updateStatus()
	})
}

func (drp *DomainRoutingPage) updateStatus() {
	mode, _ := manager.IPCClientDomainRoutingMode()
	globalState, _ := manager.IPCClientGlobalState()

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
	lines := strings.Split(text, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.ReplaceAll(line, "\r", "")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, line)
	}
	return result
}

func showInfoCustom(owner walk.Form, title, message string) {
	walk.MsgBox(owner, title, message, walk.MsgBoxIconInformation)
}
