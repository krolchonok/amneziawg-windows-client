/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"os/exec"
	"strings"
	"sort"
	"sync"
	"time"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

type DNSLogPage struct {
	*walk.TabPage

	logView       *walk.TableView
	logModel      *dnsLogModel
	autoScroll    bool
	clickedIndex  int // Index of right-clicked row for context menu
	
	enabledCheck  *walk.CheckBox
	clearButton   *walk.PushButton
	flushButton   *walk.PushButton
	refreshButton *walk.PushButton
	autoScrollCheck *walk.CheckBox
	
	statsLabel    *walk.TextLabel
	
	refreshTicker *time.Ticker
	stopRefresh   chan struct{}
	disposeOnce   sync.Once
}

type dnsLogModel struct {
	walk.TableModelBase
	walk.SorterBase
	entries []manager.DNSLogEntry
}

func (m *dnsLogModel) Sort(col int, order walk.SortOrder) error {
	asc := order == walk.SortAscending
	sort.SliceStable(m.entries, func(i, j int) bool {
		a := m.entries[i]
		b := m.entries[j]
		switch col {
		case 0: // Time
			if asc {
				return a.Timestamp.Before(b.Timestamp)
			}
			return b.Timestamp.Before(a.Timestamp)
		case 1: // Domain
			if asc {
				return a.Domain < b.Domain
			}
			return b.Domain < a.Domain
		case 2: // Type
			if asc {
				return a.QueryType < b.QueryType
			}
			return b.QueryType < a.QueryType
		case 3: // Route
			if asc {
				return a.Target < b.Target
			}
			return b.Target < a.Target
		case 4: // IPs
			ai := strings.Join(a.ResponseIPs, ", ")
			bi := strings.Join(b.ResponseIPs, ", ")
			if asc {
				return ai < bi
			}
			return bi < ai
		case 5: // Latency
			if asc {
				return a.Latency < b.Latency
			}
			return b.Latency < a.Latency
		case 6: // Error
			if asc {
				return a.Error < b.Error
			}
			return b.Error < a.Error
		default:
			return false
		}
	})
	err := m.SorterBase.Sort(col, order)
	// Ensure the view is refreshed after sorting so hover/selection render correctly.
	m.PublishRowsReset()
	return err
}

func (m *dnsLogModel) RowCount() int {
	return len(m.entries)
}

func (m *dnsLogModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.entries) {
		return ""
	}
	entry := m.entries[row]
	switch col {
	case 0: // Time
		return entry.Timestamp.Format("15:04:05.000")
	case 1: // Domain
		return entry.Domain
	case 2: // Type
		return entry.QueryType
	case 3: // Route
		return entry.Target
	case 4: // IPs
		return strings.Join(entry.ResponseIPs, ", ")
	case 5: // Latency
		return fmt.Sprintf("%.1fms", float64(entry.Latency.Microseconds())/1000)
	case 6: // Error
		return entry.Error
	}
	return ""
}

func NewDNSLogPage() (*DNSLogPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	dlp := &DNSLogPage{
		autoScroll:   true,
		clickedIndex: -1,
		stopRefresh:  make(chan struct{}),
	}

	if dlp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(dlp)

	dlp.SetTitle(l18n.Sprintf("DNS Log"))
	dlp.SetLayout(walk.NewVBoxLayout())

	// Toolbar
	toolbar, _ := walk.NewComposite(dlp)
	toolbarLayout := walk.NewHBoxLayout()
	toolbarLayout.SetMargins(walk.Margins{5, 5, 5, 5})
	toolbar.SetLayout(toolbarLayout)

	if dlp.enabledCheck, err = walk.NewCheckBox(toolbar); err != nil {
		return nil, err
	}
	dlp.enabledCheck.SetText(l18n.Sprintf("Enable logging"))
	dlp.enabledCheck.SetChecked(true)
	dlp.enabledCheck.CheckedChanged().Attach(dlp.onEnabledChanged)

	if dlp.autoScrollCheck, err = walk.NewCheckBox(toolbar); err != nil {
		return nil, err
	}
	dlp.autoScrollCheck.SetText(l18n.Sprintf("Auto-scroll"))
	dlp.autoScrollCheck.SetChecked(true)
	dlp.autoScrollCheck.CheckedChanged().Attach(func() {
		dlp.autoScroll = dlp.autoScrollCheck.Checked()
	})

	walk.NewHSpacer(toolbar)

	if dlp.statsLabel, err = walk.NewTextLabel(toolbar); err != nil {
		return nil, err
	}
	dlp.statsLabel.SetText(l18n.Sprintf("Queries: %d", 0))

	walk.NewHSpacer(toolbar)

	if dlp.refreshButton, err = walk.NewPushButton(toolbar); err != nil {
		return nil, err
	}
	dlp.refreshButton.SetText(l18n.Sprintf("Refresh"))
	dlp.refreshButton.Clicked().Attach(dlp.refreshLog)

	if dlp.clearButton, err = walk.NewPushButton(toolbar); err != nil {
		return nil, err
	}
	dlp.clearButton.SetText(l18n.Sprintf("Clear"))
	dlp.clearButton.Clicked().Attach(dlp.clearLog)

	if dlp.flushButton, err = walk.NewPushButton(toolbar); err != nil {
		return nil, err
	}
	dlp.flushButton.SetText(l18n.Sprintf("Flush DNS Cache"))
	dlp.flushButton.Clicked().Attach(dlp.flushDNSCache)

	// Log table
	dlp.logModel = &dnsLogModel{}

	if dlp.logView, err = walk.NewTableView(dlp); err != nil {
		return nil, err
	}
	// Context menu for actions on entries
	contextMenu, err := walk.NewMenu()
	if err != nil {
		return nil, err
	}
	dlp.logView.AddDisposable(contextMenu)

	// Add to Local DNS action
	addLocalDNSAction := walk.NewAction()
	addLocalDNSAction.SetText(l18n.Sprintf("Add to Local DNS"))
	addLocalDNSAction.Triggered().Attach(func() {
		idx := dlp.clickedIndex
		if idx < 0 || idx >= len(dlp.logModel.entries) {
			return
		}
		entry := dlp.logModel.entries[idx]
		domain := entry.Domain
		ip := ""
		if len(entry.ResponseIPs) > 0 {
			ip = entry.ResponseIPs[0]
		}
		if domain == "" || ip == "" {
			walk.MsgBox(dlp.Form(), l18n.Sprintf("Local DNS"), l18n.Sprintf("Cannot add: domain or IP is empty"), walk.MsgBoxIconWarning)
			return
		}
		if err := manager.AddLocalDNSRecord(domain, ip); err != nil {
			walk.MsgBox(dlp.Form(), l18n.Sprintf("Error"), err.Error(), walk.MsgBoxIconError)
			return
		}
		walk.MsgBox(dlp.Form(), l18n.Sprintf("Local DNS"), l18n.Sprintf("%s -> %s added to local DNS", domain, ip), walk.MsgBoxIconInformation)
	})
	contextMenu.Actions().Add(addLocalDNSAction)

	// Add to Domain Routing (Whitelist) action
	addWhitelistAction := walk.NewAction()
	addWhitelistAction.SetText(l18n.Sprintf("Add to Domain List"))
	addWhitelistAction.Triggered().Attach(func() {
		idx := dlp.clickedIndex
		if idx < 0 || idx >= len(dlp.logModel.entries) {
			return
		}
		entry := dlp.logModel.entries[idx]
		domain := entry.Domain
		if domain == "" {
			return
		}
		// Fetch current rules via IPC, append domain if not present
		rules, err := manager.IPCClientDomainRoutingRules()
		if err != nil {
			showErrorCustom(dlp.Form(), l18n.Sprintf("Failed to update domain routing rules"), err.Error())
			return
		}
		// check existence (case-insensitive)
		exists := false
		for _, d := range rules.Domains {
			if strings.EqualFold(d, domain) {
				exists = true
				break
			}
		}
		if !exists {
			rules.Domains = append(rules.Domains, domain)
			if err := manager.IPCClientSetDomainRoutingRules(rules); err != nil {
				showErrorCustom(dlp.Form(), l18n.Sprintf("Failed to update domain routing rules"), err.Error())
				return
			}
		}
		walk.MsgBox(dlp.Form(), l18n.Sprintf("Domain Routing"), l18n.Sprintf("%s added to domain list", domain), walk.MsgBoxIconInformation)
	})
	contextMenu.Actions().Add(addWhitelistAction)

	dlp.logView.SetModel(dlp.logModel)
	dlp.logView.SetAlternatingRowBG(true)
	dlp.logView.SetLastColumnStretched(true)
	dlp.logView.SetContextMenu(contextMenu)
	// Ensure right-click selects the clicked row and stores index for menu actions
	dlp.logView.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.RightButton {
			idx := dlp.logView.IndexAt(x, y)
			dlp.clickedIndex = idx
			if idx >= 0 {
				dlp.logView.SetCurrentIndex(idx)
			}
		}
	})

	columns := []struct {
		title string
		width int
	}{
		{l18n.Sprintf("Time"), 90},
		{l18n.Sprintf("Domain"), 200},
		{l18n.Sprintf("Type"), 50},
		{l18n.Sprintf("Route"), 60},
		{l18n.Sprintf("IPs"), 150},
		{l18n.Sprintf("Latency"), 70},
		{l18n.Sprintf("Error"), 150},
	}

	for _, col := range columns {
		c := walk.NewTableViewColumn()
		c.SetTitle(col.title)
		c.SetWidth(col.width)
		dlp.logView.Columns().Add(c)
	}

	// Start auto-refresh
	dlp.refreshTicker = time.NewTicker(1 * time.Second)
	go dlp.autoRefreshLoop()

	// Initial load
	dlp.refreshLog()

	disposables.Spare()
	return dlp, nil
}

func (dlp *DNSLogPage) Dispose() {
	dlp.disposeOnce.Do(func() {
		close(dlp.stopRefresh)
		if dlp.refreshTicker != nil {
			dlp.refreshTicker.Stop()
		}
	})
	dlp.TabPage.Dispose()
}

func (dlp *DNSLogPage) autoRefreshLoop() {
	for {
		select {
		case <-dlp.refreshTicker.C:
			dlp.Form().Synchronize(func() {
				dlp.refreshLog()
			})
		case <-dlp.stopRefresh:
			return
		}
	}
}

func (dlp *DNSLogPage) refreshLog() {
	entries, err := manager.IPCClientDNSLogGetEntries()
	if err != nil {
		return
	}

	oldCount := len(dlp.logModel.entries)
	dlp.logModel.entries = entries
	dlp.logModel.PublishRowsReset()

	dlp.statsLabel.SetText(l18n.Sprintf("Queries: %d", len(entries)))

	// Auto-scroll to bottom if enabled and new entries added
	if dlp.autoScroll && len(entries) > 0 && len(entries) > oldCount {
		dlp.logView.EnsureItemVisible(len(entries) - 1)
	}
}

func (dlp *DNSLogPage) clearLog() {
	_ = manager.IPCClientDNSLogClear()
	dlp.refreshLog()
}

func (dlp *DNSLogPage) flushDNSCache() {
	cmd := exec.Command("ipconfig", "/flushdns")
	out, err := cmd.CombinedOutput()
	if err != nil {
		walk.MsgBox(dlp.Form(), l18n.Sprintf("Flush DNS Cache"), l18n.Sprintf("Failed to flush DNS cache: %s\n\n%s", err.Error(), string(out)), walk.MsgBoxIconError)
		return
	}
	walk.MsgBox(dlp.Form(), l18n.Sprintf("Flush DNS Cache"), l18n.Sprintf("DNS cache flushed successfully."), walk.MsgBoxIconInformation)
}

func (dlp *DNSLogPage) onEnabledChanged() {
	_ = manager.IPCClientDNSLogSetEnabled(dlp.enabledCheck.Checked())
}
