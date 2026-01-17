/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"strings"
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
	
	enabledCheck  *walk.CheckBox
	clearButton   *walk.PushButton
	refreshButton *walk.PushButton
	autoScrollCheck *walk.CheckBox
	
	statsLabel    *walk.TextLabel
	
	refreshTicker *time.Ticker
	stopRefresh   chan struct{}
	disposeOnce   sync.Once
}

type dnsLogModel struct {
	walk.TableModelBase
	entries []manager.DNSLogEntry
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
		autoScroll:  true,
		stopRefresh: make(chan struct{}),
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
	dlp.statsLabel.SetText(l18n.Sprintf("Queries: 0"))

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

	// Log table
	dlp.logModel = &dnsLogModel{}

	if dlp.logView, err = walk.NewTableView(dlp); err != nil {
		return nil, err
	}
	dlp.logView.SetModel(dlp.logModel)
	dlp.logView.SetAlternatingRowBG(true)
	dlp.logView.SetLastColumnStretched(true)

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

	dlp.statsLabel.SetText(fmt.Sprintf(l18n.Sprintf("Queries: %d"), len(entries)))

	// Auto-scroll to bottom if enabled and new entries added
	if dlp.autoScroll && len(entries) > 0 && len(entries) > oldCount {
		dlp.logView.EnsureItemVisible(len(entries) - 1)
	}
}

func (dlp *DNSLogPage) clearLog() {
	_ = manager.IPCClientDNSLogClear()
	dlp.refreshLog()
}

func (dlp *DNSLogPage) onEnabledChanged() {
	_ = manager.IPCClientDNSLogSetEnabled(dlp.enabledCheck.Checked())
}
