/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"os/exec"
	"sort"
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
	clickedIndex  int // Index of right-clicked row for context menu

	enabledCheck    *walk.CheckBox
	searchEdit     *walk.LineEdit
	clearButton    *walk.PushButton
	flushButton    *walk.PushButton
	refreshButton  *walk.PushButton
	autoScrollCheck *walk.CheckBox

	statsLabel *walk.TextLabel

	refreshTicker *time.Ticker
	stopRefresh   chan struct{}
	disposeOnce   sync.Once

	// Количество записей, которые мы уже загрузили из сервиса (до фильтрации)
	lastKnownCount int
}

type dnsLogModel struct {
	walk.TableModelBase
	walk.SorterBase
	entries    []manager.DNSLogEntry
	allEntries []manager.DNSLogEntry
	filterText string
	// isSorted показывает, включена ли пользовательская сортировка
	isSorted bool
}

func (m *dnsLogModel) Sort(col int, order walk.SortOrder) error {
	m.isSorted = true
	m.sortEntries(col, order)
	err := m.SorterBase.Sort(col, order)
	// Ensure the view is refreshed after sorting so hover/selection render correctly.
	m.PublishRowsReset()
	return err
}

func (m *dnsLogModel) sortEntries(col int, order walk.SortOrder) {
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
}

func (m *dnsLogModel) SetEntries(entries []manager.DNSLogEntry) {
	m.allEntries = entries
	m.applyFilter()
}

// AppendEntries добавляет новые записи инкрементально, без полного сброса.
// Возвращает true если записи были добавлены.
func (m *dnsLogModel) AppendEntries(newEntries []manager.DNSLogEntry) bool {
	if len(newEntries) == 0 {
		return false
	}

	m.allEntries = append(m.allEntries, newEntries...)

	// Если есть фильтр или пользовательская сортировка — нужен полный пересчёт
	if m.filterText != "" || m.isSorted {
		m.applyFilter()
		return true
	}

	// Просто добавляем в конец — PublishRowsInserted вместо PublishRowsReset
	from := len(m.entries)
	m.entries = append(m.entries, newEntries...)
	m.PublishRowsInserted(from, from+len(newEntries)-1)
	return true
}

func (m *dnsLogModel) SetFilterText(text string) {
	m.filterText = strings.ToLower(strings.TrimSpace(text))
	m.applyFilter()
}

func (m *dnsLogModel) FilterActive() bool {
	return m.filterText != ""
}

func (m *dnsLogModel) TotalCount() int {
	return len(m.allEntries)
}

func (m *dnsLogModel) applyFilter() {
	if m.filterText == "" {
		m.entries = append(m.entries[:0], m.allEntries...)
	} else {
		filtered := make([]manager.DNSLogEntry, 0, len(m.allEntries))
		for _, entry := range m.allEntries {
			if strings.Contains(strings.ToLower(entry.String()), m.filterText) {
				filtered = append(filtered, entry)
			}
		}
		m.entries = filtered
	}
	if col := m.SortedColumn(); col >= 0 {
		m.sortEntries(col, m.SortOrder())
	}
	m.PublishRowsReset()
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

	searchLabel, _ := walk.NewTextLabel(toolbar)
	searchLabel.SetText(l18n.Sprintf("Search:"))

	if dlp.searchEdit, err = walk.NewLineEdit(toolbar); err != nil {
		return nil, err
	}
	dlp.searchEdit.SetToolTipText(l18n.Sprintf("Search in DNS log entries"))
	dlp.searchEdit.TextChanged().Attach(func() {
		dlp.logModel.SetFilterText(dlp.searchEdit.Text())
		dlp.updateStats()
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
	// Do not stretch the last column — stretching can trigger layout
	// recalculations that cause visual glitches when hovering rows.
	dlp.logView.SetLastColumnStretched(false)
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

	// Start auto-refresh (2 seconds to reduce visual load)
	dlp.refreshTicker = time.NewTicker(2 * time.Second)
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
				dlp.incrementalRefresh()
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

	dlp.logModel.SetEntries(entries)
	dlp.lastKnownCount = len(entries)
	dlp.updateStats()

	// Auto-scroll to bottom if enabled
	if dlp.autoScroll && len(dlp.logModel.entries) > 0 {
		dlp.logView.EnsureItemVisible(len(dlp.logModel.entries) - 1)
	}
}

// incrementalRefresh загружает все записи через стандартный IPC-метод,
// но обновляет модель инкрементально (без полного сброса таблицы).
// Это устраняет мерцание и совместимо с любой версией сервиса.
func (dlp *DNSLogPage) incrementalRefresh() {
	entries, err := manager.IPCClientDNSLogGetEntries()
	if err != nil {
		return
	}

	newCount := len(entries)
	if newCount == dlp.lastKnownCount {
		// Ничего не изменилось
		return
	}

	if newCount < dlp.lastKnownCount {
		// Лог был очищен или обрезан — полная перезагрузка
		dlp.logModel.SetEntries(entries)
		dlp.lastKnownCount = newCount
		dlp.updateStats()
		if dlp.autoScroll && len(dlp.logModel.entries) > 0 {
			dlp.logView.EnsureItemVisible(len(dlp.logModel.entries) - 1)
		}
		return
	}

	// Добавляем только новые записи
	newEntries := entries[dlp.lastKnownCount:]
	dlp.lastKnownCount = newCount

	if dlp.logModel.AppendEntries(newEntries) {
		dlp.updateStats()

		// Auto-scroll to bottom if enabled
		if dlp.autoScroll && len(dlp.logModel.entries) > 0 {
			dlp.logView.EnsureItemVisible(len(dlp.logModel.entries) - 1)
		}
	}
}

func (dlp *DNSLogPage) clearLog() {
	_ = manager.IPCClientDNSLogClear()
	dlp.lastKnownCount = 0
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

func (dlp *DNSLogPage) updateStats() {
	if dlp.logModel.FilterActive() {
		dlp.statsLabel.SetText(l18n.Sprintf("Queries: %d / %d", dlp.logModel.RowCount(), dlp.logModel.TotalCount()))
		return
	}
	dlp.statsLabel.SetText(l18n.Sprintf("Queries: %d", dlp.logModel.TotalCount()))
}
