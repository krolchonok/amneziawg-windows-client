package ui

import (
    "fmt"
    "sync"

    "github.com/lxn/walk"

    "github.com/amnezia-vpn/amneziawg-windows-client/l18n"
    "github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

// LocalDNSPage allows adding local DNS records (domain -> IP mappings)
type LocalDNSPage struct {
    *walk.TabPage

    tableView    *walk.TableView
    tableModel   *localDNSModel
    domainEdit   *walk.LineEdit
    ipEdit       *walk.LineEdit
    addButton    *walk.PushButton
    removeButton *walk.PushButton
    enableCheck  *walk.CheckBox

    disposeOnce sync.Once
}

type localDNSModel struct {
    walk.TableModelBase
    records []manager.LocalDNSRecord
}

func (m *localDNSModel) RowCount() int {
    return len(m.records)
}

func (m *localDNSModel) Value(row, col int) interface{} {
    if row < 0 || row >= len(m.records) {
        return ""
    }
    r := m.records[row]
    switch col {
    case 0:
        return r.Domain
    case 1:
        return r.IP
    }
    return ""
}

func NewLocalDNSPage() (*LocalDNSPage, error) {
    var err error
    var disposables walk.Disposables
    defer disposables.Treat()

    ldp := &LocalDNSPage{}

    if ldp.TabPage, err = walk.NewTabPage(); err != nil {
        return nil, err
    }
    disposables.Add(ldp)

    ldp.SetTitle(l18n.Sprintf("Local DNS"))
    ldp.SetLayout(walk.NewVBoxLayout())

    // Description
    descLabel, _ := walk.NewTextLabel(ldp)
    descLabel.SetText(l18n.Sprintf("Add local DNS records. These domains will resolve to the specified IP addresses."))

    // Input toolbar
    toolbar, _ := walk.NewComposite(ldp)
    toolbarLayout := walk.NewHBoxLayout()
    toolbarLayout.SetMargins(walk.Margins{5, 5, 5, 5})
    toolbar.SetLayout(toolbarLayout)

    domainLabel, _ := walk.NewTextLabel(toolbar)
    domainLabel.SetText(l18n.Sprintf("Domain:"))

    if ldp.domainEdit, err = walk.NewLineEdit(toolbar); err != nil {
        return nil, err
    }
    ldp.domainEdit.SetMaxLength(256)
    ldp.domainEdit.SetToolTipText(l18n.Sprintf("e.g. example.com"))

    ipLabel, _ := walk.NewTextLabel(toolbar)
    ipLabel.SetText(l18n.Sprintf("IP:"))

    if ldp.ipEdit, err = walk.NewLineEdit(toolbar); err != nil {
        return nil, err
    }
    ldp.ipEdit.SetMaxLength(45) // IPv6 max length
    ldp.ipEdit.SetToolTipText(l18n.Sprintf("e.g. 192.168.1.1 or ::1"))

    if ldp.addButton, err = walk.NewPushButton(toolbar); err != nil {
        return nil, err
    }
    ldp.addButton.SetText(l18n.Sprintf("Add"))
    ldp.addButton.Clicked().Attach(func() {
        domain := ldp.domainEdit.Text()
        ip := ldp.ipEdit.Text()
        if len(domain) == 0 || len(ip) == 0 {
            return
        }
        if err := manager.AddLocalDNSRecord(domain, ip); err != nil {
            walk.MsgBox(ldp.Form(), l18n.Sprintf("Error"), err.Error(), walk.MsgBoxIconError)
            return
        }
        ldp.domainEdit.SetText("")
        ldp.ipEdit.SetText("")
        ldp.refreshList()
    })

    if ldp.removeButton, err = walk.NewPushButton(toolbar); err != nil {
        return nil, err
    }
    ldp.removeButton.SetText(l18n.Sprintf("Remove"))
    ldp.removeButton.Clicked().Attach(func() {
        idx := ldp.tableView.CurrentIndex()
        if idx < 0 || idx >= len(ldp.tableModel.records) {
            return
        }
        domain := ldp.tableModel.records[idx].Domain
        _ = manager.RemoveLocalDNSRecord(domain)
        ldp.refreshList()
    })

    walk.NewHSpacer(toolbar)

    if ldp.enableCheck, err = walk.NewCheckBox(toolbar); err != nil {
        return nil, err
    }
    ldp.enableCheck.SetText(l18n.Sprintf("Enable local DNS"))
    ldp.enableCheck.SetChecked(true)

    // Table
    ldp.tableModel = &localDNSModel{}
    if ldp.tableView, err = walk.NewTableView(ldp); err != nil {
        return nil, err
    }
    ldp.tableView.SetModel(ldp.tableModel)
    ldp.tableView.SetAlternatingRowBG(true)
    ldp.tableView.SetLastColumnStretched(true)

    columns := []struct {
        title string
        width int
    }{
        {l18n.Sprintf("Domain"), 250},
        {l18n.Sprintf("IP Address"), 150},
    }
    for _, col := range columns {
        c := walk.NewTableViewColumn()
        c.SetTitle(col.title)
        c.SetWidth(col.width)
        ldp.tableView.Columns().Add(c)
    }

    ldp.refreshList()

    // Refresh list when tab becomes visible
    ldp.VisibleChanged().Attach(func() {
        if ldp.Visible() {
            ldp.refreshList()
        }
    })

    disposables.Spare()
    return ldp, nil
}

func (ldp *LocalDNSPage) refreshList() {
    records := manager.GetLocalDNSRecords()
    ldp.tableModel.records = records
    ldp.tableModel.PublishRowsReset()
}

func (ldp *LocalDNSPage) Dispose() {
    ldp.disposeOnce.Do(func() {
    })
    ldp.TabPage.Dispose()
}

// LocalDNSEnabled returns whether local DNS is enabled
func (ldp *LocalDNSPage) LocalDNSEnabled() bool {
    if ldp == nil || ldp.enableCheck == nil {
        return false
    }
    return ldp.enableCheck.Checked()
}

func (ldp *LocalDNSPage) String() string { return fmt.Sprintf("LocalDNSPage") }

// Alias for backwards compatibility
type DNSBlockPage = LocalDNSPage

func NewDNSBlockPage() (*LocalDNSPage, error) {
    return NewLocalDNSPage()
}
