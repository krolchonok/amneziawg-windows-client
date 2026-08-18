package ui

import (
	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/services"
)

const skipUpdatePromptRegistryKey = "SkipUpdatePrompt"

func updatePromptDisabled() bool {
	return services.UserKeyString(skipUpdatePromptRegistryKey) == "1"
}

func setUpdatePromptDisabled() {
	_ = services.SetUserKeyString(skipUpdatePromptRegistryKey, "1")
}

const (
	updatePromptResultUpdate = walk.DlgCmdYes
	updatePromptResultSkip   = walk.DlgCmdNo
	updatePromptResultNever  = walk.DlgCmdIgnore
)

// showUpdatePromptDialog shows a one-time-per-launch modal asking whether to
// install the update that was just found. "Never ask again" persists a
// per-user registry flag (see updatePromptDisabled) so future launches skip
// the prompt entirely; the passive Update tab and tray icon still appear
// regardless, this only suppresses the interruptive dialog.
func showUpdatePromptDialog(owner walk.Form) {
	var disposables walk.Disposables
	defer disposables.Treat()

	dlg, err := walk.NewDialogWithFixedSize(owner)
	if err != nil {
		return
	}
	disposables.Add(dlg)

	dlg.SetTitle(l18n.Sprintf("An Update is Available!"))
	if icon, err := loadShieldIcon(32); err == nil {
		dlg.SetIcon(icon)
	}
	font, _ := walk.NewFont("Segoe UI", 9, 0)
	dlg.SetFont(font)

	vbl := walk.NewVBoxLayout()
	vbl.SetMargins(walk.Margins{20, 20, 20, 20})
	vbl.SetSpacing(10)
	dlg.SetLayout(vbl)

	msg, err := walk.NewTextLabel(dlg)
	if err != nil {
		return
	}
	msg.SetText(l18n.Sprintf("An update to AmneziaWG is available. It is highly advisable to update without delay."))
	msg.SetMinMaxSize(walk.Size{300, 0}, walk.Size{0, 0})

	buttonCP, err := walk.NewComposite(dlg)
	if err != nil {
		return
	}
	hbl := walk.NewHBoxLayout()
	hbl.SetMargins(walk.Margins{VNear: 10})
	buttonCP.SetLayout(hbl)

	neverButton, err := walk.NewPushButton(buttonCP)
	if err != nil {
		return
	}
	neverButton.SetText(l18n.Sprintf("Never ask again"))
	neverButton.Clicked().Attach(func() { dlg.Close(updatePromptResultNever) })

	walk.NewHSpacer(buttonCP)

	noButton, err := walk.NewPushButton(buttonCP)
	if err != nil {
		return
	}
	noButton.SetText(l18n.Sprintf("No"))
	noButton.Clicked().Attach(func() { dlg.Close(updatePromptResultSkip) })

	updateButton, err := walk.NewPushButton(buttonCP)
	if err != nil {
		return
	}
	updateButton.SetText(l18n.Sprintf("Update Now"))
	updateButton.Clicked().Attach(func() { dlg.Close(updatePromptResultUpdate) })

	dlg.SetDefaultButton(updateButton)
	dlg.SetCancelButton(noButton)

	disposables.Spare()

	switch dlg.Run() {
	case updatePromptResultUpdate:
		_ = manager.IPCClientUpdate()
	case updatePromptResultNever:
		setUpdatePromptDisabled()
	}
}
