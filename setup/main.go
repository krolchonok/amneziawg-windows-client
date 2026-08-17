/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

//go:embed bin/amneziawg.exe
var amneziawgExe []byte

//go:embed bin/awg.exe
var awgExe []byte

//go:embed bin/wintun.dll
var wintunDll []byte

func main() {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		userProfile := os.Getenv("USERPROFILE")
		localAppData = filepath.Join(userProfile, "AppData", "Local")
	}

	installDir := filepath.Join(localAppData, "AmneziaWG")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		windows.MessageBox(0,
			windows.StringToUTF16Ptr(fmt.Sprintf("Не удалось создать директорию установки:\n%v", err)),
			windows.StringToUTF16Ptr("Ошибка установки"),
			windows.MB_ICONERROR|windows.MB_OK,
		)
		os.Exit(1)
	}

	targetAmnezia := filepath.Join(installDir, "amneziawg.exe")
	targetAwg := filepath.Join(installDir, "awg.exe")
	targetWintun := filepath.Join(installDir, "wintun.dll")

	// Write binaries
	if err := os.WriteFile(targetAmnezia, amneziawgExe, 0755); err != nil {
		windows.MessageBox(0,
			windows.StringToUTF16Ptr(fmt.Sprintf("Не удалось записать amneziawg.exe:\n%v", err)),
			windows.StringToUTF16Ptr("Ошибка установки"),
			windows.MB_ICONERROR|windows.MB_OK,
		)
		os.Exit(1)
	}

	if len(awgExe) > 0 {
		_ = os.WriteFile(targetAwg, awgExe, 0755)
	}
	if len(wintunDll) > 0 {
		_ = os.WriteFile(targetWintun, wintunDll, 0644)
	}

	// Create Desktop Shortcut
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		desktopPath := filepath.Join(userProfile, "Desktop", "AmneziaWG.lnk")
		createShortcut(desktopPath, targetAmnezia, installDir)
	}

	// Create Start Menu Shortcut
	appData := os.Getenv("APPDATA")
	if appData != "" {
		startMenuDir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs")
		_ = os.MkdirAll(startMenuDir, 0755)
		startMenuShortcut := filepath.Join(startMenuDir, "AmneziaWG.lnk")
		createShortcut(startMenuShortcut, targetAmnezia, installDir)
	}

	// Launch installed application
	cmd := exec.Command(targetAmnezia)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()

	windows.MessageBox(0,
		windows.StringToUTF16Ptr(fmt.Sprintf("AmneziaWG успешно установлен!\n\nПуть установки: %s\nЯрлыки созданы на Рабочем столе и в меню Пуск.", installDir)),
		windows.StringToUTF16Ptr("Установка завершена"),
		windows.MB_ICONINFORMATION|windows.MB_OK,
	)
}

func createShortcut(shortcutPath, targetPath, workDir string) {
	psScript := fmt.Sprintf(
		`$s=(New-Object -COM WScript.Shell).CreateShortcut('%s'); $s.TargetPath='%s'; $s.WorkingDirectory='%s'; $s.IconLocation='%s,0'; $s.Save()`,
		shortcutPath, targetPath, workDir, targetPath,
	)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}
