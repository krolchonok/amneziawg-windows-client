/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package embed

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed wintun.dll
var WintunDLL []byte

func ExtractWintunDLL() error {
	if len(WintunDLL) == 0 {
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)
	targetPath := filepath.Join(exeDir, "wintun.dll")

	// Check if existing file is already identical to embedded DLL
	if existingData, err := os.ReadFile(targetPath); err == nil {
		if bytes.Equal(sha256Hash(existingData), sha256Hash(WintunDLL)) {
			return nil
		}
	}

	// Try writing to application directory
	err = os.WriteFile(targetPath, WintunDLL, 0644)
	if err == nil {
		return nil
	}

	// Fallback to Temp directory if application directory is read-only
	tempDir := os.TempDir()
	tempTargetPath := filepath.Join(tempDir, "wintun.dll")
	if existingData, err := os.ReadFile(tempTargetPath); err == nil {
		if bytes.Equal(sha256Hash(existingData), sha256Hash(WintunDLL)) {
			return nil
		}
	}

	return os.WriteFile(tempTargetPath, WintunDLL, 0644)
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
