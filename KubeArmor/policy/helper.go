// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor
// Package policy handles policy updates over gRPC in non-k8s environment

// Contains the functions utilized by  policy.go
package policy

import (
	"fmt"
	"os"
	"path/filepath"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
)

func policyCheck(policyName string) bool {

	directoryPath := cfg.PolicyDir
	fileName := policyName + ".yaml"

	// Create the full file path by joining the directory path and the file name
	filePath := filepath.Join(directoryPath, fileName)

	// Check if the file exists
	_, err := os.Stat(filePath)
	if err == nil {
		fmt.Printf("File '%s' exists.\n", filePath)
		return true
	} else if os.IsNotExist(err) {
		fmt.Printf("File '%s' does not exist.\n", filePath)
		return false
	} else {
		fmt.Printf("Error checking file: %v\n", err)
		return false
	}
}
