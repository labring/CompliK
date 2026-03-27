// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package processor provides functionality for analyzing system processes,
// detecting suspicious behavior based on configurable rules, and identifying
// container relationships for Kubernetes workloads.
package processor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/internal/container"
	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	"github.com/sirupsen/logrus"
)

type compiledRules struct {
	blacklistProcesses  []*regexp.Regexp
	blacklistKeywords   []*regexp.Regexp
	whitelistProcesses  []*regexp.Regexp
	whitelistCommands   []*regexp.Regexp
	whitelistNamespaces []*regexp.Regexp
	whitelistPodNames   []*regexp.Regexp
}

type Processor struct {
	ProcPath string
	rules    compiledRules
	mu       sync.RWMutex
}

// compileRules compiles a list of regex patterns into compiled regular expressions
func compileRules(patterns []string) []*regexp.Regexp {
	regexps := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			legacy.L.WithFields(logrus.Fields{"rule": pattern}).WithError(err).Warn("Invalid regex pattern, skipping")
			continue
		}
		regexps = append(regexps, re)
	}
	return regexps
}

// NewProcessor creates a new processor instance with the given configuration
func NewProcessor(config *models.Config) *Processor {
	p := &Processor{ProcPath: config.Scanner.ProcPath}
	p.UpdateConfig(config)
	return p
}

// UpdateConfig updates the processor's detection rules from the new configuration
func (p *Processor) UpdateConfig(config *models.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rules := config.DetectionRules
	p.rules = compiledRules{
		blacklistProcesses:  compileRules(rules.Blacklist.Processes),
		blacklistKeywords:   compileRules(rules.Blacklist.Keywords),
		whitelistProcesses:  compileRules(rules.Whitelist.Processes),
		whitelistCommands:   compileRules(rules.Whitelist.Commands),
		whitelistNamespaces: compileRules(rules.Whitelist.Namespaces),
		whitelistPodNames:   compileRules(rules.Whitelist.PodNames),
	}
}

// GetAllProcesses returns a list of all process IDs from the proc filesystem
func (p *Processor) GetAllProcesses() ([]int, error) {
	procDirs, err := os.ReadDir(p.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s directory: %w", p.ProcPath, err)
	}
	pids := make([]int, 0, len(procDirs))
	for _, dir := range procDirs {
		if !dir.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// matchAny checks if text matches any of the provided regular expressions
// Returns true and the matching pattern if found, false and empty string otherwise
func matchAny(text string, regexps []*regexp.Regexp) (bool, string) {
	for _, re := range regexps {
		if re.MatchString(text) {
			return true, re.String()
		}
	}
	return false, ""
}

// AnalyzeProcess analyzes a single process to determine if it's malicious
// Returns process info if malicious, nil otherwise
// This function queries container info on-demand instead of using cache
func (p *Processor) AnalyzeProcess(pid int) (*models.ProcessInfo, error) {
	procDir := filepath.Join(p.ProcPath, strconv.Itoa(pid))
	cmdlineFile := filepath.Join(procDir, "cmdline")
	cmdlineData, err := os.ReadFile(cmdlineFile)
	if err != nil {
		return nil, nil
	}
	cmdline := strings.ReplaceAll(string(cmdlineData), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return nil, nil
	}
	processName := p.getProcessName(cmdline)

	procLogger := legacy.L.WithFields(logrus.Fields{
		"pid":            pid,
		"process_name":   processName,
		"cmdline":        cmdline,
		"proc_dir":       procDir,
		"cmdline_length": len(cmdline),
	})
	procLogger.Debug("Starting process analysis,Process Info:")

	// Step 1: Check if process matches blacklist
	isBlacklisted, message := p.isBlacklisted(processName, cmdline)
	if !isBlacklisted {
		procLogger.Debug("Process not in blacklist, skipping")
		return nil, nil
	}
	procLogger.WithField("reason", message).Info("Process matched blacklist rule")

	// Step 2: Check process whitelist (before heavy operations)
	if p.isProcessWhitelisted(processName, cmdline) {
		procLogger.Info("Process is whitelisted, ignoring")
		return nil, nil
	}

	// Step 3: Identify container main process
	mainProcessPID := pid
	processStatus, err := ReadProcessStatus(p.ProcPath, pid)
	if err != nil {
		procLogger.WithError(err).Debug("Failed to read process status, using current PID")
	} else {
		if IsContainerMainProcess(processStatus) {
			procLogger.WithField("main_process_pid", mainProcessPID).Info("Detected malicious process is container main process")
		} else {
			// Trace back to find container main process
			mainPID, err := FindContainerMainProcess(p.ProcPath, pid)
			if err != nil {
				procLogger.WithError(err).Debug("Failed to find container main process, continuing with current PID")
			} else {
				mainProcessPID = mainPID
				procLogger.WithFields(logrus.Fields{
					"malicious_pid":    pid,
					"main_process_pid": mainProcessPID,
				}).Info("Traced malicious process to container main process")
			}
		}
	}

	// Step 4: Get container ID
	containerID := p.getContainerIDFromPID(mainProcessPID)

	// Step 5: Query container info on-demand when container metadata is available.
	var podName, namespace string
	if containerID == "" {
		procLogger.Debug("Unable to determine container ID, continue alerting without container metadata")
	} else {
		podName, namespace, err = container.GetContainerInfo(containerID)
		if err != nil {
			procLogger.WithFields(logrus.Fields{
				"containerID": containerID,
				"error":       err.Error(),
			}).Debug("Failed to get container info, continue alerting without pod/namespace")
			podName = ""
			namespace = ""
		}
	}

	// Step 6: Check infrastructure whitelist
	if (namespace != "" || podName != "") && p.isInfraWhitelisted(namespace, podName) {
		procLogger.WithFields(logrus.Fields{
			"namespace": namespace,
			"pod":       podName,
		}).Info("Infrastructure (namespace/pod) is whitelisted, ignoring")
		return nil, nil
	}

	displayContainerID := containerID
	if displayContainerID == "" {
		displayContainerID = "unknown"
	}
	displayPodName := podName
	if displayPodName == "" {
		displayPodName = "unknown"
	}
	displayNamespace := namespace
	if displayNamespace == "" {
		displayNamespace = "unknown"
	}

	// Step 7: Confirmed as suspicious process
	procLogger.WithFields(logrus.Fields{
		"namespace":        displayNamespace,
		"pod":              displayPodName,
		"containerID":      displayContainerID,
		"malicious_pid":    pid,
		"main_process_pid": mainProcessPID,
	}).Warn("Confirmed malicious process detected")

	return &models.ProcessInfo{
		PID:         pid,
		ProcessName: processName,
		Command:     cmdline,
		Timestamp:   time.Now().Format(time.RFC3339),
		ContainerID: displayContainerID,
		Message:     message,
		PodName:     displayPodName,
		Namespace:   displayNamespace,
	}, nil
}

// isBlacklisted checks if a process name or command line matches blacklist rules
func (p *Processor) isBlacklisted(processName, cmdline string) (bool, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if matched, rule := matchAny(processName, p.rules.blacklistProcesses); matched {
		return true, fmt.Sprintf("Process name '%s' matched blacklist rule '%s'", processName, rule)
	}
	if matched, rule := matchAny(cmdline, p.rules.blacklistKeywords); matched {
		return true, fmt.Sprintf("Command line matched keyword blacklist rule '%s'", rule)
	}
	return false, ""
}

// isProcessWhitelisted checks if a process is whitelisted by name or command
func (p *Processor) isProcessWhitelisted(processName, cmdline string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return matchAnyBool(processName, p.rules.whitelistProcesses) || matchAnyBool(cmdline, p.rules.whitelistCommands)
}

// isInfraWhitelisted checks if namespace or pod name is whitelisted
func (p *Processor) isInfraWhitelisted(namespace, podName string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return matchAnyBool(namespace, p.rules.whitelistNamespaces) || matchAnyBool(podName, p.rules.whitelistPodNames)
}

// matchAnyBool is a simplified version of matchAny that only returns a boolean
func matchAnyBool(text string, regexps []*regexp.Regexp) bool {
	for _, re := range regexps {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// getProcessName extracts the process name from command line
func (p *Processor) getProcessName(cmdline string) string {
	parts := strings.Fields(cmdline)
	if len(parts) == 0 {
		return ""
	}
	return filepath.Base(parts[0])
}

// getContainerIDFromPID extracts container ID from process cgroup information
func (p *Processor) getContainerIDFromPID(pid int) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	content, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, "containerd") || strings.Contains(line, "docker") || strings.Contains(line, "kubepods") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				if strings.HasPrefix(part, "cri-containerd-") && strings.HasSuffix(part, ".scope") {
					containerID := strings.TrimPrefix(part, "cri-containerd-")
					containerID = strings.TrimSuffix(containerID, ".scope")
					if len(containerID) == 64 && isHexString(containerID) {
						return containerID
					}
				}
			}
		}
	}
	return ""
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
