// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
//
// SPDX-License-Identifier: Apache-2.0

package firewall

// Compiler generates platform-specific firewall rules from a FirewallConfig.
// Implementations must be pure Go — no privileged operations.
type Compiler interface {
	// Platform returns the backend name ("pfctl" or "iptables").
	Platform() string

	// Compile converts a FirewallConfig into a slice of rule strings.
	// This is pure in-memory work — no system calls, no root required.
	Compile(cfg *FirewallConfig) ([]string, error)

	// ValidateArg checks that a string is safe to use as a rule argument.
	ValidateArg(arg string) error

	// ApplyCommand returns the shell command an administrator should run
	// to load the rules file at rulesPath. Never executes it.
	ApplyCommand(rulesPath string) string

	// RemoveCommand returns the shell command an administrator should run
	// to remove the firewall rules. Never executes it.
	RemoveCommand() string
}
