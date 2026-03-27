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

package enforce

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

type MCPEnforcer struct {
	shell *sandbox.OpenShell
}

func NewMCPEnforcer(shell *sandbox.OpenShell) *MCPEnforcer {
	return &MCPEnforcer{shell: shell}
}

func (e *MCPEnforcer) BlockEndpoint(url string) error {
	policy, err := e.shell.LoadPolicy()
	if err != nil {
		return fmt.Errorf("enforce: load sandbox policy: %w", err)
	}

	policy.DenyEndpoint(url)

	if err := e.shell.SavePolicy(policy); err != nil {
		return fmt.Errorf("enforce: save sandbox policy: %w", err)
	}

	if e.shell.IsAvailable() {
		if err := e.shell.ReloadPolicy(); err != nil {
			return fmt.Errorf("enforce: reload sandbox policy: %w", err)
		}
	}
	return nil
}

func (e *MCPEnforcer) AllowEndpoint(url string) error {
	policy, err := e.shell.LoadPolicy()
	if err != nil {
		return fmt.Errorf("enforce: load sandbox policy: %w", err)
	}

	policy.AllowEndpoint(url)

	if err := e.shell.SavePolicy(policy); err != nil {
		return fmt.Errorf("enforce: save sandbox policy: %w", err)
	}

	if e.shell.IsAvailable() {
		if err := e.shell.ReloadPolicy(); err != nil {
			return fmt.Errorf("enforce: reload sandbox policy: %w", err)
		}
	}
	return nil
}
