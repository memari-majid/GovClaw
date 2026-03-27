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

package unit

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestDefaultSkillActions(t *testing.T) {
	actions := config.DefaultSkillActions()

	tests := []struct {
		severity    string
		wantRuntime config.RuntimeAction
		wantFile    config.FileAction
		wantInstall config.InstallAction
	}{
		{"CRITICAL", config.RuntimeEnable, config.FileActionNone, config.InstallNone},
		{"HIGH", config.RuntimeEnable, config.FileActionNone, config.InstallNone},
		{"MEDIUM", config.RuntimeEnable, config.FileActionNone, config.InstallNone},
		{"LOW", config.RuntimeEnable, config.FileActionNone, config.InstallNone},
		{"INFO", config.RuntimeEnable, config.FileActionNone, config.InstallNone},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			action := actions.ForSeverity(tt.severity)
			if action.Runtime != tt.wantRuntime {
				t.Errorf("ForSeverity(%q).Runtime = %q, want %q", tt.severity, action.Runtime, tt.wantRuntime)
			}
			if action.File != tt.wantFile {
				t.Errorf("ForSeverity(%q).File = %q, want %q", tt.severity, action.File, tt.wantFile)
			}
			if action.Install != tt.wantInstall {
				t.Errorf("ForSeverity(%q).Install = %q, want %q", tt.severity, action.Install, tt.wantInstall)
			}
		})
	}
}

func TestForSeverityCaseInsensitive(t *testing.T) {
	actions := config.DefaultSkillActions()

	variants := []string{"critical", "Critical", "CRITICAL", "cRiTiCaL"}
	for _, v := range variants {
		t.Run(v, func(t *testing.T) {
			action := actions.ForSeverity(v)
			if action.Runtime != config.RuntimeEnable {
				t.Errorf("ForSeverity(%q).Runtime = %q, want %q", v, action.Runtime, config.RuntimeEnable)
			}
		})
	}
}

func TestForSeverityUnknownFallsBackToInfo(t *testing.T) {
	actions := config.DefaultSkillActions()
	action := actions.ForSeverity("UNKNOWN")
	if action.Runtime != config.RuntimeEnable {
		t.Errorf("ForSeverity(UNKNOWN).Runtime = %q, want %q", action.Runtime, config.RuntimeEnable)
	}
	if action.File != config.FileActionNone {
		t.Errorf("ForSeverity(UNKNOWN).File = %q, want %q", action.File, config.FileActionNone)
	}
	if action.Install != config.InstallNone {
		t.Errorf("ForSeverity(UNKNOWN).Install = %q, want %q", action.Install, config.InstallNone)
	}
}

func TestShouldDisableAndQuarantine(t *testing.T) {
	actions := config.DefaultSkillActions()

	if actions.ShouldDisable("CRITICAL") {
		t.Error("expected CRITICAL not to be disabled with permissive defaults")
	}
	if actions.ShouldDisable("HIGH") {
		t.Error("expected HIGH not to be disabled with permissive defaults")
	}
	if actions.ShouldDisable("MEDIUM") {
		t.Error("expected MEDIUM not to be disabled with permissive defaults")
	}

	if actions.ShouldQuarantine("CRITICAL") {
		t.Error("expected CRITICAL not to be quarantined with permissive defaults")
	}
	if actions.ShouldQuarantine("LOW") {
		t.Error("expected LOW not to be quarantined with permissive defaults")
	}

	if actions.ShouldInstallBlock("CRITICAL") {
		t.Error("expected CRITICAL not to be install-blocked with permissive defaults")
	}
	if actions.ShouldInstallBlock("MEDIUM") {
		t.Error("expected MEDIUM not to be install-blocked with permissive defaults")
	}
}

func TestStrictPolicyDisablesMedium(t *testing.T) {
	actions := config.SkillActionsConfig{
		Critical: config.SeverityAction{File: config.FileActionQuarantine, Runtime: config.RuntimeDisable, Install: config.InstallBlock},
		High:     config.SeverityAction{File: config.FileActionQuarantine, Runtime: config.RuntimeDisable, Install: config.InstallBlock},
		Medium:   config.SeverityAction{File: config.FileActionQuarantine, Runtime: config.RuntimeDisable, Install: config.InstallBlock},
		Low:      config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
		Info:     config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
	}

	if !actions.ShouldDisable("MEDIUM") {
		t.Error("strict policy should disable MEDIUM")
	}
	if !actions.ShouldQuarantine("MEDIUM") {
		t.Error("strict policy should quarantine MEDIUM")
	}
	if !actions.ShouldInstallBlock("MEDIUM") {
		t.Error("strict policy should install-block MEDIUM")
	}
	if actions.ShouldDisable("LOW") {
		t.Error("strict policy should not disable LOW")
	}
}

func TestPermissivePolicyAllowsHigh(t *testing.T) {
	actions := config.SkillActionsConfig{
		Critical: config.SeverityAction{File: config.FileActionQuarantine, Runtime: config.RuntimeDisable, Install: config.InstallBlock},
		High:     config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
		Medium:   config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
		Low:      config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
		Info:     config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
	}

	if actions.ShouldDisable("HIGH") {
		t.Error("permissive policy should not disable HIGH")
	}
	if !actions.ShouldDisable("CRITICAL") {
		t.Error("permissive policy should still disable CRITICAL")
	}
}

func TestQuarantineWithoutDisable(t *testing.T) {
	actions := config.SkillActionsConfig{
		Critical: config.SeverityAction{File: config.FileActionQuarantine, Runtime: config.RuntimeDisable, Install: config.InstallBlock},
		High:     config.SeverityAction{File: config.FileActionQuarantine, Runtime: config.RuntimeEnable, Install: config.InstallNone},
		Medium:   config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
		Low:      config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
		Info:     config.SeverityAction{File: config.FileActionNone, Runtime: config.RuntimeEnable, Install: config.InstallNone},
	}

	action := actions.ForSeverity("HIGH")
	if action.Runtime != config.RuntimeEnable {
		t.Errorf("expected HIGH runtime to be enable, got %q", action.Runtime)
	}
	if action.File != config.FileActionQuarantine {
		t.Errorf("expected HIGH file to be quarantine, got %q", action.File)
	}
}

func TestValidateAcceptsValid(t *testing.T) {
	actions := config.DefaultSkillActions()
	if err := actions.Validate(); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
}

func TestValidateRejectsInvalidRuntime(t *testing.T) {
	actions := config.DefaultSkillActions()
	actions.Medium.Runtime = "deny"
	if err := actions.Validate(); err == nil {
		t.Fatal("expected Validate to return error for invalid runtime")
	}
}

func TestValidateRejectsInvalidFile(t *testing.T) {
	actions := config.DefaultSkillActions()
	actions.High.File = "delete"
	if err := actions.Validate(); err == nil {
		t.Fatal("expected Validate to return error for invalid file action")
	}
}

func TestValidateRejectsInvalidInstall(t *testing.T) {
	actions := config.DefaultSkillActions()
	actions.Critical.Install = "yeet"
	if err := actions.Validate(); err == nil {
		t.Fatal("expected Validate to return error for invalid install action")
	}
}
