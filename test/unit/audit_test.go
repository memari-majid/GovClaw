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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestStoreInitAndLog(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	defer os.Remove(dbPath)

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	err = store.LogEvent(audit.Event{
		Action:   "test",
		Target:   "target",
		Details:  "test event",
		Severity: "INFO",
	})
	if err != nil {
		t.Fatalf("LogEvent: %v", err)
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Action != "test" {
		t.Errorf("expected action 'test', got %q", events[0].Action)
	}
}

func TestStoreInsertScanResult(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	err = store.InsertScanResult(
		"scan-001", "skill-scanner", "/path/to/skill",
		time.Now(), 1500, 2, "HIGH", `{"scanner":"skill-scanner"}`,
	)
	if err != nil {
		t.Fatalf("InsertScanResult: %v", err)
	}
}
