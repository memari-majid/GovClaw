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

package plugins

import (
	"context"
	"time"
)

type Scanner interface {
	Name() string
	Version() string
	SupportedTargets() []string
	Scan(ctx context.Context, target string) (*ScanResult, error)
}

type ScanResult struct {
	Scanner   string        `json:"scanner"`
	Target    string        `json:"target"`
	Timestamp time.Time     `json:"timestamp"`
	Findings  []Finding     `json:"findings"`
	Duration  time.Duration `json:"duration"`
}

type Finding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Location    string   `json:"location"`
	Remediation string   `json:"remediation"`
	Scanner     string   `json:"scanner"`
	Tags        []string `json:"tags"`
}
