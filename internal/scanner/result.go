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

package scanner

import (
	"encoding/json"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

var severityRank = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
}

type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Location    string   `json:"location"`
	Remediation string   `json:"remediation"`
	Scanner     string   `json:"scanner"`
	Tags        []string `json:"tags"`
}

type ScanResult struct {
	Scanner   string        `json:"scanner"`
	Target    string        `json:"target"`
	Timestamp time.Time     `json:"timestamp"`
	Findings  []Finding     `json:"findings"`
	Duration  time.Duration `json:"duration"`
}

func (r *ScanResult) HasSeverity(s Severity) bool {
	for i := range r.Findings {
		if r.Findings[i].Severity == s {
			return true
		}
	}
	return false
}

func (r *ScanResult) MaxSeverity() Severity {
	if len(r.Findings) == 0 {
		return SeverityInfo
	}
	max := r.Findings[0].Severity
	for i := 1; i < len(r.Findings); i++ {
		if severityRank[r.Findings[i].Severity] > severityRank[max] {
			max = r.Findings[i].Severity
		}
	}
	return max
}

func (r *ScanResult) CountBySeverity(s Severity) int {
	count := 0
	for i := range r.Findings {
		if r.Findings[i].Severity == s {
			count++
		}
	}
	return count
}

func (r *ScanResult) IsClean() bool {
	return len(r.Findings) == 0
}

func CompareSeverity(a, b Severity) int {
	return severityRank[a] - severityRank[b]
}

func (r *ScanResult) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
