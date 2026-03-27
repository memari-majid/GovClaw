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

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type AlertsPanel struct {
	items    []audit.Event
	cursor   int
	width    int
	height   int
	store    *audit.Store
	message  string
}

func NewAlertsPanel(store *audit.Store) AlertsPanel {
	return AlertsPanel{store: store}
}

func (p *AlertsPanel) Refresh() {
	if p.store == nil {
		return
	}
	alerts, err := p.store.ListAlerts(100)
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	p.items = alerts
	if p.cursor >= len(p.items) && len(p.items) > 0 {
		p.cursor = len(p.items) - 1
	}
	p.message = ""
}

func (p *AlertsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *AlertsPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

func (p *AlertsPanel) CursorDown() {
	if p.cursor < len(p.items)-1 {
		p.cursor++
	}
}

func (p *AlertsPanel) Selected() *audit.Event {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p *AlertsPanel) Dismiss() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	if p.store != nil {
		_ = p.store.LogEvent(audit.Event{
			Action:   "dismiss-alert",
			Target:   sel.Target,
			Details:  fmt.Sprintf("dismissed alert %s", sel.ID),
			Severity: "INFO",
		})
	}
	p.Refresh()
	return fmt.Sprintf("Dismissed alert for %s", sel.Target)
}

func (p *AlertsPanel) Count() int {
	return len(p.items)
}

func (p *AlertsPanel) View() string {
	if p.message != "" {
		return p.message
	}

	if len(p.items) == 0 {
		return StyleInfo.Render("  No alerts. All clear.")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-10s %-19s %-20s %-30s", "SEVERITY", "TIME", "ACTION", "TARGET")
	b.WriteString(HeaderStyle.Render(header))
	b.WriteString("\n")

	maxVisible := p.height - 4
	if maxVisible < 1 {
		maxVisible = 10
	}

	start := 0
	if p.cursor >= maxVisible {
		start = p.cursor - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(p.items) {
		end = len(p.items)
	}

	for i := start; i < end; i++ {
		item := p.items[i]
		sev := SeverityStyle(item.Severity).Render(fmt.Sprintf("%-10s", item.Severity))
		ts := item.Timestamp.Format("2006-01-02 15:04")
		target := item.Target
		if len(target) > 30 {
			target = target[:27] + "..."
		}
		action := item.Action
		if len(action) > 20 {
			action = action[:17] + "..."
		}

		line := fmt.Sprintf("  %s %-19s %-20s %-30s", sev, ts, action, target)

		if i == p.cursor {
			line = SelectedStyle.Width(p.width).Render(line)
		}
		b.WriteString(line)
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	if len(p.items) > maxVisible {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(
			fmt.Sprintf("  showing %d-%d of %d", start+1, end, len(p.items)),
		))
	}

	return b.String()
}
