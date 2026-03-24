package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type mcpItem struct {
	URL     string
	Status  string
	Actions string
	Reason  string
	Time    string
}

type MCPsPanel struct {
	items   []mcpItem
	cursor  int
	width   int
	height  int
	store   *audit.Store
	message string
}

func NewMCPsPanel(store *audit.Store) MCPsPanel {
	return MCPsPanel{store: store}
}

func (p *MCPsPanel) Refresh() {
	if p.store == nil {
		return
	}

	p.items = nil

	entries, err := p.store.ListActionsByType("mcp")
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	for _, e := range entries {
		var status string
		switch e.Actions.Install {
		case "block":
			status = "blocked"
		case "allow":
			status = "allowed"
		default:
			status = "active"
		}
		p.items = append(p.items, mcpItem{
			URL:     e.TargetName,
			Status:  status,
			Actions: e.Actions.Summary(),
			Reason:  e.Reason,
			Time:    e.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}

	if p.cursor >= len(p.items) && len(p.items) > 0 {
		p.cursor = len(p.items) - 1
	}
	p.message = ""
}

func (p *MCPsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *MCPsPanel) CursorUp()   { if p.cursor > 0 { p.cursor-- } }
func (p *MCPsPanel) CursorDown() { if p.cursor < len(p.items)-1 { p.cursor++ } }

func (p *MCPsPanel) Selected() *mcpItem {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p *MCPsPanel) ToggleBlock() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	if sel.Status == "blocked" {
		_ = p.store.SetActionField("mcp", sel.URL, "install", "allow", "unblocked from TUI")
		p.Refresh()
		return fmt.Sprintf("Allowed MCP: %s", sel.URL)
	}
	_ = p.store.SetActionField("mcp", sel.URL, "install", "block", "blocked from TUI")
	p.Refresh()
	return fmt.Sprintf("Blocked MCP: %s", sel.URL)
}

func (p *MCPsPanel) Count() int { return len(p.items) }
func (p *MCPsPanel) BlockedCount() int {
	n := 0
	for _, i := range p.items {
		if i.Status == "blocked" {
			n++
		}
	}
	return n
}

func (p *MCPsPanel) View() string {
	if p.message != "" {
		return p.message
	}
	if len(p.items) == 0 {
		return StyleInfo.Render("  No MCP servers with enforcement actions. Use 'defenseclaw block mcp' or 'defenseclaw allow mcp' to add.")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-10s %-40s %-20s %-20s %-16s", "STATUS", "URL", "ACTIONS", "REASON", "SINCE")
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
		status := StatusStyle(item.Status).Render(fmt.Sprintf("%-10s", strings.ToUpper(item.Status)))
		url := item.URL
		if len(url) > 40 {
			url = url[:37] + "..."
		}
		actions := item.Actions
		if len(actions) > 20 {
			actions = actions[:17] + "..."
		}
		reason := item.Reason
		if len(reason) > 20 {
			reason = reason[:17] + "..."
		}

		line := fmt.Sprintf("  %s %-40s %-20s %-20s %-16s", status, url, actions, reason, item.Time)

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
