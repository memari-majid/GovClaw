package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// activeSpan tracks a pending tool call span with its start time.
type activeSpan struct {
	span      trace.Span
	ctx       context.Context
	startTime time.Time
	tool      string
	provider  string
}

// EventRouter dispatches gateway events to the appropriate handlers and logs
// everything to the audit store.
type EventRouter struct {
	client *Client
	store  *audit.Store
	logger *audit.Logger
	policy *enforce.PolicyEngine
	otel   *telemetry.Provider

	autoApprove     bool
	activeToolSpans map[string][]*activeSpan
	spanMu          sync.Mutex
}

// NewEventRouter creates a router that handles gateway events for the sidecar.
func NewEventRouter(client *Client, store *audit.Store, logger *audit.Logger, autoApprove bool, otel *telemetry.Provider) *EventRouter {
	return &EventRouter{
		client:          client,
		store:           store,
		logger:          logger,
		policy:          enforce.NewPolicyEngine(store),
		otel:            otel,
		autoApprove:     autoApprove,
		activeToolSpans: make(map[string][]*activeSpan),
	}
}

// Route dispatches a single event frame to the correct handler.
func (r *EventRouter) Route(evt EventFrame) {
	switch evt.Event {
	case "tool_call":
		r.handleToolCall(evt)
	case "tool_result":
		r.handleToolResult(evt)
	case "exec.approval.requested":
		r.handleApprovalRequest(evt)
	case "session.tool":
		r.handleSessionTool(evt)
	case "agent":
		r.handleAgentEvent(evt)
	case "tick", "health", "chat", "presence", "heartbeat",
		"sessions.changed", "session.message",
		"exec.approval.resolved":
		// known events, no action needed from router
	default:
		fmt.Fprintf(os.Stderr, "[sidecar] unhandled event: %s (payload_len=%d)\n",
			evt.Event, len(evt.Payload))
	}
}

// SessionToolPayload is the payload of a session.tool event from OpenClaw.
// OpenClaw sends tool execution data as session.tool rather than separate
// tool_call/tool_result events.
type SessionToolPayload struct {
	Type     string          `json:"type"`     // "call" or "result"
	Tool     string          `json:"tool"`
	Name     string          `json:"name"`
	Args     json.RawMessage `json:"args,omitempty"`
	Input    json.RawMessage `json:"input,omitempty"`
	Output   string          `json:"output,omitempty"`
	Result   string          `json:"result,omitempty"`
	Status   string          `json:"status,omitempty"`
	ExitCode *int            `json:"exit_code,omitempty"`
	CallID   string          `json:"callId,omitempty"`
}

func (r *EventRouter) handleSessionTool(evt EventFrame) {
	var payload SessionToolPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse session.tool: %v\n", err)
		fmt.Fprintf(os.Stderr, "[sidecar] raw session.tool payload: %s\n", string(evt.Payload))
		return
	}

	toolName := payload.Tool
	if toolName == "" {
		toolName = payload.Name
	}

	fmt.Fprintf(os.Stderr, "[sidecar] session.tool type=%s tool=%s status=%s callId=%s\n",
		payload.Type, toolName, payload.Status, payload.CallID)

	switch payload.Type {
	case "call", "invoke", "":
		args := payload.Args
		if args == nil {
			args = payload.Input
		}
		syntheticEvt := EventFrame{
			Type:    evt.Type,
			Event:   "tool_call",
			Payload: mustMarshal(ToolCallPayload{Tool: toolName, Args: args, Status: payload.Status}),
			Seq:     evt.Seq,
		}
		r.handleToolCall(syntheticEvt)

	case "result", "output", "response":
		output := payload.Output
		if output == "" {
			output = payload.Result
		}
		syntheticEvt := EventFrame{
			Type:    evt.Type,
			Event:   "tool_result",
			Payload: mustMarshal(ToolResultPayload{Tool: toolName, Output: output, ExitCode: payload.ExitCode}),
			Seq:     evt.Seq,
		}
		r.handleToolResult(syntheticEvt)

	default:
		fmt.Fprintf(os.Stderr, "[sidecar] session.tool unknown type=%s raw=%s\n",
			payload.Type, truncate(string(evt.Payload), 200))
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// agentEventPayload is the structure of an agent streaming event.
// Tool calls appear as type=tool_call or contain toolCall/toolResult fields.
type agentEventPayload struct {
	Type       string          `json:"type"`
	ToolCall   *agentToolCall  `json:"toolCall,omitempty"`
	ToolResult *agentToolResult `json:"toolResult,omitempty"`
	Content    json.RawMessage `json:"content,omitempty"`
}

type agentToolCall struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args,omitempty"`
	Input  json.RawMessage `json:"input,omitempty"`
	Status string          `json:"status,omitempty"`
}

type agentToolResult struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Tool     string `json:"tool"`
	Output   string `json:"output,omitempty"`
	ExitCode *int   `json:"exitCode,omitempty"`
}

func (r *EventRouter) handleAgentEvent(evt EventFrame) {
	var payload agentEventPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		return
	}

	if payload.ToolCall != nil {
		tc := payload.ToolCall
		toolName := tc.Name
		if toolName == "" {
			toolName = tc.Tool
		}
		if toolName == "" {
			return
		}
		args := tc.Args
		if args == nil {
			args = tc.Input
		}

		fmt.Fprintf(os.Stderr, "[sidecar] agent event: tool_call tool=%s id=%s\n", toolName, tc.ID)

		syntheticEvt := EventFrame{
			Type:    evt.Type,
			Event:   "tool_call",
			Payload: mustMarshal(ToolCallPayload{Tool: toolName, Args: args, Status: tc.Status}),
			Seq:     evt.Seq,
		}
		r.handleToolCall(syntheticEvt)
	}

	if payload.ToolResult != nil {
		tr := payload.ToolResult
		toolName := tr.Name
		if toolName == "" {
			toolName = tr.Tool
		}
		if toolName == "" {
			return
		}

		fmt.Fprintf(os.Stderr, "[sidecar] agent event: tool_result tool=%s id=%s\n", toolName, tr.ID)

		syntheticEvt := EventFrame{
			Type:    evt.Type,
			Event:   "tool_result",
			Payload: mustMarshal(ToolResultPayload{Tool: toolName, Output: tr.Output, ExitCode: tr.ExitCode}),
			Seq:     evt.Seq,
		}
		r.handleToolResult(syntheticEvt)
	}
}

func (r *EventRouter) handleToolCall(evt EventFrame) {
	var payload ToolCallPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse tool_call: %v\n", err)
		return
	}

	_ = r.logger.LogAction("gateway-tool-call", payload.Tool,
		fmt.Sprintf("status=%s args_length=%d", payload.Status, len(payload.Args)))

	dangerous := r.isDangerousTool(payload.Tool, payload.Args)
	flaggedPattern := ""
	if dangerous {
		flaggedPattern = r.matchedPattern(payload.Tool, payload.Args)
		_ = r.logger.LogAction("gateway-tool-call-flagged", payload.Tool,
			fmt.Sprintf("reason=dangerous-pattern pattern=%s", flaggedPattern))
		fmt.Fprintf(os.Stderr, "[sidecar] FLAGGED tool call: %s\n", payload.Tool)
	}

	if r.otel != nil {
		ctx, span := r.otel.StartToolSpan(
			context.Background(),
			payload.Tool, payload.Status, payload.Args,
			dangerous, flaggedPattern, "builtin", "",
		)
		r.spanMu.Lock()
		r.activeToolSpans[payload.Tool] = append(r.activeToolSpans[payload.Tool], &activeSpan{
			span:      span,
			ctx:       ctx,
			startTime: time.Now(),
			tool:      payload.Tool,
			provider:  "builtin",
		})
		r.spanMu.Unlock()
	}
}

func (r *EventRouter) handleToolResult(evt EventFrame) {
	var payload ToolResultPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse tool_result: %v\n", err)
		return
	}

	exitCode := 0
	if payload.ExitCode != nil {
		exitCode = *payload.ExitCode
	}

	_ = r.logger.LogAction("gateway-tool-result", payload.Tool,
		fmt.Sprintf("exit_code=%d output_len=%d", exitCode, len(payload.Output)))

	if r.otel != nil {
		r.spanMu.Lock()
		var as *activeSpan
		if q := r.activeToolSpans[payload.Tool]; len(q) > 0 {
			as = q[0]
			r.activeToolSpans[payload.Tool] = q[1:]
			if len(r.activeToolSpans[payload.Tool]) == 0 {
				delete(r.activeToolSpans, payload.Tool)
			}
		}
		r.spanMu.Unlock()

		if as != nil {
			r.otel.EndToolSpan(as.span, exitCode, len(payload.Output), as.startTime, as.tool, as.provider)
		}
	}
}

func (r *EventRouter) handleApprovalRequest(evt EventFrame) {
	var payload ApprovalRequestPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse exec.approval.requested: %v\n", err)
		return
	}

	rawCmd := ""
	var argv []string
	cwd := ""
	if payload.SystemRunPlan != nil {
		rawCmd = payload.SystemRunPlan.RawCommand
		argv = payload.SystemRunPlan.Argv
		cwd = payload.SystemRunPlan.Cwd
	}

	cmdName := baseCommand(rawCmd)
	_ = r.logger.LogAction("gateway-approval-requested", payload.ID,
		fmt.Sprintf("command_name=%s argc=%d", cmdName, len(argv)))

	var approvalSpan trace.Span
	if r.otel != nil {
		_, approvalSpan = r.otel.StartApprovalSpan(context.Background(), payload.ID, rawCmd, argv, cwd)
	}

	dangerous := r.isCommandDangerous(rawCmd)

	if dangerous {
		_ = r.logger.LogAction("gateway-approval-denied", payload.ID,
			fmt.Sprintf("reason=dangerous-command command_name=%s", cmdName))
		fmt.Fprintf(os.Stderr, "[sidecar] DENIED exec approval: %s\n", cmdName)

		if r.otel != nil {
			r.otel.EndApprovalSpan(approvalSpan, "denied", "dangerous-command", false, true)

			r.otel.EmitRuntimeAlert(
				telemetry.AlertDangerousCommand, "HIGH", telemetry.SourceLocalPattern,
				fmt.Sprintf("Dangerous command blocked: %s", cmdName),
				map[string]string{"tool": "shell", "command": rawCmd},
				map[string]string{"action_taken": "deny"},
				"", "",
			)
		}

		ctx, cancel := r.approvalCtx()
		defer cancel()
		if err := r.client.ResolveApproval(ctx, payload.ID, false,
			"defenseclaw: command matched dangerous pattern"); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] resolve approval error: %v\n", err)
		}
		return
	}

	if r.autoApprove {
		_ = r.logger.LogAction("gateway-approval-granted", payload.ID,
			fmt.Sprintf("reason=auto-approve command_name=%s", cmdName))
		fmt.Fprintf(os.Stderr, "[sidecar] AUTO-APPROVED exec: %s\n", cmdName)

		if r.otel != nil {
			r.otel.EndApprovalSpan(approvalSpan, "approved", "auto-approved safe command", true, false)
		}

		ctx, cancel := r.approvalCtx()
		defer cancel()
		if err := r.client.ResolveApproval(ctx, payload.ID, true,
			"defenseclaw: auto-approved safe command"); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] resolve approval error: %v\n", err)
		}
		return
	}

	if r.otel != nil {
		r.otel.EndApprovalSpan(approvalSpan, "pending", "awaiting manual approval", false, false)
	}
}

// approvalCtx returns a context with a timeout for approval resolution RPCs.
// The caller is responsible for calling the returned cancel function.
func (r *EventRouter) approvalCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

var dangerousPatterns = []string{
	"curl",
	"wget",
	"nc ",
	"ncat",
	"netcat",
	"/dev/tcp",
	"base64 -d",
	"base64 --decode",
	"eval ",
	"bash -c",
	"sh -c",
	"python -c",
	"perl -e",
	"ruby -e",
	"rm -rf /",
	"dd if=",
	"mkfs",
	"chmod 777",
	"> /etc/",
	">> /etc/",
	"passwd",
	"shadow",
	"sudoers",
}

func (r *EventRouter) isDangerousTool(tool string, args json.RawMessage) bool {
	if tool != "shell" && tool != "system.run" && tool != "exec" {
		return false
	}

	argsStr := strings.ToLower(string(args))
	for _, pattern := range dangerousPatterns {
		if strings.Contains(argsStr, pattern) {
			return true
		}
	}
	return false
}

func (r *EventRouter) matchedPattern(tool string, args json.RawMessage) string {
	argsStr := strings.ToLower(string(args))
	for _, pattern := range dangerousPatterns {
		if strings.Contains(argsStr, pattern) {
			return pattern
		}
	}
	return ""
}

func (r *EventRouter) isCommandDangerous(rawCmd string) bool {
	lower := strings.ToLower(rawCmd)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func baseCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	fields := strings.Fields(cmd)
	base := fields[0]
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	return base
}
