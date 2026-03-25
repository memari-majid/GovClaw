package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// StartToolSpan starts a new OTel span for a tool_call event.
// Raw args are not exported to avoid leaking tokens, keys, or prompt content.
// Metrics are always recorded when OTel is enabled, even if traces are off.
func (p *Provider) StartToolSpan(
	ctx context.Context,
	tool, status string,
	args json.RawMessage,
	dangerous bool,
	flaggedPattern, toolProvider, skillKey string,
) (context.Context, trace.Span) {
	p.RecordToolCall(ctx, tool, toolProvider, dangerous)

	if !p.TracesEnabled() {
		return ctx, nil
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("tool/%s", tool),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("defenseclaw.tool.name", tool),
		attribute.String("defenseclaw.tool.status", status),
		attribute.Int("defenseclaw.tool.args_length", len(args)),
		attribute.Bool("defenseclaw.tool.dangerous", dangerous),
		attribute.String("defenseclaw.tool.provider", toolProvider),
	)

	if skillKey != "" {
		span.SetAttributes(attribute.String("defenseclaw.tool.skill_key", skillKey))
	}

	if flaggedPattern != "" {
		span.SetAttributes(attribute.String("defenseclaw.tool.flagged_pattern", flaggedPattern))
		span.AddEvent("tool.flagged", trace.WithAttributes(
			attribute.String("defenseclaw.flag.reason", "dangerous-pattern"),
			attribute.String("defenseclaw.flag.pattern", flaggedPattern),
		))
	}

	return ctx, span
}

// EndToolSpan ends an active tool call span with result data.
// Metrics are always recorded when OTel is enabled, even if the span is nil
// (traces disabled).
func (p *Provider) EndToolSpan(span trace.Span, exitCode, outputLen int, startTime time.Time, tool, toolProvider string) {
	ctx := context.Background()
	durationMs := float64(time.Since(startTime).Milliseconds())

	if exitCode != 0 {
		p.RecordToolError(ctx, tool, exitCode)
	}
	p.RecordToolDuration(ctx, tool, toolProvider, durationMs)

	if span == nil {
		return
	}

	span.SetAttributes(
		attribute.Int("defenseclaw.tool.exit_code", exitCode),
		attribute.Int("defenseclaw.tool.output_length", outputLen),
	)

	if exitCode != 0 {
		span.SetStatus(codes.Error, fmt.Sprintf("exit_code=%d", exitCode))
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// StartApprovalSpan starts a new OTel span for an exec approval request.
// Raw command strings and argv are not exported to avoid leaking tokens or secrets.
func (p *Provider) StartApprovalSpan(
	ctx context.Context,
	id, command string,
	argv []string,
	cwd string,
) (context.Context, trace.Span) {
	if !p.TracesEnabled() {
		return ctx, nil
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("exec.approval/%s", id),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("defenseclaw.approval.id", id),
		attribute.String("defenseclaw.approval.command_name", baseCommand(command)),
		attribute.Int("defenseclaw.approval.argc", len(argv)),
	)

	return ctx, span
}

// EndApprovalSpan ends an active approval span with the resolution.
// Metrics are always recorded when OTel is enabled, even if the span is nil
// (traces disabled).
func (p *Provider) EndApprovalSpan(span trace.Span, result, reason string, auto, dangerous bool) {
	p.RecordApproval(context.Background(), result, auto, dangerous)

	if span == nil {
		return
	}

	span.SetAttributes(
		attribute.String("defenseclaw.approval.result", result),
		attribute.String("defenseclaw.approval.reason", reason),
		attribute.Bool("defenseclaw.approval.auto", auto),
		attribute.Bool("defenseclaw.approval.dangerous", dangerous),
	)

	if result == "denied" || result == "timeout" {
		span.SetStatus(codes.Error, result)
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// StartLLMSpan starts a new OTel span for an LLM call (future-ready).
// Metrics are always recorded when OTel is enabled, even if traces are off.
func (p *Provider) StartLLMSpan(
	ctx context.Context,
	system, model, provider string,
	maxTokens int,
	temperature float64,
) (context.Context, trace.Span) {
	p.RecordLLMCall(ctx, system, model)

	if !p.TracesEnabled() {
		return ctx, nil
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("llm/%s", model),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("gen_ai.system", system),
		attribute.String("gen_ai.request.model", model),
		attribute.Int("gen_ai.request.max_tokens", maxTokens),
		attribute.Float64("gen_ai.request.temperature", temperature),
		attribute.String("defenseclaw.llm.provider", provider),
	)

	return ctx, span
}

// EndLLMSpan ends an active LLM call span with response data.
// Metrics are always recorded when OTel is enabled, even if the span is nil
// (traces disabled).
func (p *Provider) EndLLMSpan(
	span trace.Span,
	responseModel string,
	promptTokens, completionTokens int,
	finishReasons []string,
	toolCallCount int,
	guardrail, guardrailResult string,
	system string,
	startTime time.Time,
) {
	ctx := context.Background()
	durationMs := float64(time.Since(startTime).Milliseconds())
	p.RecordLLMTokens(ctx, system, int64(promptTokens), int64(completionTokens))
	p.RecordLLMDuration(ctx, system, responseModel, durationMs)

	if span == nil {
		return
	}

	span.SetAttributes(
		attribute.String("gen_ai.response.model", responseModel),
		attribute.StringSlice("gen_ai.response.finish_reasons", finishReasons),
		attribute.Int("gen_ai.usage.prompt_tokens", promptTokens),
		attribute.Int("gen_ai.usage.completion_tokens", completionTokens),
		attribute.Int("defenseclaw.llm.tool_calls", toolCallCount),
		attribute.String("defenseclaw.llm.guardrail", guardrail),
		attribute.String("defenseclaw.llm.guardrail.result", guardrailResult),
	)

	if guardrailResult == "blocked" {
		span.SetStatus(codes.Error, "guardrail blocked")
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// baseCommand extracts the executable name from a command string,
// stripping path prefixes and arguments to avoid leaking sensitive content.
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

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
