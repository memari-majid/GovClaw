package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// metricsSet holds all registered OTel instruments.
type metricsSet struct {
	// Scan metrics
	scanCount         metric.Int64Counter
	scanDuration      metric.Float64Histogram
	scanFindings      metric.Int64Counter
	scanFindingsGauge metric.Int64UpDownCounter

	// Runtime metrics
	toolCalls     metric.Int64Counter
	toolDuration  metric.Float64Histogram
	toolErrors    metric.Int64Counter
	approvalCount metric.Int64Counter
	llmCalls      metric.Int64Counter
	llmTokens     metric.Int64Counter
	llmDuration   metric.Float64Histogram

	// Alert metrics
	alertCount           metric.Int64Counter
	guardrailEvaluations metric.Int64Counter
	guardrailLatency     metric.Float64Histogram
}

func newMetricsSet(m metric.Meter) (*metricsSet, error) {
	var ms metricsSet
	var err error

	ms.scanCount, err = m.Int64Counter("defenseclaw.scan.count",
		metric.WithUnit("{scan}"),
		metric.WithDescription("Total number of scans completed"))
	if err != nil {
		return nil, err
	}

	ms.scanDuration, err = m.Float64Histogram("defenseclaw.scan.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Scan duration distribution"))
	if err != nil {
		return nil, err
	}

	ms.scanFindings, err = m.Int64Counter("defenseclaw.scan.findings",
		metric.WithUnit("{finding}"),
		metric.WithDescription("Total findings across all scans"))
	if err != nil {
		return nil, err
	}

	ms.scanFindingsGauge, err = m.Int64UpDownCounter("defenseclaw.scan.findings.gauge",
		metric.WithUnit("{finding}"),
		metric.WithDescription("Current open finding count"))
	if err != nil {
		return nil, err
	}

	ms.toolCalls, err = m.Int64Counter("defenseclaw.tool.calls",
		metric.WithUnit("{call}"),
		metric.WithDescription("Total tool calls observed"))
	if err != nil {
		return nil, err
	}

	ms.toolDuration, err = m.Float64Histogram("defenseclaw.tool.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Tool call duration distribution"))
	if err != nil {
		return nil, err
	}

	ms.toolErrors, err = m.Int64Counter("defenseclaw.tool.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Tool calls that returned non-zero exit codes"))
	if err != nil {
		return nil, err
	}

	ms.approvalCount, err = m.Int64Counter("defenseclaw.approval.count",
		metric.WithUnit("{request}"),
		metric.WithDescription("Exec approval requests processed"))
	if err != nil {
		return nil, err
	}

	ms.llmCalls, err = m.Int64Counter("defenseclaw.llm.calls",
		metric.WithUnit("{call}"),
		metric.WithDescription("Total LLM calls observed"))
	if err != nil {
		return nil, err
	}

	ms.llmTokens, err = m.Int64Counter("defenseclaw.llm.tokens",
		metric.WithUnit("{token}"),
		metric.WithDescription("Total tokens consumed"))
	if err != nil {
		return nil, err
	}

	ms.llmDuration, err = m.Float64Histogram("defenseclaw.llm.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("LLM call duration distribution"))
	if err != nil {
		return nil, err
	}

	ms.alertCount, err = m.Int64Counter("defenseclaw.alert.count",
		metric.WithUnit("{alert}"),
		metric.WithDescription("Total runtime alerts emitted"))
	if err != nil {
		return nil, err
	}

	ms.guardrailEvaluations, err = m.Int64Counter("defenseclaw.guardrail.evaluations",
		metric.WithUnit("{evaluation}"),
		metric.WithDescription("Total guardrail evaluations performed"))
	if err != nil {
		return nil, err
	}

	ms.guardrailLatency, err = m.Float64Histogram("defenseclaw.guardrail.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("Guardrail evaluation latency distribution"))
	if err != nil {
		return nil, err
	}

	return &ms, nil
}

// RecordScan records scan-related metrics.
func (p *Provider) RecordScan(ctx context.Context, scanner, targetType, verdict string, durationMs float64, findings map[string]int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}

	baseAttrs := metric.WithAttributes(
		attribute.String("scanner", scanner),
		attribute.String("target_type", targetType),
	)

	p.metrics.scanCount.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scanner", scanner),
		attribute.String("target_type", targetType),
		attribute.String("verdict", verdict),
	))
	p.metrics.scanDuration.Record(ctx, durationMs, baseAttrs)

	for severity, count := range findings {
		if count > 0 {
			p.metrics.scanFindings.Add(ctx, int64(count), metric.WithAttributes(
				attribute.String("scanner", scanner),
				attribute.String("target_type", targetType),
				attribute.String("severity", severity),
			))
			p.metrics.scanFindingsGauge.Add(ctx, int64(count), metric.WithAttributes(
				attribute.String("target_type", targetType),
				attribute.String("severity", severity),
			))
		}
	}
}

// RecordToolCall records a tool call metric.
func (p *Provider) RecordToolCall(ctx context.Context, tool, provider string, dangerous bool) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.toolCalls.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tool.name", tool),
		attribute.String("tool.provider", provider),
		attribute.Bool("dangerous", dangerous),
	))
}

// RecordToolDuration records a tool call duration metric.
func (p *Provider) RecordToolDuration(ctx context.Context, tool, provider string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.toolDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("tool.name", tool),
		attribute.String("tool.provider", provider),
	))
}

// RecordToolError records a tool error metric.
func (p *Provider) RecordToolError(ctx context.Context, tool string, exitCode int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.toolErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tool.name", tool),
		attribute.Int("exit_code", exitCode),
	))
}

// RecordApproval records an approval request metric.
func (p *Provider) RecordApproval(ctx context.Context, result string, auto, dangerous bool) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.approvalCount.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result),
		attribute.Bool("auto", auto),
		attribute.Bool("dangerous", dangerous),
	))
}

// RecordLLMCall records an LLM call metric.
func (p *Provider) RecordLLMCall(ctx context.Context, system, model string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.llmCalls.Add(ctx, 1, metric.WithAttributes(
		attribute.String("gen_ai.system", system),
		attribute.String("gen_ai.request.model", model),
	))
}

// RecordLLMTokens records token consumption metrics.
func (p *Provider) RecordLLMTokens(ctx context.Context, system string, prompt, completion int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	if prompt > 0 {
		p.metrics.llmTokens.Add(ctx, prompt, metric.WithAttributes(
			attribute.String("gen_ai.system", system),
			attribute.String("token.type", "prompt"),
		))
	}
	if completion > 0 {
		p.metrics.llmTokens.Add(ctx, completion, metric.WithAttributes(
			attribute.String("gen_ai.system", system),
			attribute.String("token.type", "completion"),
		))
	}
}

// RecordLLMDuration records LLM call duration.
func (p *Provider) RecordLLMDuration(ctx context.Context, system, model string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.llmDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("gen_ai.system", system),
		attribute.String("gen_ai.request.model", model),
	))
}

// RecordAlert records a runtime alert metric.
func (p *Provider) RecordAlert(ctx context.Context, alertType, severity, source string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.alertCount.Add(ctx, 1, metric.WithAttributes(
		attribute.String("alert.type", alertType),
		attribute.String("alert.severity", severity),
		attribute.String("alert.source", source),
	))
}

// RecordGuardrailEvaluation records a guardrail evaluation metric.
func (p *Provider) RecordGuardrailEvaluation(ctx context.Context, scanner, actionTaken string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.guardrailEvaluations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("guardrail.scanner", scanner),
		attribute.String("guardrail.action_taken", actionTaken),
	))
}

// RecordGuardrailLatency records guardrail evaluation latency.
func (p *Provider) RecordGuardrailLatency(ctx context.Context, scanner string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.guardrailLatency.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("guardrail.scanner", scanner),
	))
}
