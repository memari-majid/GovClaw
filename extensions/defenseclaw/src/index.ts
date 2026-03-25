/**
 * DefenseClaw OpenClaw Plugin
 *
 * Integrates DefenseClaw security into the OpenClaw plugin lifecycle:
 *
 * Runtime:
 *  - before_tool_call: intercepts tool calls via the Go sidecar inspect API
 *
 * Slash commands:
 *  - /scan <path>: scan a skill directory
 *  - /block <type> <name> [reason]: block a skill, MCP, or plugin
 *  - /allow <type> <name> [reason]: allow-list a skill, MCP, or plugin
 *
 * The plugin uses:
 *  1. Native TS scanners for plugins and MCP configs (in-process, fast)
 *  2. CLI shell-out to `defenseclaw` for skill/code scans (full scanner suite)
 *  3. REST API to the Go sidecar for tool inspection and audit logging
 */

import type { PluginApi } from "@openclaw/plugin-sdk";
import { PolicyEnforcer, runSkillScan } from "./policy/enforcer.js";
import { scanPlugin } from "./scanners/plugin_scanner/index.js";
import { scanMCPServer } from "./scanners/mcp-scanner.js";
import type {
  ScanResult,
  Finding,
  InstallType,
} from "./types.js";
import { compareSeverity, maxSeverity } from "./types.js";
import { loadSidecarConfig } from "./sidecar-config.js";

function formatFindings(findings: Finding[], limit = 15): string[] {
  const lines: string[] = [];
  const sorted = [...findings].sort(
    (a, b) => compareSeverity(b.severity, a.severity),
  );

  for (const f of sorted.slice(0, limit)) {
    const loc = f.location ? ` (${f.location})` : "";
    lines.push(`- **[${f.severity}]** ${f.title}${loc}`);
  }

  if (findings.length > limit) {
    lines.push(`- ... and ${findings.length - limit} more`);
  }

  return lines;
}

export default function (api: PluginApi) {
  const enforcer = new PolicyEnforcer();

  // ─── Runtime: tool call interception ───

  const SIDECAR_API = loadSidecarConfig().baseUrl;
  const INSPECT_TIMEOUT_MS = 2_000;

  async function inspectTool(
    payload: Record<string, unknown>,
  ): Promise<{ action: string; severity: string; reason: string; mode: string }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), INSPECT_TIMEOUT_MS);
    try {
      const res = await fetch(`${SIDECAR_API}/api/v1/inspect/tool`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      return (await res.json()) as {
        action: string;
        severity: string;
        reason: string;
        mode: string;
      };
    } catch {
      return { action: "allow", severity: "NONE", reason: "sidecar unreachable", mode: "observe" };
    } finally {
      clearTimeout(timer);
    }
  }

  api.on("before_tool_call", async (event) => {
    if (event.toolName === "message") {
      const content =
        (event.args?.content as string) || (event.args?.body as string) || "";
      if (!content) return;

      const verdict = await inspectTool({
        tool: "message",
        args: event.args,
        content,
        direction: "outbound",
      });

      console.log(
        `[defenseclaw] message-tool verdict:${verdict.action} severity:${verdict.severity}`,
      );

      if (verdict.action === "block" && verdict.mode === "action") {
        event.cancel(`DefenseClaw: outbound blocked — ${verdict.reason}`);
      }
      return;
    }

    const verdict = await inspectTool({
      tool: event.toolName,
      args: event.args,
    });

    console.log(
      `[defenseclaw] tool:${event.toolName} verdict:${verdict.action} severity:${verdict.severity}`,
    );

    if (verdict.action === "block" && verdict.mode === "action") {
      event.cancel(`DefenseClaw: ${verdict.reason}`);
    }
  });

  // ─── Slash command: /scan ───

  api.registerCommand({
    name: "scan",
    description: "Scan a skill, plugin, or MCP config with DefenseClaw",
    args: [
      { name: "target", description: "Path to skill/plugin directory or MCP config", required: true },
      { name: "type", description: "Scan type: skill (default), plugin, mcp", required: false },
    ],
    handler: async ({ args }) => {
      const target = args.target as string | undefined;
      if (!target) {
        return { text: "Usage: /scan <path> [skill|plugin|mcp]" };
      }

      const scanType = (args.type ?? "skill") as string;

      if (scanType === "plugin") {
        return handlePluginScan(target);
      }

      if (scanType === "mcp") {
        return handleMCPScan(target);
      }

      return handleSkillScan(target);
    },
  });

  // ─── Slash command: /block ───

  api.registerCommand({
    name: "block",
    description: "Block a skill, MCP server, or plugin",
    args: [
      { name: "type", description: "Target type: skill, mcp, plugin", required: true },
      { name: "name", description: "Name of the target to block", required: true },
      { name: "reason", description: "Reason for blocking", required: false },
    ],
    handler: async ({ args }) => {
      const targetType = args.type as InstallType | undefined;
      const name = args.name as string | undefined;
      if (!targetType || !name) {
        return { text: "Usage: /block <skill|mcp|plugin> <name> [reason]" };
      }

      const reason = (args.reason as string) || "Blocked via /block command";

      await enforcer.block(targetType, name, reason);
      return {
        text: `Blocked ${targetType} **${name}**: ${reason}`,
      };
    },
  });

  // ─── Slash command: /allow ───

  api.registerCommand({
    name: "allow",
    description: "Allow-list a skill, MCP server, or plugin",
    args: [
      { name: "type", description: "Target type: skill, mcp, plugin", required: true },
      { name: "name", description: "Name of the target to allow", required: true },
      { name: "reason", description: "Reason for allowing", required: false },
    ],
    handler: async ({ args }) => {
      const targetType = args.type as InstallType | undefined;
      const name = args.name as string | undefined;
      if (!targetType || !name) {
        return { text: "Usage: /allow <skill|mcp|plugin> <name> [reason]" };
      }

      const reason = (args.reason as string) || "Allowed via /allow command";

      await enforcer.allow(targetType, name, reason);
      return {
        text: `Allow-listed ${targetType} **${name}**: ${reason}`,
      };
    },
  });
}

// ─── Scan handlers ───

async function handlePluginScan(target: string): Promise<{ text: string }> {
  try {
    const result = await scanPlugin(target);
    return { text: formatScanOutput("Plugin", target, result) };
  } catch (err) {
    return {
      text: `Plugin scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function handleMCPScan(target: string): Promise<{ text: string }> {
  try {
    const result = await scanMCPServer(target);
    return { text: formatScanOutput("MCP", target, result) };
  } catch (err) {
    return {
      text: `MCP scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function handleSkillScan(target: string): Promise<{ text: string }> {
  try {
    const result = await runSkillScan(target);
    return { text: formatScanOutput("Skill", target, result) };
  } catch (err) {
    return {
      text: `Skill scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function formatScanOutput(
  scanType: string,
  target: string,
  result: ScanResult,
): string {
  const lines: string[] = [`**DefenseClaw ${scanType} Scan: ${target}**\n`];

  if (result.findings.length === 0) {
    lines.push("Verdict: **CLEAN** — no findings");
    return lines.join("\n");
  }

  const max = maxSeverity(result.findings.map((f) => f.severity));
  lines.push(
    `Verdict: **${max}** (${result.findings.length} finding${result.findings.length === 1 ? "" : "s"})\n`,
  );
  lines.push(...formatFindings(result.findings));

  return lines.join("\n");
}
