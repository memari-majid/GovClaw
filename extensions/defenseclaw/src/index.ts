/**
 * DefenseClaw OpenClaw Plugin
 *
 * Integrates DefenseClaw security into the OpenClaw plugin lifecycle:
 *
 * Boot-time:
 *  - Syncs block/allow lists from the Go daemon
 *  - Verifies sidecar reachability on gateway_start
 *
 * Lifecycle hooks:
 *  - skill_install / skill_uninstall: admission gate for skills
 *  - mcp_connect / mcp_disconnect: admission gate for MCP servers
 *
 * Slash commands:
 *  - /scan <path>: scan a skill directory
 *  - /block <type> <name> [reason]: block a skill, MCP, or plugin
 *  - /allow <type> <name> [reason]: allow-list a skill, MCP, or plugin
 *
 * The plugin uses:
 *  1. Native TS scanners for plugins and MCP configs (in-process, fast)
 *  2. CLI shell-out to `defenseclaw` for skill/code scans (full scanner suite)
 *  3. REST API to the Go daemon for policy state and audit logging
 */

import { definePluginEntry } from "@openclaw/plugin-sdk";
import { DaemonClient } from "./client.js";
import { PolicyEnforcer, runSkillScan } from "./policy/enforcer.js";
import { scanPlugin } from "./scanners/plugin_scanner/index.js";
import { scanMCPServer } from "./scanners/mcp-scanner.js";
import type {
  ScanResult,
  AdmissionResult,
  Finding,
  InstallType,
} from "./types.js";
import { compareSeverity, maxSeverity } from "./types.js";

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

function formatAdmissionResult(result: AdmissionResult): string {
  const icon =
    result.verdict === "clean" || result.verdict === "allowed"
      ? "PASS"
      : result.verdict === "warning"
        ? "WARN"
        : "FAIL";

  return `[${icon}] ${result.type} "${result.name}": ${result.verdict} — ${result.reason}`;
}

export default definePluginEntry(({ api, registerService, registerCommand }) => {
  const client = new DaemonClient();
  const enforcer = new PolicyEnforcer();

  // ─── Background service: sync block/allow lists from sidecar ───

  registerService("defenseclaw-watcher", {
    start: async () => {
      try {
        await enforcer.syncFromDaemon();
        console.log("[defenseclaw] block/allow lists synced from sidecar");
      } catch (err) {
        console.error(
          `[defenseclaw] failed to sync from sidecar: ${err instanceof Error ? err.message : String(err)}`,
        );
        console.error(
          "[defenseclaw] WARNING: operating without daemon sync — enforcement may be stale",
        );
      }

      return {
        stop: () => undefined,
      };
    },
  });

  // ─── Lifecycle: gateway_start ───

  api.on("gateway_start", async () => {
    console.log("[defenseclaw] gateway started — syncing state from sidecar...");

    const health = await client.status();
    if (health.ok) {
      console.log("[defenseclaw] sidecar is reachable");
    } else {
      console.error(
        `[defenseclaw] WARNING: sidecar unreachable (${health.error ?? "unknown"}) — ` +
        "enforcement will use local cache only. Ensure defenseclaw-gateway is running.",
      );
    }

    await enforcer.syncFromDaemon().catch(() => {
      console.error("[defenseclaw] failed to sync block/allow lists from sidecar");
    });
  });

  // ─── Lifecycle: skill install/uninstall ───

  api.guard("skill_install", async (event: { name: string; path: string }) => {
    console.log(`[defenseclaw] skill install detected: ${event.name}`);

    const result = await enforcer.evaluateSkill(event.path, event.name);
    console.log(`[defenseclaw] ${formatAdmissionResult(result)}`);

    if (result.verdict === "rejected" || result.verdict === "blocked" || result.verdict === "scan-error") {
      return { allow: false, reason: result.reason };
    }

    return { allow: true };
  });

  api.on("skill_uninstall", async (event: { name: string; path: string }) => {
    console.log(`[defenseclaw] skill uninstalled: ${event.name}`);
    await client
      .logEvent({
        action: "skill.uninstall",
        target: event.path,
        actor: "openclaw",
        severity: "INFO",
        details: JSON.stringify({ name: event.name }),
      })
      .catch(() => {});
  });

  // ─── Lifecycle: MCP connect/disconnect ───

  api.guard("mcp_connect", async (event: { name: string; config_path?: string }) => {
    console.log(`[defenseclaw] MCP server connecting: ${event.name}`);

    if (event.config_path) {
      const result = await enforcer.evaluateMCPServer(
        event.config_path,
        event.name,
      );
      console.log(`[defenseclaw] ${formatAdmissionResult(result)}`);

      if (result.verdict === "rejected" || result.verdict === "blocked" || result.verdict === "scan-error") {
        return { allow: false, reason: result.reason };
      }
    } else {
      console.log(
        `[defenseclaw] MCP "${event.name}" connected (no config path — skipping scan)`,
      );
    }

    return { allow: true };
  });

  api.on("mcp_disconnect", async (event: { name: string }) => {
    console.log(`[defenseclaw] MCP server disconnected: ${event.name}`);
    await client
      .logEvent({
        action: "mcp.disconnect",
        target: event.name,
        actor: "openclaw",
        severity: "INFO",
        details: JSON.stringify({ name: event.name }),
      })
      .catch(() => {});
  });

  // ─── Slash command: /scan ───

  registerCommand("/scan", {
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

  registerCommand("/block", {
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

  registerCommand("/allow", {
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
});

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
