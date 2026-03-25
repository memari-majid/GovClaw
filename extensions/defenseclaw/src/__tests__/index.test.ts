import { describe, it, expect, vi, beforeEach } from "vitest";
import type { AdmissionResult, ScanResult, Verdict } from "../types.js";

// --- Hoisted mocks (available before module-level vi.mock factories) ---

const { mockEnforcer, mockClient, mockRunSkillScan, mockScanPlugin, mockScanMCPServer } =
  vi.hoisted(() => ({
    mockEnforcer: {
      syncFromDaemon: vi.fn(),
      evaluateSkill: vi.fn(),
      evaluateMCPServer: vi.fn(),
      block: vi.fn(),
      allow: vi.fn(),
    },
    mockClient: {
      status: vi.fn(),
      logEvent: vi.fn(),
    },
    mockRunSkillScan: vi.fn(),
    mockScanPlugin: vi.fn(),
    mockScanMCPServer: vi.fn(),
  }));

vi.mock("@openclaw/plugin-sdk", () => ({
  definePluginEntry: (fn: unknown) => fn,
}));

vi.mock("../client.js", () => ({
  DaemonClient: vi.fn(() => mockClient),
}));

vi.mock("../policy/enforcer.js", () => ({
  PolicyEnforcer: vi.fn(() => mockEnforcer),
  runSkillScan: mockRunSkillScan,
}));

vi.mock("../scanners/plugin_scanner/index.js", () => ({
  scanPlugin: mockScanPlugin,
}));

vi.mock("../scanners/mcp-scanner.js", () => ({
  scanMCPServer: mockScanMCPServer,
}));

// --- Helpers ---

type GuardHandler = (event: Record<string, unknown>) => Promise<{ allow: boolean; reason?: string }>;
type EventHandler = (...args: unknown[]) => Promise<void>;

function createMockContext() {
  const guards: Record<string, GuardHandler> = {};
  const listeners: Record<string, EventHandler> = {};
  const services: Record<string, { start: () => Promise<{ stop: () => void }> }> = {};
  const commands: Record<string, { handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> }> = {};

  return {
    ctx: {
      api: {
        on: vi.fn((event: string, handler: EventHandler) => {
          listeners[event] = handler;
        }),
        guard: vi.fn((event: string, handler: GuardHandler) => {
          guards[event] = handler;
        }),
      },
      registerService: vi.fn((name: string, def: { start: () => Promise<{ stop: () => void }> }) => {
        services[name] = def;
      }),
      registerCommand: vi.fn((name: string, def: { handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> }) => {
        commands[name] = def;
      }),
    },
    guards,
    listeners,
    services,
    commands,
  };
}

function makeAdmission(overrides: Partial<AdmissionResult> & { verdict: Verdict }): AdmissionResult {
  return {
    type: "skill",
    name: "test",
    path: "/test",
    reason: "test reason",
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    scanner: "test-scanner",
    target: "/test",
    timestamp: new Date().toISOString(),
    findings: [],
    ...overrides,
  };
}

// --- Import the plugin (mock of definePluginEntry returns the raw callback) ---

import pluginSetup from "../index.js";

// --- Tests ---

describe("DefenseClaw OpenClaw Plugin", () => {
  let guards: Record<string, GuardHandler>;
  let listeners: Record<string, EventHandler>;
  let services: Record<string, { start: () => Promise<{ stop: () => void }> }>;
  let commands: Record<string, { handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> }>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEnforcer.syncFromDaemon.mockResolvedValue(undefined);
    mockEnforcer.block.mockResolvedValue(undefined);
    mockEnforcer.allow.mockResolvedValue(undefined);
    mockClient.status.mockResolvedValue({ ok: true });
    mockClient.logEvent.mockResolvedValue({ ok: true, status: 200 });

    const mock = createMockContext();
    guards = mock.guards;
    listeners = mock.listeners;
    services = mock.services;
    commands = mock.commands;
    (pluginSetup as (ctx: unknown) => void)(mock.ctx);
  });

  // ─── Registration ───

  describe("registration", () => {
    it("registers skill_install and mcp_connect as guards", () => {
      expect(guards.skill_install).toBeTypeOf("function");
      expect(guards.mcp_connect).toBeTypeOf("function");
    });

    it("registers gateway_start, skill_uninstall, mcp_disconnect as event listeners", () => {
      expect(listeners.gateway_start).toBeTypeOf("function");
      expect(listeners.skill_uninstall).toBeTypeOf("function");
      expect(listeners.mcp_disconnect).toBeTypeOf("function");
    });

    it("registers defenseclaw-watcher service", () => {
      expect(services["defenseclaw-watcher"]).toBeDefined();
    });

    it("registers /scan, /block, /allow commands", () => {
      expect(commands["/scan"]).toBeDefined();
      expect(commands["/block"]).toBeDefined();
      expect(commands["/allow"]).toBeDefined();
    });
  });

  // ─── Guard: skill_install ───

  describe("guard: skill_install", () => {
    it("rejects blocked skill", async () => {
      mockEnforcer.evaluateSkill.mockResolvedValue(
        makeAdmission({ verdict: "blocked", reason: "Block list: known malware" }),
      );

      const decision = await guards.skill_install({ name: "evil", path: "/skills/evil" });

      expect(decision.allow).toBe(false);
      expect(decision.reason).toBe("Block list: known malware");
      expect(mockEnforcer.evaluateSkill).toHaveBeenCalledWith("/skills/evil", "evil");
    });

    it("rejects skill with critical/high findings", async () => {
      mockEnforcer.evaluateSkill.mockResolvedValue(
        makeAdmission({ verdict: "rejected", reason: "2 finding(s) at HIGH or above" }),
      );

      const decision = await guards.skill_install({ name: "risky", path: "/skills/risky" });

      expect(decision.allow).toBe(false);
      expect(decision.reason).toContain("HIGH");
    });

    it("rejects on scan error", async () => {
      mockEnforcer.evaluateSkill.mockResolvedValue(
        makeAdmission({ verdict: "scan-error", reason: "Scan failed: timeout" }),
      );

      const decision = await guards.skill_install({ name: "broken", path: "/skills/broken" });

      expect(decision.allow).toBe(false);
      expect(decision.reason).toContain("Scan failed");
    });

    it("allows clean skill", async () => {
      mockEnforcer.evaluateSkill.mockResolvedValue(
        makeAdmission({ verdict: "clean", reason: "No findings" }),
      );

      const decision = await guards.skill_install({ name: "safe", path: "/skills/safe" });

      expect(decision.allow).toBe(true);
      expect(decision.reason).toBeUndefined();
    });

    it("allows explicitly allow-listed skill", async () => {
      mockEnforcer.evaluateSkill.mockResolvedValue(
        makeAdmission({ verdict: "allowed", reason: "Allow list: reviewed and safe" }),
      );

      const decision = await guards.skill_install({ name: "trusted", path: "/skills/trusted" });

      expect(decision.allow).toBe(true);
    });

    it("allows skill with warning-level findings", async () => {
      mockEnforcer.evaluateSkill.mockResolvedValue(
        makeAdmission({ verdict: "warning", reason: "1 finding(s) at MEDIUM" }),
      );

      const decision = await guards.skill_install({ name: "medium", path: "/skills/medium" });

      expect(decision.allow).toBe(true);
    });
  });

  // ─── Guard: mcp_connect ───

  describe("guard: mcp_connect", () => {
    it("rejects blocked MCP server", async () => {
      mockEnforcer.evaluateMCPServer.mockResolvedValue(
        makeAdmission({ type: "mcp", verdict: "blocked", reason: "Block list: malicious server" }),
      );

      const decision = await guards.mcp_connect({ name: "evil-mcp", config_path: "/mcp.json" });

      expect(decision.allow).toBe(false);
      expect(decision.reason).toContain("malicious server");
      expect(mockEnforcer.evaluateMCPServer).toHaveBeenCalledWith("/mcp.json", "evil-mcp");
    });

    it("rejects MCP with high findings", async () => {
      mockEnforcer.evaluateMCPServer.mockResolvedValue(
        makeAdmission({ type: "mcp", verdict: "rejected", reason: "credentials exposed in env" }),
      );

      const decision = await guards.mcp_connect({ name: "leaky", config_path: "/mcp.json" });

      expect(decision.allow).toBe(false);
      expect(decision.reason).toContain("credentials exposed");
    });

    it("rejects MCP on scan error", async () => {
      mockEnforcer.evaluateMCPServer.mockResolvedValue(
        makeAdmission({ type: "mcp", verdict: "scan-error", reason: "Scan failed: parse error" }),
      );

      const decision = await guards.mcp_connect({ name: "bad-config", config_path: "/broken.json" });

      expect(decision.allow).toBe(false);
    });

    it("allows clean MCP server", async () => {
      mockEnforcer.evaluateMCPServer.mockResolvedValue(
        makeAdmission({ type: "mcp", verdict: "clean", reason: "No findings" }),
      );

      const decision = await guards.mcp_connect({ name: "safe-mcp", config_path: "/mcp.json" });

      expect(decision.allow).toBe(true);
    });

    it("allows MCP without config_path (skips scan)", async () => {
      const decision = await guards.mcp_connect({ name: "no-config-mcp" });

      expect(decision.allow).toBe(true);
      expect(mockEnforcer.evaluateMCPServer).not.toHaveBeenCalled();
    });

    it("allows MCP with warning-level findings", async () => {
      mockEnforcer.evaluateMCPServer.mockResolvedValue(
        makeAdmission({ type: "mcp", verdict: "warning", reason: "minor issue" }),
      );

      const decision = await guards.mcp_connect({ name: "ok-mcp", config_path: "/mcp.json" });

      expect(decision.allow).toBe(true);
    });
  });

  // ─── Event: gateway_start ───

  describe("event: gateway_start", () => {
    it("checks sidecar health and syncs block/allow lists", async () => {
      await listeners.gateway_start();

      expect(mockClient.status).toHaveBeenCalled();
      expect(mockEnforcer.syncFromDaemon).toHaveBeenCalled();
    });

    it("handles unreachable sidecar without throwing", async () => {
      mockClient.status.mockResolvedValue({ ok: false, error: "ECONNREFUSED" });
      mockEnforcer.syncFromDaemon.mockRejectedValue(new Error("connection refused"));

      await expect(listeners.gateway_start()).resolves.toBeUndefined();
    });
  });

  // ─── Event: skill_uninstall ───

  describe("event: skill_uninstall", () => {
    it("logs uninstall event to daemon", async () => {
      await listeners.skill_uninstall({ name: "removed-skill", path: "/skills/removed" });

      expect(mockClient.logEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "skill.uninstall",
          target: "/skills/removed",
          actor: "openclaw",
          severity: "INFO",
        }),
      );
    });

    it("handles daemon log failure without throwing", async () => {
      mockClient.logEvent.mockRejectedValue(new Error("daemon down"));

      await expect(
        listeners.skill_uninstall({ name: "removed", path: "/skills/removed" }),
      ).resolves.toBeUndefined();
    });
  });

  // ─── Event: mcp_disconnect ───

  describe("event: mcp_disconnect", () => {
    it("logs disconnect event to daemon", async () => {
      await listeners.mcp_disconnect({ name: "stopped-mcp" });

      expect(mockClient.logEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "mcp.disconnect",
          target: "stopped-mcp",
          actor: "openclaw",
          severity: "INFO",
        }),
      );
    });

    it("handles daemon log failure without throwing", async () => {
      mockClient.logEvent.mockRejectedValue(new Error("daemon down"));

      await expect(
        listeners.mcp_disconnect({ name: "stopped" }),
      ).resolves.toBeUndefined();
    });
  });

  // ─── Service: defenseclaw-watcher ───

  describe("service: defenseclaw-watcher", () => {
    it("syncs block/allow lists on start", async () => {
      const handle = await services["defenseclaw-watcher"].start();

      expect(mockEnforcer.syncFromDaemon).toHaveBeenCalled();
      expect(handle.stop).toBeTypeOf("function");
    });

    it("handles sync failure without crashing", async () => {
      mockEnforcer.syncFromDaemon.mockRejectedValueOnce(new Error("daemon unreachable"));

      const handle = await services["defenseclaw-watcher"].start();

      expect(handle.stop).toBeTypeOf("function");
    });
  });

  // ─── Command: /scan ───

  describe("command: /scan", () => {
    it("runs skill scan by default", async () => {
      mockRunSkillScan.mockResolvedValue(makeScanResult());

      const result = await commands["/scan"].handler({ args: { target: "/skills/test" } });

      expect(result.text).toContain("Skill Scan");
      expect(result.text).toContain("CLEAN");
      expect(mockRunSkillScan).toHaveBeenCalledWith("/skills/test");
    });

    it("runs plugin scan when type=plugin", async () => {
      mockScanPlugin.mockResolvedValue(makeScanResult());

      const result = await commands["/scan"].handler({ args: { target: "/plugins/test", type: "plugin" } });

      expect(result.text).toContain("Plugin Scan");
      expect(mockScanPlugin).toHaveBeenCalledWith("/plugins/test");
    });

    it("runs mcp scan when type=mcp", async () => {
      mockScanMCPServer.mockResolvedValue(makeScanResult());

      const result = await commands["/scan"].handler({ args: { target: "/mcp.json", type: "mcp" } });

      expect(result.text).toContain("MCP Scan");
      expect(mockScanMCPServer).toHaveBeenCalledWith("/mcp.json");
    });

    it("reports findings with severity", async () => {
      mockRunSkillScan.mockResolvedValue(
        makeScanResult({
          findings: [
            {
              id: "f1",
              severity: "HIGH",
              title: "Shell exec detected",
              description: "test",
              scanner: "skill-scanner",
            },
          ],
        }),
      );

      const result = await commands["/scan"].handler({ args: { target: "/skills/danger" } });

      expect(result.text).toContain("HIGH");
      expect(result.text).toContain("Shell exec detected");
    });

    it("returns usage when no target provided", async () => {
      const result = await commands["/scan"].handler({ args: {} });

      expect(result.text).toContain("Usage");
    });

    it("handles scan failure gracefully", async () => {
      mockRunSkillScan.mockRejectedValue(new Error("scanner not found"));

      const result = await commands["/scan"].handler({ args: { target: "/skills/fail" } });

      expect(result.text).toContain("failed");
      expect(result.text).toContain("scanner not found");
    });
  });

  // ─── Command: /block ───

  describe("command: /block", () => {
    it("blocks target via enforcer", async () => {
      const result = await commands["/block"].handler({
        args: { type: "skill", name: "bad-skill", reason: "malicious content" },
      });

      expect(mockEnforcer.block).toHaveBeenCalledWith("skill", "bad-skill", "malicious content");
      expect(result.text).toContain("Blocked");
      expect(result.text).toContain("bad-skill");
    });

    it("uses default reason when not provided", async () => {
      await commands["/block"].handler({ args: { type: "mcp", name: "some-mcp" } });

      expect(mockEnforcer.block).toHaveBeenCalledWith("mcp", "some-mcp", "Blocked via /block command");
    });

    it("returns usage when type is missing", async () => {
      const result = await commands["/block"].handler({ args: { name: "test" } });

      expect(result.text).toContain("Usage");
    });

    it("returns usage when name is missing", async () => {
      const result = await commands["/block"].handler({ args: { type: "skill" } });

      expect(result.text).toContain("Usage");
    });
  });

  // ─── Command: /allow ───

  describe("command: /allow", () => {
    it("allow-lists target via enforcer", async () => {
      const result = await commands["/allow"].handler({
        args: { type: "skill", name: "safe-skill", reason: "reviewed and approved" },
      });

      expect(mockEnforcer.allow).toHaveBeenCalledWith("skill", "safe-skill", "reviewed and approved");
      expect(result.text).toContain("Allow-listed");
      expect(result.text).toContain("safe-skill");
    });

    it("uses default reason when not provided", async () => {
      await commands["/allow"].handler({ args: { type: "plugin", name: "good-plugin" } });

      expect(mockEnforcer.allow).toHaveBeenCalledWith("plugin", "good-plugin", "Allowed via /allow command");
    });

    it("returns usage when type is missing", async () => {
      const result = await commands["/allow"].handler({ args: { name: "test" } });

      expect(result.text).toContain("Usage");
    });

    it("returns usage when name is missing", async () => {
      const result = await commands["/allow"].handler({ args: { type: "skill" } });

      expect(result.text).toContain("Usage");
    });
  });
});
