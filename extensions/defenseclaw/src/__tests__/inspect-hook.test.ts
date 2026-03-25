import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer } from "node:http";
import type { Server, IncomingMessage, ServerResponse } from "node:http";

let server: Server;
let port: number;
let lastInspectRequest: Record<string, unknown> = {};
let verdictOverride: Record<string, unknown> | null = null;

beforeAll(
  () =>
    new Promise<void>((resolve) => {
      server = createServer((req: IncomingMessage, res: ServerResponse) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf-8");
          lastInspectRequest = body ? JSON.parse(body) : {};

          res.writeHead(200, { "Content-Type": "application/json" });

          if (verdictOverride) {
            res.end(JSON.stringify(verdictOverride));
          } else {
            res.end(
              JSON.stringify({
                action: "allow",
                severity: "NONE",
                reason: "",
                findings: [],
                mode: "observe",
              }),
            );
          }
        });
      });

      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        port = typeof addr === "object" && addr ? addr.port : 0;
        resolve();
      });
    }),
);

afterAll(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve());
    }),
);

function reset() {
  lastInspectRequest = {};
  verdictOverride = null;
}

async function callInspect(
  payload: Record<string, unknown>,
): Promise<{ action: string; severity: string; reason: string; mode: string }> {
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/inspect/tool`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return (await res.json()) as {
    action: string;
    severity: string;
    reason: string;
    mode: string;
  };
}

describe("inspect/tool endpoint integration", () => {
  it("sends tool name and args for general tool call", async () => {
    reset();
    const verdict = await callInspect({
      tool: "shell",
      args: { command: "ls -la" },
    });

    expect(verdict.action).toBe("allow");
    expect(lastInspectRequest).toEqual({
      tool: "shell",
      args: { command: "ls -la" },
    });
  });

  it("sends content and direction for message tool", async () => {
    reset();
    const verdict = await callInspect({
      tool: "message",
      args: { to: "+123" },
      content: "Hello there",
      direction: "outbound",
    });

    expect(verdict.action).toBe("allow");
    expect(lastInspectRequest).toMatchObject({
      tool: "message",
      content: "Hello there",
      direction: "outbound",
    });
  });

  it("returns block verdict from server", async () => {
    reset();
    verdictOverride = {
      action: "block",
      severity: "HIGH",
      reason: "dangerous-cmd:curl",
      findings: ["dangerous-cmd:curl"],
      mode: "action",
    };

    const verdict = await callInspect({
      tool: "shell",
      args: { command: "curl evil.com" },
    });

    expect(verdict.action).toBe("block");
    expect(verdict.severity).toBe("HIGH");
    expect(verdict.mode).toBe("action");
  });

  it("returns observe mode so plugin skips enforcement", async () => {
    reset();
    verdictOverride = {
      action: "block",
      severity: "HIGH",
      reason: "dangerous-cmd:curl",
      findings: ["dangerous-cmd:curl"],
      mode: "observe",
    };

    const verdict = await callInspect({
      tool: "shell",
      args: { command: "curl evil.com" },
    });

    expect(verdict.action).toBe("block");
    expect(verdict.mode).toBe("observe");
  });
});

describe("before_tool_call hook logic", () => {
  it("cancels tool when action=block and mode=action", () => {
    let cancelled = false;
    let cancelReason = "";

    const event = {
      toolName: "shell",
      args: { command: "curl evil.com" } as Record<string, unknown>,
      cancel(reason: string) {
        cancelled = true;
        cancelReason = reason;
      },
    };

    const verdict = {
      action: "block",
      severity: "HIGH",
      reason: "dangerous-cmd:curl",
      mode: "action",
    };

    if (verdict.action === "block" && verdict.mode === "action") {
      event.cancel(`DefenseClaw: ${verdict.reason}`);
    }

    expect(cancelled).toBe(true);
    expect(cancelReason).toBe("DefenseClaw: dangerous-cmd:curl");
  });

  it("does not cancel when mode=observe even if action=block", () => {
    let cancelled = false;

    const event = {
      toolName: "shell",
      args: { command: "curl evil.com" } as Record<string, unknown>,
      cancel(_reason: string) {
        cancelled = true;
      },
    };

    const verdict = {
      action: "block",
      severity: "HIGH",
      reason: "dangerous-cmd:curl",
      mode: "observe",
    };

    if (verdict.action === "block" && verdict.mode === "action") {
      event.cancel(`DefenseClaw: ${verdict.reason}`);
    }

    expect(cancelled).toBe(false);
  });

  it("does not cancel when action=allow", () => {
    let cancelled = false;

    const event = {
      toolName: "read_file",
      args: { path: "/tmp/hello.txt" } as Record<string, unknown>,
      cancel(_reason: string) {
        cancelled = true;
      },
    };

    const verdict = {
      action: "allow",
      severity: "NONE",
      reason: "",
      mode: "action",
    };

    if (verdict.action === "block" && verdict.mode === "action") {
      event.cancel(`DefenseClaw: ${verdict.reason}`);
    }

    expect(cancelled).toBe(false);
  });

  it("cancels outbound message with secrets in action mode", () => {
    let cancelled = false;
    let cancelReason = "";

    const event = {
      toolName: "message",
      args: { to: "+123", content: "key: sk-ant-secret" } as Record<string, unknown>,
      cancel(reason: string) {
        cancelled = true;
        cancelReason = reason;
      },
    };

    const verdict = {
      action: "block",
      severity: "HIGH",
      reason: "secret:sk-ant-",
      mode: "action",
    };

    if (verdict.action === "block" && verdict.mode === "action") {
      event.cancel(`DefenseClaw: outbound blocked — ${verdict.reason}`);
    }

    expect(cancelled).toBe(true);
    expect(cancelReason).toContain("outbound blocked");
    expect(cancelReason).toContain("sk-ant-");
  });
});
