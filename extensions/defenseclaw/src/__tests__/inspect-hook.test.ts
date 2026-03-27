/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
  function simulateHook(
    verdict: { action: string; severity: string; reason: string; mode: string },
    toolName: string,
  ): { block: boolean; blockReason: string } | undefined {
    if (verdict.action === "block" && verdict.mode === "action") {
      const prefix = toolName === "message" ? "DefenseClaw: outbound blocked — " : "DefenseClaw: ";
      return { block: true, blockReason: `${prefix}${verdict.reason}` };
    }
    return undefined;
  }

  it("blocks tool when action=block and mode=action", () => {
    const result = simulateHook(
      { action: "block", severity: "HIGH", reason: "dangerous-cmd:curl", mode: "action" },
      "shell",
    );

    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
    expect(result!.blockReason).toBe("DefenseClaw: dangerous-cmd:curl");
  });

  it("does not block when mode=observe even if action=block", () => {
    const result = simulateHook(
      { action: "block", severity: "HIGH", reason: "dangerous-cmd:curl", mode: "observe" },
      "shell",
    );

    expect(result).toBeUndefined();
  });

  it("does not block when action=allow", () => {
    const result = simulateHook(
      { action: "allow", severity: "NONE", reason: "", mode: "action" },
      "read_file",
    );

    expect(result).toBeUndefined();
  });

  it("blocks outbound message with secrets in action mode", () => {
    const result = simulateHook(
      { action: "block", severity: "HIGH", reason: "secret:sk-ant-", mode: "action" },
      "message",
    );

    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
    expect(result!.blockReason).toContain("outbound blocked");
    expect(result!.blockReason).toContain("sk-ant-");
  });
});
