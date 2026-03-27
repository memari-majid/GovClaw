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
import { runCodeScan } from "../policy/enforcer.js";

let server: Server;
let port: number;
let lastRequest: { method: string; url: string; body: string } | null = null;
let mockResponse: { status: number; body: string } = {
  status: 200,
  body: JSON.stringify({
    scanner: "codeguard",
    target: "/tmp/test.py",
    timestamp: "2026-03-25T00:00:00Z",
    findings: [],
    duration: 100000,
  }),
};

beforeAll(
  () =>
    new Promise<void>((resolve) => {
      server = createServer((req: IncomingMessage, res: ServerResponse) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          lastRequest = {
            method: req.method ?? "GET",
            url: req.url ?? "",
            body: Buffer.concat(chunks).toString("utf-8"),
          };
          res.writeHead(mockResponse.status, {
            "Content-Type": "application/json",
          });
          res.end(mockResponse.body);
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
  lastRequest = null;
  mockResponse = {
    status: 200,
    body: JSON.stringify({
      scanner: "codeguard",
      target: "/tmp/test.py",
      timestamp: "2026-03-25T00:00:00Z",
      findings: [],
      duration: 100000,
    }),
  };
}

describe("runCodeScan", () => {
  it("sends correct POST request with path and headers", async () => {
    reset();
    await runCodeScan("/tmp/test.py", `http://127.0.0.1:${port}`);

    expect(lastRequest).not.toBeNull();
    expect(lastRequest!.method).toBe("POST");
    expect(lastRequest!.url).toBe("/api/v1/scan/code");

    const body = JSON.parse(lastRequest!.body);
    expect(body.path).toBe("/tmp/test.py");
  });

  it("parses findings from sidecar response", async () => {
    reset();
    mockResponse = {
      status: 200,
      body: JSON.stringify({
        scanner: "codeguard",
        target: "/tmp/vuln.py",
        timestamp: "2026-03-25T00:00:00Z",
        findings: [
          {
            id: "CG-EXEC-001",
            severity: "HIGH",
            title: "Unsafe command execution",
            description: "os.system(cmd)",
            location: "/tmp/vuln.py:3",
            remediation: "Use parameterized execution",
            scanner: "codeguard",
            tags: ["codeguard"],
          },
          {
            id: "CG-SQL-001",
            severity: "HIGH",
            title: "Potential SQL injection",
            description: 'cursor.execute(f"SELECT...")',
            location: "/tmp/vuln.py:7",
            remediation: "Use parameterized queries",
            scanner: "codeguard",
            tags: ["codeguard"],
          },
        ],
        duration: 200000,
      }),
    };

    const result = await runCodeScan(
      "/tmp/vuln.py",
      `http://127.0.0.1:${port}`,
    );

    expect(result.scanner).toBe("codeguard");
    expect(result.target).toBe("/tmp/vuln.py");
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0].id).toBe("CG-EXEC-001");
    expect(result.findings[0].severity).toBe("HIGH");
    expect(result.findings[1].id).toBe("CG-SQL-001");
  });

  it("handles empty findings (clean scan)", async () => {
    reset();
    const result = await runCodeScan(
      "/tmp/clean.py",
      `http://127.0.0.1:${port}`,
    );

    expect(result.scanner).toBe("codeguard");
    expect(result.findings).toHaveLength(0);
  });

  it("throws on server error response", async () => {
    reset();
    mockResponse = {
      status: 500,
      body: JSON.stringify({ error: "internal error" }),
    };

    await expect(
      runCodeScan("/tmp/test.py", `http://127.0.0.1:${port}`),
    ).rejects.toThrow(/HTTP 500/);
  });

  it("throws on connection refused", async () => {
    reset();
    await expect(
      runCodeScan("/tmp/test.py", "http://127.0.0.1:1"),
    ).rejects.toThrow();
  });
});
