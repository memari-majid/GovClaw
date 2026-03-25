"""Plugin scanner — shells out to defenseclaw-plugin-scanner (Node.js).

The scanner lives in extensions/defenseclaw and is installed as a Node binary.
Supports the same LLM flags as the skill scanner (reads from skill_scanner config).
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from defenseclaw.models import Finding, ScanResult

SCANNER_NAME = "defenseclaw-plugin-scanner"


class PluginScannerWrapper:
    def __init__(self, binary: str = SCANNER_NAME) -> None:
        self.binary = binary

    def name(self) -> str:
        return "plugin-scanner"

    def scan(
        self,
        target: str,
        *,
        policy: str = "",
        profile: str = "",
        use_llm: bool = False,
        llm_model: str = "",
        llm_api_key: str = "",
        llm_provider: str = "",
        llm_consensus_runs: int = 0,
        disable_meta: bool = False,
        lenient: bool = False,
    ) -> ScanResult:
        import time

        start = time.monotonic()

        args = [self.binary, target]
        if policy:
            args.extend(["--policy", policy])
        if profile:
            args.extend(["--profile", profile])
        if use_llm:
            args.append("--use-llm")
            if llm_model:
                args.extend(["--llm-model", llm_model])
            if llm_provider:
                args.extend(["--llm-provider", llm_provider])
            if llm_consensus_runs > 0:
                args.extend(["--llm-consensus-runs", str(llm_consensus_runs)])
        if disable_meta:
            args.append("--no-meta")
        if lenient:
            args.append("--lenient")

        # Set up environment:
        # - PYTHONPATH so the Node binary can find cli/defenseclaw/llm.py (litellm bridge)
        # - SKILL_SCANNER_LLM_API_KEY for the LLM API key
        import os
        cli_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        pythonpath = f"{cli_dir}:{existing_pythonpath}" if existing_pythonpath else cli_dir
        env = {**os.environ, "PYTHONPATH": pythonpath}
        if llm_api_key:
            env["SKILL_SCANNER_LLM_API_KEY"] = llm_api_key

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=300,  # longer timeout when LLM is enabled
                env=env,
            )
        except FileNotFoundError:
            print(
                f"error: {self.binary} not found.\n"
                "  Build and link the extension:\n"
                "    cd extensions/defenseclaw && npm run build && npm link",
                file=sys.stderr,
            )
            raise SystemExit(1)

        elapsed = time.monotonic() - start
        findings: list[Finding] = []

        if proc.stdout.strip():
            try:
                # The TS plugin scanner outputs a full ScanResult object with
                # scanner, target, timestamp, findings[], duration_ns, metadata,
                # and assessment fields (see extensions/defenseclaw/src/types.ts).
                data = json.loads(proc.stdout)
                for f in data.get("findings", []):
                    if f.get("suppressed", False):
                        continue
                    findings.append(Finding(
                        id=f.get("id", ""),
                        severity=f.get("severity", "INFO"),
                        title=f.get("title", ""),
                        description=f.get("description", ""),
                        location=f.get("location", ""),
                        remediation=f.get("remediation", ""),
                        scanner="plugin-scanner",
                        tags=f.get("tags", []),
                    ))
            except json.JSONDecodeError:
                pass

        if proc.returncode != 0 and not findings:
            stderr_msg = proc.stderr.strip()[:200] if proc.stderr else "unknown error"
            findings.append(Finding(
                id="scanner-error",
                severity="ERROR",
                title=f"Plugin scanner exited with code {proc.returncode}",
                description=stderr_msg,
                scanner="plugin-scanner",
            ))

        return ScanResult(
            scanner="plugin-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )
