"""defenseclaw setup — Configure DefenseClaw settings and integrations.

Mirrors internal/cli/setup.go.
"""

from __future__ import annotations

import os
import subprocess

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def setup() -> None:
    """Configure DefenseClaw components."""


@setup.command("skill-scanner")
@click.option("--use-llm", is_flag=True, default=None, help="Enable LLM analyzer")
@click.option("--use-behavioral", is_flag=True, default=None, help="Enable behavioral analyzer")
@click.option("--enable-meta", is_flag=True, default=None, help="Enable meta-analyzer")
@click.option("--use-trigger", is_flag=True, default=None, help="Enable trigger analyzer")
@click.option("--use-virustotal", is_flag=True, default=None, help="Enable VirusTotal scanner")
@click.option("--use-aidefense", is_flag=True, default=None, help="Enable AI Defense analyzer")
@click.option("--llm-provider", default=None, help="LLM provider (anthropic or openai)")
@click.option("--llm-model", default=None, help="LLM model name")
@click.option("--llm-consensus-runs", type=int, default=None, help="LLM consensus runs (0=disabled)")
@click.option("--policy", default=None, help="Scan policy preset (strict, balanced, permissive)")
@click.option("--lenient", is_flag=True, default=None, help="Tolerate malformed skills")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_skill_scanner(
    app: AppContext,
    use_llm, use_behavioral, enable_meta, use_trigger,
    use_virustotal, use_aidefense,
    llm_provider, llm_model, llm_consensus_runs,
    policy, lenient, non_interactive,
) -> None:
    """Configure skill-scanner analyzers, API keys, and policy.

    Interactively configure how skill-scanner runs. Enables LLM analysis,
    behavioral dataflow analysis, meta-analyzer filtering, and more.

    API keys are stored in ~/.defenseclaw/config.yaml and injected as
    environment variables when skill-scanner runs.

    Use --non-interactive with flags for CI/scripted configuration.
    """
    sc = app.cfg.scanners.skill_scanner

    if non_interactive:
        if use_llm is not None:
            sc.use_llm = use_llm
        if use_behavioral is not None:
            sc.use_behavioral = use_behavioral
        if enable_meta is not None:
            sc.enable_meta = enable_meta
        if use_trigger is not None:
            sc.use_trigger = use_trigger
        if use_virustotal is not None:
            sc.use_virustotal = use_virustotal
        if use_aidefense is not None:
            sc.use_aidefense = use_aidefense
        if llm_provider is not None:
            sc.llm_provider = llm_provider
        if llm_model is not None:
            sc.llm_model = llm_model
        if llm_consensus_runs is not None:
            sc.llm_consensus_runs = llm_consensus_runs
        if policy is not None:
            sc.policy = policy
        if lenient is not None:
            sc.lenient = lenient
    else:
        _interactive_setup(sc)

    app.cfg.save()
    _print_summary(sc)

    if app.logger:
        parts = [f"use_llm={sc.use_llm}", f"use_behavioral={sc.use_behavioral}", f"enable_meta={sc.enable_meta}"]
        if sc.llm_provider:
            parts.append(f"llm_provider={sc.llm_provider}")
        if sc.policy:
            parts.append(f"policy={sc.policy}")
        app.logger.log_action("setup-skill-scanner", "config", " ".join(parts))


def _interactive_setup(sc) -> None:
    click.echo()
    click.echo("  Skill Scanner Configuration")
    click.echo("  ────────────────────────────")
    click.echo(f"  Binary: {sc.binary}")
    click.echo()

    sc.use_behavioral = click.confirm("  Enable behavioral analyzer (dataflow analysis)?", default=sc.use_behavioral)
    sc.use_llm = click.confirm("  Enable LLM analyzer (semantic analysis)?", default=sc.use_llm)

    if sc.use_llm:
        sc.llm_provider = click.prompt(
            "  LLM provider (anthropic/openai)",
            default=sc.llm_provider or "anthropic",
        )
        sc.llm_model = click.prompt("  LLM model name", default=sc.llm_model or "", show_default=False)
        sc.enable_meta = click.confirm("  Enable meta-analyzer (false positive filtering)?", default=sc.enable_meta)
        sc.llm_consensus_runs = click.prompt(
            "  LLM consensus runs (0 = disabled)", type=int, default=sc.llm_consensus_runs,
        )
        sc.llm_api_key = _prompt_secret("SKILL_SCANNER_LLM_API_KEY", sc.llm_api_key)

    sc.use_trigger = click.confirm("  Enable trigger analyzer (vague description checks)?", default=sc.use_trigger)
    sc.use_virustotal = click.confirm("  Enable VirusTotal binary scanner?", default=sc.use_virustotal)
    if sc.use_virustotal:
        sc.virustotal_api_key = _prompt_secret("VIRUSTOTAL_API_KEY", sc.virustotal_api_key)

    sc.use_aidefense = click.confirm("  Enable Cisco AI Defense analyzer?", default=sc.use_aidefense)
    if sc.use_aidefense:
        sc.aidefense_api_key = _prompt_secret("AI_DEFENSE_API_KEY", sc.aidefense_api_key)

    click.echo()
    choices = ["strict", "balanced", "permissive"]
    val = click.prompt(
        f"  Scan policy preset ({'/'.join(choices)})",
        default=sc.policy or "none", show_default=True,
    )
    if val in choices:
        sc.policy = val
    elif val == "none":
        sc.policy = ""

    sc.lenient = click.confirm("  Lenient mode (tolerate malformed skills)?", default=sc.lenient)


def _prompt_secret(env_name: str, current: str) -> str:
    env_val = os.environ.get(env_name, "")
    if current:
        hint = _mask(current)
    elif env_val:
        hint = f"from env: {_mask(env_val)}"
    else:
        hint = "(not set)"
    val = click.prompt(f"  {env_name} [{hint}]", default="", show_default=False)
    if val:
        return val
    return current or env_val


def _mask(key: str) -> str:
    if len(key) <= 8:
        return "****"
    return key[:4] + "..." + key[-4:]


def _print_summary(sc) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    rows = [
        ("use_behavioral", str(sc.use_behavioral).lower()),
        ("use_llm", str(sc.use_llm).lower()),
    ]
    if sc.use_llm:
        rows.append(("llm_provider", sc.llm_provider))
        if sc.llm_model:
            rows.append(("llm_model", sc.llm_model))
        rows.append(("enable_meta", str(sc.enable_meta).lower()))
        if sc.llm_consensus_runs > 0:
            rows.append(("llm_consensus_runs", str(sc.llm_consensus_runs)))
        if sc.llm_api_key:
            rows.append(("llm_api_key", _mask(sc.llm_api_key)))
    if sc.use_trigger:
        rows.append(("use_trigger", "true"))
    if sc.use_virustotal:
        rows.append(("use_virustotal", "true"))
        if sc.virustotal_api_key:
            rows.append(("virustotal_api_key", _mask(sc.virustotal_api_key)))
    if sc.use_aidefense:
        rows.append(("use_aidefense", "true"))
        if sc.aidefense_api_key:
            rows.append(("aidefense_api_key", _mask(sc.aidefense_api_key)))
    if sc.policy:
        rows.append(("policy", sc.policy))
    if sc.lenient:
        rows.append(("lenient", "true"))

    for key, val in rows:
        click.echo(f"    scanners.skill_scanner.{key + ':':<22s} {val}")
    click.echo()


# ---------------------------------------------------------------------------
# setup gateway
# ---------------------------------------------------------------------------

@setup.command("gateway")
@click.option("--remote", is_flag=True, help="Configure for a remote OpenClaw gateway (requires auth token)")
@click.option("--host", default=None, help="Gateway host")
@click.option("--port", type=int, default=None, help="Gateway WebSocket port")
@click.option("--api-port", type=int, default=None, help="Sidecar REST API port")
@click.option("--token", default=None, help="Gateway auth token")
@click.option("--ssm-param", default=None, help="AWS SSM parameter name for token")
@click.option("--ssm-region", default=None, help="AWS region for SSM")
@click.option("--ssm-profile", default=None, help="AWS CLI profile for SSM")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_gateway(
    app: AppContext,
    remote: bool,
    host, port, api_port, token,
    ssm_param, ssm_region, ssm_profile,
    non_interactive: bool,
) -> None:
    """Configure gateway connection for the DefenseClaw sidecar.

    By default configures for a local OpenClaw instance (no token needed).
    Use --remote to configure for a remote gateway that requires an auth token,
    optionally fetched from AWS SSM Parameter Store.
    """
    gw = app.cfg.gateway

    if non_interactive:
        if host is not None:
            gw.host = host
        if port is not None:
            gw.port = port
        if api_port is not None:
            gw.api_port = api_port
        if token is not None:
            gw.token = token
        elif ssm_param:
            fetched = _fetch_ssm_token(ssm_param, ssm_region or "us-east-1", ssm_profile)
            if fetched:
                gw.token = fetched
            else:
                click.echo("error: failed to fetch token from SSM", err=True)
                raise SystemExit(1)
    elif remote:
        _interactive_gateway_remote(gw)
    else:
        _interactive_gateway_local(gw)

    app.cfg.save()
    _print_gateway_summary(gw)

    if app.logger:
        mode = "remote" if (remote or gw.token) else "local"
        app.logger.log_action("setup-gateway", "config", f"mode={mode} host={gw.host} port={gw.port}")


def _interactive_gateway_local(gw) -> None:
    click.echo()
    click.echo("  Gateway Configuration (local)")
    click.echo("  ─────────────────────────────")
    click.echo()

    gw.host = click.prompt("  Gateway host", default=gw.host)
    gw.port = click.prompt("  Gateway port", default=gw.port, type=int)
    gw.api_port = click.prompt("  Sidecar API port", default=gw.api_port, type=int)
    gw.token = ""
    click.echo()
    click.echo("  Local mode: no auth token needed.")


def _interactive_gateway_remote(gw) -> None:
    click.echo()
    click.echo("  Gateway Configuration (remote)")
    click.echo("  ──────────────────────────────")
    click.echo()

    gw.host = click.prompt("  Gateway host", default=gw.host)
    gw.port = click.prompt("  Gateway port", default=gw.port, type=int)
    gw.api_port = click.prompt("  Sidecar API port", default=gw.api_port, type=int)

    click.echo()
    use_ssm = click.confirm("  Fetch token from AWS SSM Parameter Store?", default=True)

    if use_ssm:
        param = click.prompt(
            "  SSM parameter name",
            default="/openclaw/openclaw-bedrock/gateway-token",
        )
        region = click.prompt("  AWS region", default="us-east-1")
        profile = click.prompt("  AWS CLI profile", default="devops")

        click.echo("  Fetching token from SSM...", nl=False)
        fetched = _fetch_ssm_token(param, region, profile)
        if fetched:
            gw.token = fetched
            click.echo(f" ok ({_mask(fetched)})")
        else:
            click.echo(" failed")
            click.echo("  Falling back to manual entry.")
            gw.token = _prompt_secret("OPENCLAW_GATEWAY_TOKEN", gw.token)
    else:
        gw.token = _prompt_secret("OPENCLAW_GATEWAY_TOKEN", gw.token)

    if not gw.token:
        click.echo("  warning: no token set — sidecar will fail to connect to a remote gateway", err=True)


def _fetch_ssm_token(param: str, region: str, profile: str | None) -> str | None:
    cmd = [
        "aws", "ssm", "get-parameter",
        "--name", param,
        "--with-decryption",
        "--query", "Parameter.Value",
        "--output", "text",
        "--region", region,
    ]
    if profile:
        cmd.extend(["--profile", profile])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


# ---------------------------------------------------------------------------
# setup guardrail
# ---------------------------------------------------------------------------

@setup.command("guardrail")
@click.option("--disable", is_flag=True, help="Disable guardrail and revert OpenClaw config")
@click.option("--mode", "guard_mode", type=click.Choice(["observe", "action"]), default=None,
              help="Guardrail mode")
@click.option("--scanner-mode", type=click.Choice(["local", "remote", "both"]), default=None,
              help="Scanner mode (local patterns, remote Cisco API, or both)")
@click.option("--cisco-endpoint", default=None, help="Cisco AI Defense API endpoint")
@click.option("--cisco-api-key-env", default=None, help="Env var name holding Cisco AI Defense API key")
@click.option("--cisco-timeout-ms", type=int, default=None, help="Cisco AI Defense timeout (ms)")
@click.option("--port", "guard_port", type=int, default=None, help="LiteLLM proxy port")
@click.option("--restart", is_flag=True, help="Restart defenseclaw-gateway and openclaw gateway after setup")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_guardrail(
    app: AppContext,
    disable: bool,
    guard_mode, guard_port,
    scanner_mode, cisco_endpoint, cisco_api_key_env, cisco_timeout_ms,
    restart: bool,
    non_interactive: bool,
) -> None:
    """Configure the LLM guardrail (routes LLM traffic through LiteLLM for inspection).

    Routes all LLM traffic through a local LiteLLM proxy with DefenseClaw
    guardrails attached. Every prompt and response is inspected for prompt
    injection, secrets, PII, and data exfiltration patterns.

    Two modes:
      observe — log findings, never block (default, recommended to start)
      action  — block prompts/responses that match security policies

    Use --disable to turn off the guardrail and restore direct LLM access.
    """
    from defenseclaw.guardrail import (
        generate_litellm_config,
        install_guardrail_module,
        patch_openclaw_config,
        write_litellm_config,
    )

    gc = app.cfg.guardrail

    if disable:
        _disable_guardrail(app, gc, restart=restart)
        return

    if non_interactive:
        if guard_mode is not None:
            gc.mode = guard_mode
        if scanner_mode is not None:
            gc.scanner_mode = scanner_mode
        if cisco_endpoint is not None:
            gc.cisco_ai_defense.endpoint = cisco_endpoint
        if cisco_api_key_env is not None:
            gc.cisco_ai_defense.api_key_env = cisco_api_key_env
        if cisco_timeout_ms is not None:
            gc.cisco_ai_defense.timeout_ms = cisco_timeout_ms
        if guard_port is not None:
            gc.port = guard_port
        gc.enabled = True
    else:
        _interactive_guardrail_setup(app, gc)

    if not gc.enabled:
        click.echo("  Guardrail not enabled. Run again without declining to configure.")
        return

    # Generate LiteLLM config
    litellm_cfg = generate_litellm_config(
        model=gc.model,
        model_name=gc.model_name,
        api_key_env=gc.api_key_env,
        port=gc.port,
        device_key_file=app.cfg.gateway.device_key_file,
    )
    write_litellm_config(litellm_cfg, gc.litellm_config)

    # Install guardrail module
    repo_source = _find_guardrail_source()
    if repo_source:
        install_guardrail_module(repo_source, gc.guardrail_dir)

    # Derive the master key for OpenClaw config
    from defenseclaw.guardrail import _derive_master_key
    master_key = _derive_master_key(app.cfg.gateway.device_key_file)

    # Patch OpenClaw config
    prev_model = patch_openclaw_config(
        openclaw_config_file=app.cfg.claw.config_file,
        model_name=gc.model_name,
        litellm_port=gc.port,
        master_key=master_key,
        original_model=gc.original_model,
    )
    if prev_model and not gc.original_model:
        gc.original_model = prev_model

    app.cfg.save()

    data_dir = os.path.dirname(gc.litellm_config) if gc.litellm_config else os.path.expanduser("~/.defenseclaw")
    _print_guardrail_summary(gc, app.cfg.claw.config_file, restart=restart)

    if restart:
        _restart_services(data_dir)

    if app.logger:
        app.logger.log_action(
            "setup-guardrail", "config",
            f"mode={gc.mode} scanner_mode={gc.scanner_mode} port={gc.port} model={gc.model}",
        )


def _interactive_guardrail_setup(app: AppContext, gc) -> None:
    from defenseclaw.guardrail import (
        detect_api_key_env,
        detect_current_model,
        model_to_litellm_name,
    )

    click.echo()
    click.echo("  LLM Guardrail Configuration")
    click.echo("  ────────────────────────────")
    click.echo()
    click.echo("  Routes all LLM traffic through a local inspection proxy.")
    click.echo("  Every prompt and response is scanned for security issues.")
    click.echo()

    if not click.confirm("  Enable LLM guardrail?", default=True):
        gc.enabled = False
        return

    gc.enabled = True

    click.echo()
    click.echo("  Modes:")
    click.echo("    observe — log and alert only, never block (recommended to start)")
    click.echo("    action  — block prompts/responses that match security policies")
    gc.mode = click.prompt(
        "  Mode", type=click.Choice(["observe", "action"]), default=gc.mode or "observe",
    )

    click.echo()
    click.echo("  Scanner modes:")
    click.echo("    local  — pattern matching only, no network calls (fastest)")
    click.echo("    remote — Cisco AI Defense cloud API only")
    click.echo("    both   — local first, then Cisco if clean (recommended)")
    gc.scanner_mode = click.prompt(
        "  Scanner mode", type=click.Choice(["local", "remote", "both"]),
        default=gc.scanner_mode or "local",
    )

    if gc.scanner_mode in ("remote", "both"):
        click.echo()
        click.echo("  Cisco AI Defense Configuration")
        click.echo("  ──────────────────────────────")
        gc.cisco_ai_defense.endpoint = click.prompt(
            "  API endpoint", default=gc.cisco_ai_defense.endpoint,
        )
        cisco_key_env = gc.cisco_ai_defense.api_key_env or "CISCO_AI_DEFENSE_API_KEY"
        env_val = os.environ.get(cisco_key_env, "")
        if env_val:
            click.echo(f"  API key env var: {cisco_key_env} ({_mask(env_val)})")
        else:
            click.echo(f"  API key env var: {cisco_key_env} (not set)")
            click.echo(f"    Set it before starting: export {cisco_key_env}=your-key")
        gc.cisco_ai_defense.api_key_env = click.prompt(
            "  API key env var name", default=cisco_key_env,
        )
        gc.cisco_ai_defense.timeout_ms = click.prompt(
            "  Timeout (ms)", default=gc.cisco_ai_defense.timeout_ms, type=int,
        )

    gc.port = click.prompt("  LiteLLM proxy port", default=gc.port or 4000, type=int)

    # Detect current model
    current_model, current_provider = detect_current_model(app.cfg.claw.config_file)
    click.echo()

    if current_model and not current_model.startswith("litellm/"):
        click.echo(f"  Current OpenClaw model: {current_model}")
        if click.confirm("  Route this model through the guardrail?", default=True):
            gc.model = current_model
            gc.model_name = model_to_litellm_name(current_model)
            gc.original_model = current_model
        else:
            gc.model = click.prompt("  Upstream model (e.g. anthropic/claude-sonnet-4-20250514)")
            gc.model_name = model_to_litellm_name(gc.model)
    elif current_model and current_model.startswith("litellm/"):
        click.echo(f"  Already routed through LiteLLM: {current_model}")
        if gc.model:
            click.echo(f"  Upstream model: {gc.model}")
        else:
            click.echo("  Upstream model not configured — need to set it.")
            gc.model = click.prompt("  Upstream model (e.g. anthropic/claude-sonnet-4-20250514)")
            gc.model_name = model_to_litellm_name(gc.model)
        if not gc.original_model or gc.original_model.startswith("litellm/"):
            gc.original_model = gc.model
    else:
        gc.model = click.prompt("  Upstream model (e.g. anthropic/claude-sonnet-4-20250514)")
        gc.model_name = model_to_litellm_name(gc.model)

    if not gc.model_name:
        gc.model_name = model_to_litellm_name(gc.model)

    if not gc.model or not gc.model_name:
        click.echo("  Error: model and model_name must not be empty.")
        gc.enabled = False
        return

    # API key env var
    if not gc.api_key_env or _looks_like_secret(gc.api_key_env):
        gc.api_key_env = detect_api_key_env(gc.model)

    env_val = os.environ.get(gc.api_key_env, "")
    click.echo()
    if env_val:
        click.echo(f"  API key env var: {gc.api_key_env} ({_mask(env_val)})")
        if not click.confirm("  Use this env var?", default=True):
            gc.api_key_env = _prompt_env_var_name(gc.api_key_env)
    else:
        click.echo(f"  API key env var: {gc.api_key_env} (not currently set in environment)")
        click.echo("  Set it before starting the sidecar:")
        click.echo(f"    export {gc.api_key_env}=your-key-here")
        gc.api_key_env = _prompt_env_var_name(gc.api_key_env)


def _disable_guardrail(app: AppContext, gc, *, restart: bool = False) -> None:
    from defenseclaw.guardrail import restore_openclaw_config

    click.echo()
    click.echo("  Disabling LLM guardrail...")

    if gc.original_model:
        if restore_openclaw_config(app.cfg.claw.config_file, gc.original_model):
            click.echo(f"  ✓ OpenClaw model restored to: {gc.original_model}")
        else:
            click.echo("  ⚠ Could not restore OpenClaw config")

    gc.enabled = False
    app.cfg.save()
    click.echo("  ✓ Config saved")

    if restart:
        click.echo()
        data_dir = os.path.dirname(gc.litellm_config) if gc.litellm_config else os.path.expanduser("~/.defenseclaw")
        _restart_services(data_dir)
    else:
        click.echo()
        click.echo("  Restart services for changes to take effect:")
        click.echo("    defenseclaw-gateway restart")
        click.echo("    openclaw gateway restart")
        click.echo()
        click.echo("  Or re-run with --restart:")
        click.echo("    defenseclaw setup guardrail --disable --restart")
    click.echo()

    if app.logger:
        app.logger.log_action("setup-guardrail", "config", "disabled")


def _find_guardrail_source() -> str | None:
    """Locate the guardrail module in the repo or package."""
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "guardrails", "defenseclaw_guardrail.py"),
        os.path.join(os.path.dirname(__file__), "..", "guardrails", "defenseclaw_guardrail.py"),
    ]
    # Also check relative to the repo root if we can detect it
    try:
        pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        repo_root = os.path.dirname(os.path.dirname(pkg_dir))
        candidates.append(os.path.join(repo_root, "guardrails", "defenseclaw_guardrail.py"))
    except Exception:
        pass

    for c in candidates:
        resolved = os.path.realpath(c)
        if os.path.isfile(resolved):
            return resolved
    return None


def _print_guardrail_summary(gc, openclaw_config_file: str, *, restart: bool = False) -> None:
    click.echo()
    click.echo("  ✓ Config saved to ~/.defenseclaw/config.yaml")
    click.echo(f"  ✓ LiteLLM config written to {gc.litellm_config}")
    click.echo(f"  ✓ Guardrail module installed to {gc.guardrail_dir}/defenseclaw_guardrail.py")
    click.echo(f"  ✓ OpenClaw config patched: {openclaw_config_file}")
    if gc.original_model:
        click.echo(f"  ✓ Original model saved for revert: {gc.original_model}")
    click.echo()

    rows = [
        ("mode", gc.mode),
        ("scanner_mode", gc.scanner_mode),
        ("port", str(gc.port)),
        ("model", gc.model),
        ("model_name", gc.model_name),
        ("api_key_env", gc.api_key_env),
    ]
    if gc.scanner_mode in ("remote", "both"):
        rows.append(("cisco_endpoint", gc.cisco_ai_defense.endpoint))
        rows.append(("cisco_api_key_env", gc.cisco_ai_defense.api_key_env))
        rows.append(("cisco_timeout_ms", str(gc.cisco_ai_defense.timeout_ms)))
    for key, val in rows:
        click.echo(f"    guardrail.{key + ':':<16s} {val}")
    click.echo()

    if not restart:
        click.echo("  Restart services for changes to take effect:")
        click.echo("    defenseclaw-gateway restart")
        click.echo("    openclaw gateway restart")
        click.echo()
        click.echo("  Or re-run with --restart:")
        click.echo("    defenseclaw setup guardrail --restart")
        click.echo()

    click.echo("  To disable and revert:")
    click.echo("    defenseclaw setup guardrail --disable")
    click.echo()


# ---------------------------------------------------------------------------
# Service restart helpers
# ---------------------------------------------------------------------------

def _is_pid_alive(pid_file: str) -> bool:
    """Check if the process in the given PID file is alive (signal 0)."""
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError, OSError):
        return False


def _restart_services(data_dir: str) -> None:
    """Restart defenseclaw-gateway and openclaw gateway."""
    click.echo("  Restarting services...")
    click.echo("  ──────────────────────")

    _restart_defense_gateway(data_dir)
    _restart_openclaw_gateway()

    click.echo()


def _restart_defense_gateway(data_dir: str) -> None:
    pid_file = os.path.join(data_dir, "gateway.pid")
    was_running = _is_pid_alive(pid_file)

    action = "restarting" if was_running else "starting"
    click.echo(f"  defenseclaw-gateway: {action}...", nl=False)

    cmd = ["defenseclaw-gateway", "restart"] if was_running else ["defenseclaw-gateway", "start"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            click.echo(" ✓")
        else:
            click.echo(" ✗")
            err = (result.stderr or result.stdout or "").strip()
            if err:
                for line in err.splitlines()[:3]:
                    click.echo(f"    {line}")
    except FileNotFoundError:
        click.echo(" ✗ (binary not found)")
        click.echo("    Build with: make gateway")
    except subprocess.TimeoutExpired:
        click.echo(" ✗ (timed out)")


def _restart_openclaw_gateway() -> None:
    click.echo("  openclaw gateway: checking...", nl=False)

    try:
        health = subprocess.run(
            ["openclaw", "gateway", "health"],
            capture_output=True, text=True, timeout=15,
        )
        was_running = health.returncode == 0
    except FileNotFoundError:
        click.echo(" skipped (openclaw not found)")
        return
    except subprocess.TimeoutExpired:
        click.echo(" skipped (health check timed out)")
        return

    if not was_running:
        click.echo(" not running, skipping")
        click.echo("    Start manually: openclaw gateway")
        return

    click.echo(" restarting...", nl=False)
    try:
        result = subprocess.run(
            ["openclaw", "gateway", "restart"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            click.echo(" ✓")
        else:
            click.echo(" ✗")
            err = (result.stderr or result.stdout or "").strip()
            if err:
                for line in err.splitlines()[:3]:
                    click.echo(f"    {line}")
    except subprocess.TimeoutExpired:
        click.echo(" ✗ (timed out)")


def _looks_like_secret(value: str) -> bool:
    """Detect if a value looks like an actual secret rather than an env var name."""
    if not value:
        return False
    prefixes = ("sk-", "sk-ant-", "sk-proj-", "ghp_", "gho_", "xoxb-", "xoxp-")
    if any(value.startswith(p) for p in prefixes):
        return True
    if len(value) > 30 and not value.isupper():
        return True
    return False


def _prompt_env_var_name(default: str) -> str:
    """Prompt for an env var name, rejecting values that look like actual secrets."""
    while True:
        val = click.prompt("  Env var name (e.g. ANTHROPIC_API_KEY)", default=default)
        if _looks_like_secret(val):
            click.echo("  That looks like an actual API key, not an env var name.")
            click.echo("  Enter the NAME of the environment variable (e.g. ANTHROPIC_API_KEY).")
            continue
        return val


def _print_gateway_summary(gw) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    rows = [
        ("host", gw.host),
        ("port", str(gw.port)),
        ("api_port", str(gw.api_port)),
        ("token", _mask(gw.token) if gw.token else "(none — local mode)"),
    ]

    for key, val in rows:
        click.echo(f"    gateway.{key + ':':<12s} {val}")
    click.echo()

    if gw.token:
        click.echo("  Start the sidecar with:")
        click.echo("    defenseclaw-gateway")
    else:
        click.echo("  Start the sidecar with:")
        click.echo("    defenseclaw-gateway")
        click.echo("  (local mode — ensure OpenClaw is running on this machine)")
    click.echo()
