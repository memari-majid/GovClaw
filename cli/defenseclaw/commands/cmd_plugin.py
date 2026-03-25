"""defenseclaw plugin — Manage plugins (install, list, remove, scan)."""

from __future__ import annotations

import os
import shutil

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def plugin() -> None:
    """Manage DefenseClaw plugins — install, list, remove, scan."""


@plugin.command()
@click.argument("name_or_path")
@click.option("--json", "as_json", is_flag=True, help="Output scan results as JSON")
@click.option("--policy", "policy_name", default="", help="Scan policy: default, strict, permissive, or path to YAML")
@click.option("--profile", type=click.Choice(["default", "strict"]), default=None,
              help="Scan profile (overrides policy profile)")
@click.option("--use-llm", is_flag=True, help="Enable LLM-based semantic analysis (uses skill_scanner LLM config)")
@click.option("--llm-model", default="", help="LLM model override (e.g. claude-sonnet-4-20250514, gpt-4)")
@click.option("--llm-provider", default="", help="LLM provider hint (anthropic, openai, ollama, etc.)")
@click.option("--llm-consensus-runs", default=0, type=int, help="Number of LLM consensus runs (default: 1)")
@click.option("--enable-meta/--no-meta", default=True, help="Enable/disable meta analyzer (default: enabled)")
@click.option("--lenient", is_flag=True, help="Suppress low-confidence findings (sets min_confidence=0.5)")
@pass_ctx
def scan(
    app: AppContext,
    name_or_path: str,
    as_json: bool,
    policy_name: str,
    profile: str | None,
    use_llm: bool,
    llm_model: str,
    llm_provider: str,
    llm_consensus_runs: int,
    enable_meta: bool,
    lenient: bool,
) -> None:
    """Scan a plugin directory for security issues.

    Uses defenseclaw-plugin-scanner to check for dangerous permissions,
    install scripts, credential theft, obfuscation, and supply chain risks.

    LLM analysis uses the same litellm configuration as the skill scanner
    (reads from config.yaml: scanners.skill_scanner.llm_*).

    Examples:\n
      defenseclaw plugin scan my-plugin\n
      defenseclaw plugin scan my-plugin --policy strict\n
      defenseclaw plugin scan my-plugin --use-llm\n
      defenseclaw plugin scan my-plugin --use-llm --llm-model gpt-4\n
      defenseclaw plugin scan my-plugin --policy ~/.defenseclaw/policies/custom.yaml\n
      defenseclaw plugin scan /path/to/plugin --profile strict --lenient
    """
    from defenseclaw.scanner.plugin import PluginScannerWrapper

    plugin_dir = app.cfg.plugin_dir
    scan_dir = name_or_path

    if not os.path.isdir(scan_dir):
        candidate = os.path.join(plugin_dir, name_or_path)
        if os.path.isdir(candidate):
            scan_dir = candidate
        else:
            click.echo(f"error: plugin not found: {name_or_path}", err=True)
            click.echo(f"  Provide a path or an installed plugin name from {plugin_dir}", err=True)
            raise SystemExit(1)

    # Build scan options from CLI flags + config
    scan_options = _build_scan_options(
        app, policy_name, profile, use_llm, llm_model, llm_provider,
        llm_consensus_runs, enable_meta, lenient,
    )

    scanner = PluginScannerWrapper()
    if not as_json:
        flags = []
        if policy_name:
            flags.append(f"policy={policy_name}")
        if use_llm:
            model = llm_model or scan_options.get("llm_model", "")
            flags.append(f"llm={model}")
        if profile:
            flags.append(f"profile={profile}")
        flag_str = f" ({', '.join(flags)})" if flags else ""
        click.echo(f"[plugin] scanning {scan_dir}{flag_str}...")

    try:
        result = scanner.scan(scan_dir, **scan_options)
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"error: scan failed: {exc}", err=True)
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    if as_json:
        click.echo(result.to_json())
    elif result.is_clean():
        click.secho(f"  Plugin: {os.path.basename(scan_dir)}", bold=True)
        click.secho("  Verdict: CLEAN", fg="green")
    else:
        sev = result.max_severity()
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
        click.secho(f"  Plugin:   {os.path.basename(scan_dir)}", bold=True)
        click.echo(f"  Duration: {result.duration.total_seconds():.2f}s")
        click.secho(f"  Verdict:  {sev} ({len(result.findings)} findings)", fg=color)
        click.echo()
        for f in result.findings:
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
            click.secho(f"    [{f.severity}]", fg=sev_color, nl=False)
            click.echo(f" {f.title}")
            if f.location:
                click.echo(f"      Location: {f.location}")
            if f.remediation:
                click.echo(f"      Fix: {f.remediation}")


def _build_scan_options(
    app: AppContext,
    policy_name: str,
    profile: str | None,
    use_llm: bool,
    llm_model: str,
    llm_provider: str,
    llm_consensus_runs: int,
    enable_meta: bool,
    lenient: bool,
) -> dict:
    """Build scan options dict from CLI flags + skill_scanner LLM config."""
    opts: dict = {}

    if policy_name:
        opts["policy"] = policy_name
    if profile:
        opts["profile"] = profile

    # LLM config: CLI flags override, then fall back to skill_scanner config
    if use_llm:
        cfg = app.cfg.scanners.skill_scanner
        opts["use_llm"] = True
        opts["llm_model"] = llm_model or cfg.llm_model or "claude-sonnet-4-20250514"
        opts["llm_api_key"] = cfg.llm_api_key
        opts["llm_provider"] = llm_provider or cfg.llm_provider
        opts["llm_consensus_runs"] = llm_consensus_runs or cfg.llm_consensus_runs or 1

    if not enable_meta:
        opts["disable_meta"] = True

    if lenient:
        opts["lenient"] = True

    return opts


@plugin.command()
@click.argument("name_or_path")
@pass_ctx
def install(app: AppContext, name_or_path: str) -> None:
    """Install a plugin from a path or registry."""
    plugin_dir = app.cfg.plugin_dir
    os.makedirs(plugin_dir, exist_ok=True)

    if os.path.isdir(name_or_path):
        name = os.path.basename(name_or_path.rstrip("/"))
        dest = os.path.join(plugin_dir, name)
        if os.path.exists(dest):
            click.echo(f"Plugin already installed: {name}")
            click.echo(f"  Remove first with: defenseclaw plugin remove {name}")
            return
        shutil.copytree(name_or_path, dest)
        click.echo(f"Installed plugin: {name}")
        if app.logger:
            app.logger.log_action("plugin-install", name, f"source={name_or_path}")
    else:
        click.echo("Plugin registry not yet implemented.")
        click.echo("  Install from a local path: defenseclaw plugin install /path/to/plugin")


@plugin.command("list")
@pass_ctx
def list_plugins(app: AppContext) -> None:
    """List installed plugins."""
    plugin_dir = app.cfg.plugin_dir
    if not os.path.isdir(plugin_dir):
        click.echo("No plugins installed.")
        return

    entries = [e for e in os.listdir(plugin_dir) if os.path.isdir(os.path.join(plugin_dir, e))]
    if not entries:
        click.echo("No plugins installed.")
        return

    click.echo("Installed plugins:")
    for name in sorted(entries):
        click.echo(f"  {name}")


@plugin.command()
@click.argument("name")
@pass_ctx
def remove(app: AppContext, name: str) -> None:
    """Remove an installed plugin."""
    plugin_dir = app.cfg.plugin_dir
    safe_name = os.path.basename(name)
    if not safe_name or safe_name in (".", ".."):
        click.echo(f"Invalid plugin name: {name}", err=True)
        raise SystemExit(1)

    path = os.path.realpath(os.path.join(plugin_dir, safe_name))
    if not path.startswith(os.path.realpath(plugin_dir) + os.sep):
        click.echo(f"Invalid plugin name: {name}", err=True)
        raise SystemExit(1)

    if not os.path.isdir(path):
        click.echo(f"Plugin not found: {safe_name}")
        return

    shutil.rmtree(path)
    click.echo(f"Removed plugin: {safe_name}")
    if app.logger:
        app.logger.log_action("plugin-remove", safe_name, "")
