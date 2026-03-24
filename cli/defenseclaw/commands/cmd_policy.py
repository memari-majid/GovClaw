"""defenseclaw policy — Create, list, show, and activate security policies."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
import yaml

from defenseclaw.context import AppContext, pass_ctx

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RUNTIME_CHOICES = ["disable", "enable"]
FILE_CHOICES = ["quarantine", "none"]
INSTALL_CHOICES = ["block", "allow", "none"]

BUILTIN_POLICIES = {"default", "strict", "permissive"}


def _policies_dir(app: AppContext) -> str:
    return app.cfg.policy_dir


def _bundled_policies_dir() -> str:
    """Return path to the bundled policies/ directory shipped with the repo."""
    here = Path(__file__).resolve()
    # cli/defenseclaw/commands/cmd_policy.py -> repo root / policies
    repo_root = here.parent.parent.parent.parent
    return str(repo_root / "policies")


def _ensure_policies_dir(app: AppContext) -> str:
    d = _policies_dir(app)
    os.makedirs(d, exist_ok=True)
    return d


def _list_policy_files(app: AppContext) -> list[str]:
    """Return paths to all .yaml policy files (user dir + bundled)."""
    files: list[str] = []
    user_dir = _policies_dir(app)
    if os.path.isdir(user_dir):
        for name in os.listdir(user_dir):
            if name.endswith(".yaml") and not name.startswith("."):
                files.append(os.path.join(user_dir, name))

    bundled = _bundled_policies_dir()
    if os.path.isdir(bundled):
        seen = {os.path.basename(f) for f in files}
        for name in os.listdir(bundled):
            if name.endswith(".yaml") and not name.startswith(".") and name not in seen:
                files.append(os.path.join(bundled, name))

    return sorted(files)


def _load_policy(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _find_policy(app: AppContext, name: str) -> str | None:
    """Find a policy file by name (without .yaml extension)."""
    user_dir = _policies_dir(app)
    candidate = os.path.join(user_dir, f"{name}.yaml")
    if os.path.isfile(candidate):
        return candidate

    bundled = _bundled_policies_dir()
    candidate = os.path.join(bundled, f"{name}.yaml")
    if os.path.isfile(candidate):
        return candidate

    return None


@click.group()
def policy() -> None:
    """Manage DefenseClaw security policies — create, list, show, activate."""


@policy.command()
@click.argument("name")
@click.option("--description", "-d", default="", help="Policy description")
@click.option("--from-preset", type=click.Choice(["default", "strict", "permissive"]),
              help="Start from a built-in preset and customize")
@click.option("--scan-on-install/--no-scan-on-install", default=True,
              help="Scan on install (default: true)")
@click.option("--allow-list-bypass/--no-allow-list-bypass", default=True,
              help="Allow-listed items skip scan (default: true)")
@click.option("--critical-action", type=click.Choice(["block", "warn", "allow"]), default=None,
              help="Action for CRITICAL findings")
@click.option("--high-action", type=click.Choice(["block", "warn", "allow"]), default=None,
              help="Action for HIGH findings")
@click.option("--medium-action", type=click.Choice(["block", "warn", "allow"]), default=None,
              help="Action for MEDIUM findings")
@click.option("--low-action", type=click.Choice(["block", "warn", "allow"]), default=None,
              help="Action for LOW findings")
@pass_ctx
def create(
    app: AppContext,
    name: str,
    description: str,
    from_preset: str | None,
    scan_on_install: bool,
    allow_list_bypass: bool,
    critical_action: str | None,
    high_action: str | None,
    medium_action: str | None,
    low_action: str | None,
) -> None:
    """Create a new security policy.

    Examples:\n
      defenseclaw policy create my-strict --from-preset strict\n
      defenseclaw policy create prod --critical-action block --high-action block --medium-action warn\n
      defenseclaw policy create dev --critical-action block --high-action warn --medium-action allow
    """
    if name in BUILTIN_POLICIES:
        click.echo(f"error: cannot overwrite built-in policy '{name}'", err=True)
        raise SystemExit(1)

    policies_dir = _ensure_policies_dir(app)
    dest = os.path.join(policies_dir, f"{name}.yaml")

    if os.path.exists(dest):
        click.echo(f"error: policy '{name}' already exists at {dest}", err=True)
        click.echo("  Delete it first or choose a different name.", err=True)
        raise SystemExit(1)

    # Start from preset or defaults
    if from_preset:
        preset_path = _find_policy(app, from_preset)
        if preset_path:
            data = _load_policy(preset_path)
        else:
            data = _default_policy_data()
    else:
        data = _default_policy_data()

    data["name"] = name
    if description:
        data["description"] = description
    elif "description" not in data:
        data["description"] = f"Custom policy: {name}"

    data.setdefault("admission", {})
    data["admission"]["scan_on_install"] = scan_on_install
    data["admission"]["allow_list_bypass_scan"] = allow_list_bypass

    # Apply severity overrides
    actions = data.setdefault("skill_actions", {})
    severity_overrides = {
        "critical": critical_action,
        "high": high_action,
        "medium": medium_action,
        "low": low_action,
    }

    for sev, action in severity_overrides.items():
        if action is not None:
            actions[sev] = _action_for_level(action)

    # Ensure all severities exist
    for sev in SEVERITIES:
        if sev not in actions:
            actions[sev] = _action_for_level("allow")

    with open(dest, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    click.secho(f"Policy '{name}' created at {dest}", fg="green")
    click.echo(f"  Activate with: defenseclaw policy activate {name}")

    if app.logger:
        app.logger.log_action("policy-create", name, f"path={dest}")


@policy.command("list")
@pass_ctx
def list_policies(app: AppContext) -> None:
    """List all available policies (built-in and custom)."""
    files = _list_policy_files(app)

    if not files:
        click.echo("No policies found.")
        return

    active = _get_active_policy_name(app)

    click.echo("Available policies:")
    click.echo()
    for path in files:
        data = _load_policy(path)
        pname = data.get("name", Path(path).stem)
        desc = data.get("description", "")
        is_builtin = path.startswith(_bundled_policies_dir())
        is_active = pname == active

        prefix = "  * " if is_active else "    "
        label = click.style(pname, bold=True)
        tag = ""
        if is_builtin:
            tag = click.style(" [built-in]", dim=True)
        if is_active:
            tag += click.style(" [active]", fg="green")

        click.echo(f"{prefix}{label}{tag}")
        if desc:
            click.echo(f"      {desc}")

    click.echo()
    click.echo("  Activate a policy: defenseclaw policy activate <name>")
    click.echo("  Show details:      defenseclaw policy show <name>")


@policy.command()
@click.argument("name")
@pass_ctx
def show(app: AppContext, name: str) -> None:
    """Show details of a policy."""
    path = _find_policy(app, name)
    if not path:
        click.echo(f"error: policy '{name}' not found", err=True)
        raise SystemExit(1)

    data = _load_policy(path)
    pname = data.get("name", name)
    desc = data.get("description", "")

    click.secho(f"Policy: {pname}", bold=True)
    if desc:
        click.echo(f"  {desc}")
    click.echo()

    admission = data.get("admission", {})
    click.echo("Admission:")
    click.echo(f"  scan_on_install:        {admission.get('scan_on_install', True)}")
    click.echo(f"  allow_list_bypass_scan: {admission.get('allow_list_bypass_scan', True)}")
    click.echo()

    click.echo("Severity Actions:")
    actions = data.get("skill_actions", {})
    for sev in SEVERITIES:
        action = actions.get(sev, {})
        file_a = action.get("file", "none")
        runtime_a = action.get("runtime", "enable")
        install_a = action.get("install", "none")

        if install_a == "block":
            color = "red"
        elif file_a == "quarantine":
            color = "red"
        elif runtime_a == "disable":
            color = "yellow"
        else:
            color = "green"

        click.echo(f"  {sev.upper():10s}  ", nl=False)
        click.secho(f"install={install_a:5s}  file={file_a:10s}  runtime={runtime_a}", fg=color)

    enforcement = data.get("enforcement", {})
    if enforcement:
        click.echo()
        click.echo("Enforcement:")
        click.echo(f"  update_sandbox_policy:         {enforcement.get('update_sandbox_policy', True)}")
        click.echo(f"  max_enforcement_delay_seconds: {enforcement.get('max_enforcement_delay_seconds', 2)}")

    audit_cfg = data.get("audit", {})
    if audit_cfg:
        click.echo()
        click.echo("Audit:")
        click.echo(f"  retention_days: {audit_cfg.get('retention_days', 90)}")


@policy.command()
@click.argument("name")
@pass_ctx
def activate(app: AppContext, name: str) -> None:
    """Activate a policy — applies it to config.yaml and syncs OPA data.json."""
    path = _find_policy(app, name)
    if not path:
        click.echo(f"error: policy '{name}' not found", err=True)
        raise SystemExit(1)

    data = _load_policy(path)

    # Update skill_actions in config
    actions_raw = data.get("skill_actions", {})

    from defenseclaw.config import (
        SeverityAction,
        SkillActionsConfig,
    )

    def _parse_action(raw: dict) -> SeverityAction:
        return SeverityAction(
            file=raw.get("file", "none"),
            runtime=raw.get("runtime", "enable"),
            install=raw.get("install", "none"),
        )

    new_actions = SkillActionsConfig(
        critical=_parse_action(actions_raw.get("critical", {})),
        high=_parse_action(actions_raw.get("high", {})),
        medium=_parse_action(actions_raw.get("medium", {})),
        low=_parse_action(actions_raw.get("low", {})),
        info=_parse_action(actions_raw.get("info", {})),
    )

    app.cfg.skill_actions = new_actions
    app.cfg.save()
    click.echo(f"Config updated with policy '{name}'.")

    # Sync OPA data.json
    _sync_opa_data(app, data)

    click.secho(f"Policy '{name}' activated.", fg="green")
    if app.logger:
        app.logger.log_action("policy-activate", name, f"source={path}")


@policy.command()
@click.argument("name")
@pass_ctx
def delete(app: AppContext, name: str) -> None:
    """Delete a custom policy."""
    if name in BUILTIN_POLICIES:
        click.echo(f"error: cannot delete built-in policy '{name}'", err=True)
        raise SystemExit(1)

    user_dir = _policies_dir(app)
    path = os.path.join(user_dir, f"{name}.yaml")
    if not os.path.isfile(path):
        click.echo(f"error: policy '{name}' not found in {user_dir}", err=True)
        raise SystemExit(1)

    os.remove(path)
    click.echo(f"Policy '{name}' deleted.")
    if app.logger:
        app.logger.log_action("policy-delete", name, "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _default_policy_data() -> dict:
    return {
        "name": "custom",
        "description": "Custom policy",
        "admission": {
            "scan_on_install": True,
            "allow_list_bypass_scan": True,
        },
        "skill_actions": {
            "critical": {"file": "quarantine", "runtime": "disable", "install": "block"},
            "high": {"file": "quarantine", "runtime": "disable", "install": "block"},
            "medium": {"file": "none", "runtime": "enable", "install": "none"},
            "low": {"file": "none", "runtime": "enable", "install": "none"},
            "info": {"file": "none", "runtime": "enable", "install": "none"},
        },
        "enforcement": {
            "update_sandbox_policy": True,
            "max_enforcement_delay_seconds": 2,
        },
        "audit": {
            "log_all_actions": True,
            "log_scan_results": True,
            "retention_days": 90,
        },
    }


def _action_for_level(level: str) -> dict:
    """Convert a simple action level (block/warn/allow) to a full action dict."""
    if level == "block":
        return {"file": "quarantine", "runtime": "disable", "install": "block"}
    elif level == "warn":
        return {"file": "none", "runtime": "enable", "install": "none"}
    else:  # allow
        return {"file": "none", "runtime": "enable", "install": "none"}


def _get_active_policy_name(app: AppContext) -> str | None:
    """Determine which policy is currently active by reading OPA data.json."""
    rego_dir = _bundled_policies_dir()
    data_json = os.path.join(rego_dir, "rego", "data.json")
    if not os.path.isfile(data_json):
        return None
    try:
        with open(data_json) as f:
            data = json.load(f)
        return data.get("config", {}).get("policy_name")
    except (OSError, json.JSONDecodeError):
        return None


def _sync_opa_data(app: AppContext, policy_data: dict) -> None:
    """Sync OPA data.json with the activated policy settings."""
    rego_dir = os.path.join(_bundled_policies_dir(), "rego")
    data_json_path = os.path.join(rego_dir, "data.json")

    if not os.path.isfile(data_json_path):
        return

    try:
        with open(data_json_path) as f:
            opa_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    # Update config section
    opa_data.setdefault("config", {})
    opa_data["config"]["policy_name"] = policy_data.get("name", "custom")
    admission = policy_data.get("admission", {})
    if "allow_list_bypass_scan" in admission:
        opa_data["config"]["allow_list_bypass_scan"] = admission["allow_list_bypass_scan"]
    if "scan_on_install" in admission:
        opa_data["config"]["scan_on_install"] = admission["scan_on_install"]

    enforcement = policy_data.get("enforcement", {})
    if "update_sandbox_policy" in enforcement:
        opa_data["config"]["update_sandbox_policy"] = enforcement["update_sandbox_policy"]
    if "max_enforcement_delay_seconds" in enforcement:
        opa_data["config"]["max_enforcement_delay_seconds"] = enforcement["max_enforcement_delay_seconds"]

    # Update actions: map policy YAML format to OPA data.json format
    actions = policy_data.get("skill_actions", {})
    opa_actions = {}
    for sev in SEVERITIES:
        raw = actions.get(sev, {})
        runtime = raw.get("runtime", "enable")
        file_action = raw.get("file", "none")
        # OPA uses "block"/"allow" for runtime, not "disable"/"enable"
        opa_runtime = "block" if runtime == "disable" else "allow"
        opa_actions[sev.upper()] = {"runtime": opa_runtime, "file": file_action}

    opa_data["actions"] = opa_actions

    # Update audit
    audit_cfg = policy_data.get("audit", {})
    if audit_cfg:
        opa_data.setdefault("audit", {})
        for key in ("retention_days", "log_all_actions", "log_scan_results"):
            if key in audit_cfg:
                opa_data["audit"][key] = audit_cfg[key]

    with open(data_json_path, "w") as f:
        json.dump(opa_data, f, indent=2)
        f.write("\n")

    click.echo(f"OPA data.json synced at {data_json_path}")
