#!/usr/bin/env python3
"""
Adversary-in-a-Box — Red Team Campaign Runner
==============================================
CLI launcher for MITRE ATT&CK campaign modules.

Usage:
    python runner.py --list
    python runner.py --campaign phishing
    python runner.py --campaign full-killchain
    python runner.py --technique T1566.001
"""

import ipaddress
import os
import socket
import sys
import time
from typing import NoReturn
from urllib.parse import urlparse, urlsplit, urlunsplit

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from utils.logger import AttackLogger
from utils.mitre_tagger import MitreTagger

# Campaign registry — maps names to module paths
CAMPAIGNS: dict[str, dict] = {
    "phishing": {
        "module": "campaigns.phishing.spear_phish",
        "class": "SpearPhishCampaign",
        "techniques": ["T1566.001"],
        "description": "Spearphishing email with benign payload attachment",
        "domain": 1,
    },
    "recon": {
        "module": "campaigns.initial_access.vuln_scan",
        "class": "VulnScanCampaign",
        "techniques": ["T1595", "T1589"],
        "description": "Active reconnaissance — port scan + service fingerprinting",
        "domain": 1,
    },
    "initial-access": {
        "module": "campaigns.initial_access.exploit_web",
        "class": "ExploitWebCampaign",
        "techniques": ["T1190"],
        "description": "Exploit public-facing web application (OWASP Top 10)",
        "domain": 1,
    },
    # Phase B1c: standalone malware-drop (T1204). Stages EICAR to a known
    # path; reversible via --cleanup-all.
    "malware-drop": {
        "module": "campaigns.initial_access.malware_drop",
        "class": "MalwareDropCampaign",
        "techniques": ["T1204"],
        "description": "Drop EICAR test payload (benign AV-fail marker)",
        "domain": 1,
    },
    "privesc": {
        "module": "campaigns.privilege_escalation.sudo_abuse",
        "class": "SudoAbuseCampaign",
        "techniques": ["T1548.003"],
        "description": "Privilege escalation via sudo misconfiguration",
        "domain": 1,
    },
    # Phase A6: SuidHuntCampaign existed in
    # campaigns/privilege_escalation/suid_hunt.py but wasn't registered, so
    # --technique T1548.001 silently fell back to SudoAbuseCampaign — same
    # bug class as the SshHijack one closed by audit-2 Gap #10.
    "privesc-suid": {
        "module": "campaigns.privilege_escalation.suid_hunt",
        "class": "SuidHuntCampaign",
        "techniques": ["T1548.001"],
        "description": "Privilege escalation via SUID/SGID binary abuse",
        "domain": 1,
    },
    # Phase B1a: on-path attack simulation (T1557). Containers share an L2
    # bridge so real ARP spoofing is suppressed; the campaign emits a
    # behavioral signature at /tmp/lab_mitm.log instead.
    "mitm": {
        "module": "campaigns.credential_access.mitm",
        "class": "MitmCampaign",
        "techniques": ["T1557"],
        "description": "On-path attack simulation -- duplicate MAC/IP binding",
        "domain": 1,
    },
    # Phase B1b: brute force (T1110). 10-entry hard-coded wordlist
    # against victim-web /login, rate-limited.
    "brute-force": {
        "module": "campaigns.credential_access.brute_force",
        "class": "BruteForceCampaign",
        "techniques": ["T1110"],
        "description": "Credential brute force against victim-web /login",
        "domain": 2,
    },
    "lateral": {
        "module": "campaigns.lateral_movement.pass_the_hash",
        "class": "PassTheHashCampaign",
        "techniques": ["T1550.002"],
        "description": "Lateral movement via Pass-the-Hash (NTLM relay simulation)",
        "domain": 2,
    },
    # Audit-2 Gap #10: SshHijackCampaign existed in
    # campaigns/lateral_movement/ssh_hijack.py but wasn't registered, so
    # --technique T1563.001 silently fell back to PassTheHashCampaign.
    "lateral-ssh": {
        "module": "campaigns.lateral_movement.ssh_hijack",
        "class": "SshHijackCampaign",
        "techniques": ["T1563.001"],
        "description": "Lateral movement via SSH agent socket hijacking",
        "domain": 2,
    },
    "exfil": {
        "module": "campaigns.exfiltration.dns_tunnel",
        "class": "DnsTunnelCampaign",
        "techniques": ["T1048.003"],
        "description": "Data exfiltration over DNS tunnel",
        "domain": 1,
    },
    # Same bug class as Phase A6 / audit-2 Gap #10: HttpsExfilCampaign
    # existed in campaigns/exfiltration/https_exfil.py but wasn't
    # registered, so --technique T1041 silently fell back to
    # DnsTunnelCampaign (wrong technique).
    "exfil-https": {
        "module": "campaigns.exfiltration.https_exfil",
        "class": "HttpsExfilCampaign",
        "techniques": ["T1041"],
        "description": "Data exfiltration over HTTPS C2 channel",
        "domain": 1,
    },
    "persistence": {
        "module": "campaigns.persistence.cron_backdoor",
        "class": "CronBackdoorCampaign",
        "techniques": ["T1053.003"],
        "description": "Persistence via cron backdoor",
        "domain": 1,
    },
    # Same bug class as `exfil-https` above: SshKeyPlantCampaign existed
    # in campaigns/persistence/ssh_key_plant.py but wasn't registered,
    # so --technique T1098.004 silently fell back to CronBackdoorCampaign.
    "persistence-sshkey": {
        "module": "campaigns.persistence.ssh_key_plant",
        "class": "SshKeyPlantCampaign",
        "techniques": ["T1098.004"],
        "description": "Persistence via planted SSH authorized_keys entry",
        "domain": 1,
    },
    # Phase B1d: ransomware simulation (T1486). Renames decoys in a
    # known directory with a .locked suffix + drops a ransom note.
    # Fully reversible -- cleanup() unrenames and clears the dir.
    "ransomware": {
        "module": "campaigns.impact.ransomware_sim",
        "class": "RansomwareSimCampaign",
        "techniques": ["T1486"],
        "description": "Ransomware simulation -- rename decoys + drop ransom note",
        "domain": 1,
    },
    "full-killchain": {
        "module": None,  # Runs all campaigns in sequence
        "class": None,
        # Ordered by MITRE tactic so the kill-chain narrative reads
        # recon -> initial-access -> credential-access -> privesc ->
        # lateral -> exfil -> impact -> persistence. Keep this list in
        # sync with _run_full_killchain() below.
        "techniques": [
            "T1595",
            "T1589",
            "T1566.001",
            "T1190",
            "T1204",
            "T1110",
            "T1557",
            "T1548.003",
            "T1548.001",
            "T1550.002",
            "T1563.001",
            "T1048.003",
            "T1041",
            "T1486",
            "T1053.003",
            "T1098.004",
        ],
        "description": "Full kill chain across all registered MITRE techniques",
        "domain": "1-2-3",
    },
}

# Technique-to-campaign mapping. Meta-campaigns (module=None, e.g.
# full-killchain) are excluded so their aggregated techniques list
# doesn't overwrite the real single-campaign mappings.
TECHNIQUE_MAP = {
    tech: name for name, cfg in CAMPAIGNS.items() if cfg.get("module") for tech in cfg["techniques"]
}

console = Console()
logger = AttackLogger()
tagger = MitreTagger()


def print_banner():
    banner = Text()
    banner.append("  █████╗ ██████╗ ██╗   ██╗    ██████╗  ██████╗ ██╗  ██╗\n", style="bold red")
    banner.append(" ██╔══██╗██╔══██╗██║   ██║    ██╔══██╗██╔═══██╗╚██╗██╔╝\n", style="bold red")
    banner.append(" ███████║██║  ██║██║   ██║    ██████╔╝██║   ██║ ╚███╔╝ \n", style="bold red")
    banner.append(" ██╔══██║██║  ██║╚██╗ ██╔╝    ██╔══██╗██║   ██║ ██╔██╗ \n", style="bold red")
    banner.append(" ██║  ██║██████╔╝ ╚████╔╝     ██████╔╝╚██████╔╝██╔╝ ██╗\n", style="bold red")
    banner.append(" ╚═╝  ╚═╝╚═════╝   ╚═══╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝\n", style="bold red")
    banner.append("  Adversary-in-a-Box | Red Team Campaign Runner\n", style="dim")
    banner.append("  CompTIA Security+ SY0-701 | MITRE ATT&CK Framework\n", style="dim")
    console.print(Panel(banner, border_style="red"))


def list_campaigns():
    """Render the available-campaigns table."""
    print_banner()
    table = Table(title="Available Campaigns", border_style="red", header_style="bold red")
    table.add_column("Campaign", style="cyan", no_wrap=True)
    table.add_column("MITRE Techniques", style="yellow")
    table.add_column("Domain", justify="center")
    table.add_column("Description", style="white")

    for name, cfg in CAMPAIGNS.items():
        table.add_row(
            name,
            ", ".join(cfg["techniques"]),
            str(cfg["domain"]),
            cfg["description"],
        )
    console.print(table)


def _report_emit_health():
    """P4: surface silent SIEM-emission failures at the end of a run so a
    green campaign result doesn't mask telemetry that never reached ES."""
    if tagger.emit_failures:
        console.print(
            f"[bold yellow]⚠ {tagger.emit_failures}/{tagger.emit_attempts} SIEM "
            "emissions failed[/bold yellow] — this run is unlikely to be scored. "
            "Check that Elasticsearch is reachable from the red-team container."
        )


# P8 (R1): the lab fabric's docker-compose service names. A target named by
# one of these is in-scope by definition (in-lab DNS resolves it to the lab
# subnet at runtime, but we allow it by name so validation works pre-DNS too).
LAB_HOSTNAMES = frozenset(
    {
        "victim-web",
        "victim-db",
        "victim-mail",
    }
)

# P8 (R1): every operator-supplied env var a campaign may dial out to. The web
# gate alone was insufficient -- phishing reads TARGET_MAIL_HOST (live SMTP
# connect), pass-the-hash reads TARGET_DB_HOST, and mitm reads MITM_VICTIM,
# all straight from the environment. Each is vetted against the allowlist in
# run_campaign before any campaign fires, so none can be pointed out of scope.
# Keep in sync with the os.environ.get("TARGET_*"/"MITM_*") reads in campaigns/.
TARGET_ENV_VARS = (
    "TARGET_WEB",  # exploit_web / brute_force / recon (also --target default)
    "TARGET_MAIL_HOST",  # phishing.spear_phish — SMTP connection
    "TARGET_DB_HOST",  # lateral_movement.pass_the_hash
    "MITM_VICTIM",  # credential_access.mitm — spoofed victim host
)


def _target_host(target: str) -> str:
    """Extract the bare host from a URL or host[:port][/path] string.
    Normalized to lowercase with any trailing dot stripped so that
    `Victim-Web` and `victim-web.` compare equal to `victim-web`."""
    t = (target or "").strip()
    if "://" in t:
        host = urlparse(t).hostname or ""
    elif t.startswith("[") and "]" in t:  # bracketed IPv6 literal
        host = t[1 : t.index("]")]
    else:
        host = t.split("/", 1)[0].split(":", 1)[0]
    return host.rstrip(".").lower()


def _lab_networks() -> list:
    """The /24s a target IP may legally fall within (lab + quarantine)."""
    nets = []
    for prefix in (
        os.environ.get("LAB_NET_PREFIX", "172.20.0"),
        os.environ.get("QUARANTINE_NET_PREFIX", ""),
    ):
        if prefix:
            try:
                nets.append(ipaddress.ip_network(f"{prefix}.0/24", strict=False))
            except ValueError:
                pass
    return nets


def _is_lab_target(host: str) -> bool:
    """True iff host is a known lab service name or an IP within a lab /24.

    Note: for a non-literal hostname this validates the name->IP binding at
    resolve time; the campaign re-resolves at connect time, so this gate does
    not by itself defeat a rebinding resolver. The lab networks are
    `internal: true` (no egress), which is the actual containment -- prefer
    IP-literal targets when that air-gap is not present."""
    if not host:
        return False
    if host in LAB_HOSTNAMES:
        return True
    nets = _lab_networks()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not a literal IP -- resolve it (an unknown hostname pointing into
        # the lab subnet is allowed; anything else is rejected).
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (OSError, ValueError):
            return False
    return any(ip in net for net in nets)


def _resolve_host_ip(host: str):
    """Parse a literal or resolve a hostname to an ipaddress, exactly once.
    Returns None if the host is empty or cannot be resolved."""
    if not host:
        return None
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        try:
            return ipaddress.ip_address(socket.gethostbyname(host))
        except (OSError, ValueError):
            return None


def _pin_host_in_target(target: str, ip: str) -> str:
    """Return `target` with its host component replaced by `ip`, preserving
    scheme, port, path and query. #145: once the allowlist has resolved and
    vetted a hostname, the campaign must connect to that exact IP rather than
    re-resolve (which a short-TTL / rebinding resolver could swap out)."""
    t = (target or "").strip()
    # urlsplit/_target_host strip the RFC 3986 brackets off an IPv6 host, so
    # re-add them when pinning an IPv6 address or the rebuilt netloc is invalid.
    host = f"[{ip}]" if ":" in ip else ip
    if "://" in t:
        parts = urlsplit(t)
        netloc = f"{host}:{parts.port}" if parts.port is not None else host
        if parts.username:  # preserve any userinfo
            cred = parts.username + (f":{parts.password}" if parts.password else "")
            netloc = f"{cred}@{netloc}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    if t.startswith("[") and "]" in t:  # bracketed IPv6 literal -- already an IP
        return t
    host_part = t.split("/", 1)[0]
    rest = t[len(host_part) :]  # path, if any
    if ":" in host_part:
        return f"{host}:{host_part.split(':', 1)[1]}{rest}"
    return f"{host}{rest}"


def _reject_target(target: str, host: str) -> NoReturn:
    """Print the out-of-scope refusal and exit non-zero. Never returns -- the
    NoReturn annotation lets the type checker narrow `ip` to non-None after the
    rejection branch in _vet_and_pin_target."""
    prefix = os.environ.get("LAB_NET_PREFIX", "172.20.0")
    console.print(
        f"[red]✗ Refusing out-of-scope target '{target}' (host '{host}'). "
        f"P8 allowlist permits only lab services "
        f"({', '.join(sorted(LAB_HOSTNAMES))}) or IPs in {prefix}.0/24. "
        f"Set LAB_NET_PREFIX/QUARANTINE_NET_PREFIX to match your lab.[/red]"
    )
    sys.exit(2)


def _vet_and_pin_target(target: str) -> str:
    """Validate `target` against the P8 allowlist and return a connect-safe
    form. A non-literal hostname is resolved exactly once here and the
    validated IP is pinned into the returned target (#145, TOCTOU). Lab service
    names pass by name (in-lab DNS controls them); IP literals are unchanged.
    Exits non-zero on an out-of-scope target so it never reaches a campaign."""
    host = _target_host(target)
    if host in LAB_HOSTNAMES:
        # Intentionally NOT pinned: these names are served only by the lab's
        # embedded Docker DNS on an `internal: true` network the operator does
        # not control, so there is no rebinding surface. Pinning them would also
        # break the pre-DNS validation path (dry-runs / tests where the name
        # does not resolve). Arbitrary hostnames below ARE resolved and pinned.
        return target
    ip = _resolve_host_ip(host)
    if ip is None or not any(ip in net for net in _lab_networks()):
        _reject_target(target, host)
    # Pin the single vetted resolution. For an IP-literal target this is a
    # no-op (host already equals `ip`); for a hostname it freezes the address.
    return _pin_host_in_target(target, str(ip))


# P8 (R1): the in-lab default web target, used when neither --target nor
# TARGET_WEB is supplied. Pulled out of its two former inline call sites so the
# guard below can fail fast at import if a future edit (e.g. a template copy)
# ever points the fallback out of scope -- that path does not pass through the
# runtime allowlist gate.
DEFAULT_WEB_TARGET = "http://172.20.0.30"


def _within_canonical_lab(host: str) -> bool:
    """Membership test against the *documented* lab /24, independent of any
    LAB_NET_PREFIX override -- used only to sanity-check the built-in default."""
    if host in LAB_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network("172.20.0.0/24")
    except ValueError:
        return False


assert _within_canonical_lab(
    _target_host(DEFAULT_WEB_TARGET)
), f"DEFAULT_WEB_TARGET {DEFAULT_WEB_TARGET!r} is outside the canonical lab range"


def run_campaign(campaign, technique, target, dry_run):
    """Run a red team campaign or specific MITRE technique."""
    print_banner()

    if technique and not campaign:
        campaign = TECHNIQUE_MAP.get(technique)
        if not campaign:
            console.print(f"[red]Unknown technique: {technique}[/red]")
            sys.exit(1)

    if not campaign:
        console.print("[red]Error: specify --campaign or --technique[/red]")
        sys.exit(1)

    if campaign not in CAMPAIGNS:
        console.print(
            f"[red]Unknown campaign: {campaign}. Run 'runner.py --list' to see options.[/red]"
        )
        sys.exit(1)

    cfg = CAMPAIGNS[campaign]
    
    # P10: check if force is required
    is_impact = False
    if cfg.get("module"):
        is_impact = any(tagger.get_metadata(t).get("tactic") == "Impact" for t in cfg["techniques"])
    if (campaign == "full-killchain" or is_impact) and not force and not dry_run:
        console.print("[red]✗ Refusing to run destructive campaign without --force.[/red]")
        sys.exit(1)
    console.print(f"\n[bold red]🔴 Launching campaign:[/bold red] [cyan]{campaign}[/cyan]")
    console.print(f"[dim]Techniques: {', '.join(cfg['techniques'])}[/dim]")
    console.print(f"[dim]Description: {cfg['description']}[/dim]\n")

    # P8 (R1): vet EVERY operator-supplied target before anything fires --
    # --target plus each TARGET_* / MITM_* env var a campaign may dial out to.
    # The built-in lab defaults are trusted; only values the operator actually
    # set are checked. full-killchain runs every campaign, so a single sweep
    # here covers the single-campaign and kill-chain paths alike.
    # #145: vet-and-pin rewrites a vetted hostname to its resolved IP, so the
    # value the campaign actually dials is the one the allowlist approved.
    if target:
        target = _vet_and_pin_target(target)
    for var in TARGET_ENV_VARS:
        val = os.environ.get(var)
        if val:
            os.environ[var] = _vet_and_pin_target(val)

    if dry_run:
        console.print("[yellow]DRY RUN — no actions will be executed[/yellow]")
        console.print(f"[yellow]Resolved target:[/yellow] {os.environ.get('TARGET_WEB', target)}")
        console.print(f"[yellow]Campaign plan:[/yellow] {campaign} ({', '.join(cfg['techniques'])})")
        return

    # P4: warn early if the SIEM is unreachable so the operator knows this
    # run's attack telemetry won't be ingested or scored (emission is
    # best-effort and would otherwise fail silently). AIB_SKIP_PREFLIGHT (the
    # same escape hatch as scripts/lab/start.sh) skips the reachability probe
    # for tests and intentionally air-gapped dry runs.
    if not os.environ.get("AIB_SKIP_PREFLIGHT") and not tagger.preflight():
        console.print(
            f"[yellow]⚠ SIEM unreachable at {tagger.SIEM_HOST}:{tagger.SIEM_PORT} — "
            "attack telemetry will not be scored. Continuing anyway.[/yellow]"
        )

    if campaign == "full-killchain":
        _run_full_killchain(target)
    else:
        _run_single_campaign(campaign, cfg, target)

    _report_emit_health()


def _run_single_campaign(name, cfg, target_override=None):
    """Dynamically import and execute a single campaign module."""
    import importlib
    import uuid

    # audit-4 G1a: mint a per-run correlation id. Every SIEM doc this run
    # emits (lifecycle + per-technique) carries it, so the scoreboard can
    # join attack -> detection -> response by campaign_id and compute
    # MTTD/MTTA. Without it the scorer's join always returned zero rows.
    campaign_id = uuid.uuid4().hex
    start = time.monotonic()

    # campaign_start anchors MTTD; emit it before any attack action fires.
    tagger.emit_lifecycle(
        "campaign_start",
        campaign_id,
        {"campaign": name, "techniques": cfg["techniques"]},
    )
    logger.log_campaign_start(name, target_override or "", cfg["techniques"])

    try:
        module = importlib.import_module(cfg["module"])
        klass = getattr(module, cfg["class"])
        # P8 (R1): run_campaign already vetted any operator-supplied target
        # (--target / TARGET_WEB) against the allowlist. The DEFAULT_WEB_TARGET
        # fallback is an in-lab address, guarded against out-of-scope edits at
        # import (see _within_canonical_lab assertion above).
        target = target_override or os.environ.get("TARGET_WEB", DEFAULT_WEB_TARGET)
        instance = klass(target=target, logger=logger, tagger=tagger)

        console.print(f"[green]▶ Executing {cfg['class']}...[/green]")
        
        timeout_str = os.environ.get("CAMPAIGN_TIMEOUT", "")
        timeout = int(timeout_str) if timeout_str else 0
        import signal

        def _timeout_handler(signum, frame):
            raise TimeoutError("Campaign timed out.")
            
        if timeout > 0:
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(timeout)
            
        try:
            result = instance.run()
            success = bool(result.get("success"))

            if success:
                console.print("[bold green]✓ Campaign completed successfully[/bold green]")
            else:
                console.print(
                    f"[yellow]⚠ Campaign completed with warnings: {result.get('message')}[/yellow]"
                )
        except TimeoutError:
            success = False
            result = {"success": False, "message": f"Campaign timed out after {timeout} seconds."}
            tagger.emit_lifecycle("campaign_timeout", campaign_id, {"campaign": name})
            console.print(f"[red]✗ {result['message']}[/red]")
        finally:
            if timeout > 0:
                signal.alarm(0)

        # Log to SIEM, tagged with the run's correlation id.
        for technique in cfg["techniques"]:
            tagger.tag_and_emit(technique, result, campaign_id)

    except Exception as exc:
        success = False
        console.print(f"[red]✗ Campaign failed: {exc}[/red]")
        logger.log_error(name, str(exc))
    finally:
        duration = time.monotonic() - start
        # campaign_end feeds the campaigns-completed count + the kill-chain
        # narrative. Emitted in finally so a crashed stage is still scored.
        tagger.emit_lifecycle(
            "campaign_end",
            campaign_id,
            {"campaign": name, "success": success, "duration_seconds": round(duration, 3)},
        )
        logger.log_campaign_end(name, success, duration)


def _run_full_killchain(target_override=None):
    """Run all campaigns in kill-chain order.

    Ordered by MITRE tactic so the narrative reads recon -> initial-access ->
    credential-access -> privesc -> lateral -> exfil -> impact -> persistence.
    Keep this list aligned with CAMPAIGNS["full-killchain"]["techniques"].
    """
    kill_chain = [
        "recon",
        "phishing",
        "initial-access",
        "malware-drop",
        "brute-force",
        "mitm",
        "privesc",
        "privesc-suid",
        "lateral",
        "lateral-ssh",
        "exfil",
        "exfil-https",
        "ransomware",
        "persistence",
        "persistence-sshkey",
    ]
    console.print("[bold red]⚡ Starting Full Kill Chain[/bold red]\n")

    for i, campaign_name in enumerate(kill_chain, 1):
        cfg = CAMPAIGNS[campaign_name]
        console.print(f"[cyan]Step {i}/{len(kill_chain)}: {campaign_name.upper()}[/cyan]")
        _run_single_campaign(campaign_name, cfg, target_override)
        time.sleep(2)  # Brief pause between stages

    console.print("\n[bold red]💀 Full kill chain complete.[/bold red]")


def cleanup_all():
    """
    OQ-1 (ADR 0001): roll back any persistent state every campaign may have
    left on disk (planted SSH keys, cron entries, beacon scripts, etc.).
    Idempotent — safe to run more than once. Intended to be invoked from the
    IR playbook engine OR by hand before `docker compose down`.
    """
    import importlib

    print_banner()
    console.print(
        "[bold yellow]Running --cleanup-all over every disk-touching campaign...[/bold yellow]\n"
    )
    for name, cfg in CAMPAIGNS.items():
        if not cfg.get("module"):
            continue
        try:
            module = importlib.import_module(cfg["module"])
            klass = getattr(module, cfg["class"])
            # cleanup() is safe to call on a freshly-constructed instance —
            # it operates on well-known paths (beacon scripts, authorized_keys
            # files) rather than instance state from a prior run().
            target = os.environ.get("TARGET_WEB", "http://victim-web")
            inst = klass(target=target, logger=logger, tagger=tagger)
            # Pre-register the well-known paths that each disk-touching
            # campaign uses, so cleanup works without a preceding run().
            for path in getattr(klass, "WELL_KNOWN_ARTIFACTS", ()):
                inst.register_cleanup_path(path)
            result = inst.cleanup()
            removed = len(result.get("removed", []))
            errors = len(result.get("errors", []))
            color = "green" if errors == 0 else "yellow"
            console.print(
                f"  [{color}]{name:<16}[/{color}] "
                f"technique={result.get('technique', '?'):<10} "
                f"removed={removed} errors={errors}"
            )
            if errors:
                for e in result["errors"]:
                    console.print(f"      [red]! {e}[/red]")
        except Exception as exc:
            console.print(f"  [red]{name:<16} cleanup failed: {exc}[/red]")
    console.print("\n[bold green]Cleanup complete.[/bold green]")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--list", "show_list", is_flag=True, help="List available campaigns and exit.")
@click.option("--campaign", "-c", default=None, help="Campaign name to run (e.g. phishing, recon).")
@click.option(
    "--technique", "-t", default=None, help="MITRE ATT&CK technique ID (e.g., T1566.001)."
)
@click.option("--target", default=None, help="Override target IP/hostname.")
@click.option("--dry-run", is_flag=True, help="Simulate campaign without executing actions.")
@click.option(
    "--cleanup-all",
    "do_cleanup",
    is_flag=True,
    help="OQ-1: roll back persistent state left by any campaign and exit.",
)
@click.option("--force", is_flag=True, help="P10: Force execution of impact campaigns or full-killchain.")
def main(show_list, campaign, technique, target, dry_run, do_cleanup, force):
    """Adversary-in-a-Box red team campaign launcher."""
    if do_cleanup:
        cleanup_all()
        return
    if show_list:
        list_campaigns()
        return
    run_campaign(campaign, technique, target, dry_run, force)


if __name__ == "__main__":
    main()
