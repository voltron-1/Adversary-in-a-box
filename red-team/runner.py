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

import os
import sys
import time
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from utils.logger import AttackLogger
from utils.mitre_tagger import MitreTagger

# Campaign registry — maps names to module paths
CAMPAIGNS = {
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
    "privesc": {
        "module": "campaigns.privilege_escalation.sudo_abuse",
        "class": "SudoAbuseCampaign",
        "techniques": ["T1548.003", "T1548.001"],
        "description": "Privilege escalation via sudo misconfiguration + SUID abuse",
        "domain": 1,
    },
    "lateral": {
        "module": "campaigns.lateral_movement.pass_the_hash",
        "class": "PassTheHashCampaign",
        "techniques": ["T1550.002", "T1563.001"],
        "description": "Lateral movement via Pass-the-Hash + SSH hijacking",
        "domain": 2,
    },
    "exfil": {
        "module": "campaigns.exfiltration.dns_tunnel",
        "class": "DnsTunnelCampaign",
        "techniques": ["T1048.003", "T1041"],
        "description": "Data exfiltration over DNS tunnel + HTTPS C2 channel",
        "domain": 1,
    },
    "persistence": {
        "module": "campaigns.persistence.cron_backdoor",
        "class": "CronBackdoorCampaign",
        "techniques": ["T1053.003", "T1098.004"],
        "description": "Persistence via cron backdoor + SSH authorized keys",
        "domain": 1,
    },
    "full-killchain": {
        "module": None,  # Runs all campaigns in sequence
        "class": None,
        "techniques": ["T1595", "T1566.001", "T1190", "T1548.003", "T1550.002", "T1048.003", "T1053.003"],
        "description": "Full kill chain: recon → initial access → privesc → lateral → exfil → persist",
        "domain": "1-2-3",
    },
}

# Technique-to-campaign mapping
TECHNIQUE_MAP = {tech: name for name, cfg in CAMPAIGNS.items() for tech in cfg["techniques"]}

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


@click.group()
def cli():
    """Adversary-in-a-Box Red Team Campaign Launcher"""
    pass


@cli.command("list")
def list_campaigns():
    """List all available campaigns and techniques."""
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


@cli.command("run")
@click.option("--campaign", "-c", default=None, help="Campaign name to run")
@click.option("--technique", "-t", default=None, help="MITRE ATT&CK technique ID (e.g., T1566.001)")
@click.option("--target", default=None, help="Override target IP/hostname")
@click.option("--dry-run", is_flag=True, help="Simulate campaign without executing")
def run_campaign(campaign, technique, target, dry_run):
    """Run a red team campaign or specific MITRE technique."""
    print_banner()

    # Resolve technique to campaign name
    if technique and not campaign:
        campaign = TECHNIQUE_MAP.get(technique)
        if not campaign:
            console.print(f"[red]Unknown technique: {technique}[/red]")
            sys.exit(1)

    if not campaign:
        console.print("[red]Error: specify --campaign or --technique[/red]")
        sys.exit(1)

    if campaign not in CAMPAIGNS:
        console.print(f"[red]Unknown campaign: {campaign}. Run 'runner.py list' to see options.[/red]")
        sys.exit(1)

    cfg = CAMPAIGNS[campaign]
    console.print(f"\n[bold red]🔴 Launching campaign:[/bold red] [cyan]{campaign}[/cyan]")
    console.print(f"[dim]Techniques: {', '.join(cfg['techniques'])}[/dim]")
    console.print(f"[dim]Description: {cfg['description']}[/dim]\n")

    if dry_run:
        console.print("[yellow]DRY RUN — no actions will be executed[/yellow]")
        return

    if campaign == "full-killchain":
        _run_full_killchain(target)
        return

    _run_single_campaign(campaign, cfg, target)


def _run_single_campaign(name, cfg, target_override=None):
    """Dynamically import and execute a single campaign module."""
    import importlib
    try:
        module = importlib.import_module(cfg["module"])
        klass = getattr(module, cfg["class"])
        target = target_override or os.environ.get("TARGET_WEB", "http://172.20.0.30")
        instance = klass(target=target, logger=logger, tagger=tagger)

        console.print(f"[green]▶ Executing {cfg['class']}...[/green]")
        result = instance.run()

        if result.get("success"):
            console.print(f"[bold green]✓ Campaign completed successfully[/bold green]")
        else:
            console.print(f"[yellow]⚠ Campaign completed with warnings: {result.get('message')}[/yellow]")

        # Log to SIEM
        for technique in cfg["techniques"]:
            tagger.tag_and_emit(technique, result)

    except Exception as exc:
        console.print(f"[red]✗ Campaign failed: {exc}[/red]")
        logger.log_error(name, str(exc))


def _run_full_killchain(target_override=None):
    """Run all campaigns in kill-chain order."""
    kill_chain = ["recon", "phishing", "initial-access", "privesc", "lateral", "exfil", "persistence"]
    console.print("[bold red]⚡ Starting Full Kill Chain[/bold red]\n")

    for i, campaign_name in enumerate(kill_chain, 1):
        cfg = CAMPAIGNS[campaign_name]
        console.print(f"[cyan]Step {i}/{len(kill_chain)}: {campaign_name.upper()}[/cyan]")
        _run_single_campaign(campaign_name, cfg, target_override)
        time.sleep(2)  # Brief pause between stages

    console.print("\n[bold red]💀 Full kill chain complete.[/bold red]")


# Support `python runner.py --campaign X` syntax (not just subcommand)
@click.command()
@click.option("--list", "show_list", is_flag=True, help="List campaigns")
@click.option("--campaign", "-c", default=None)
@click.option("--technique", "-t", default=None)
@click.option("--target", default=None)
@click.option("--dry-run", is_flag=True)
def main(show_list, campaign, technique, target, dry_run):
    if show_list:
        list_campaigns.invoke(click.Context(list_campaigns))
    else:
        ctx = click.Context(run_campaign)
        ctx.invoke(run_campaign, campaign=campaign, technique=technique, target=target, dry_run=dry_run)


if __name__ == "__main__":
    main()
