import argparse
import os
import sys
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box

from geoip import GeoIPResolver
from scanner import NetworkScanner
from threat import ThreatDetector
from firewall import FirewallManager
from alerts import AlertManager

console = Console()

def generate_layout(
    connections,
    alerts,
    stats,
    is_admin: bool,
    auto_block: bool,
    filter_query: str = "",
    webhook_active: bool = False
) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="stats", size=3),
        Layout(name="main", ratio=1),
        Layout(name="alerts", size=8)
    )

    # 1. Header
    admin_tag = "[bold green][ADMIN: ACTIVE][/bold green]" if is_admin else "[bold red][ADMIN: NO - Run as Admin to Enable Firewall Block][/bold red]"
    autoblock_tag = "[bold green][AUTO-BLOCK: ON][/bold green]" if auto_block else "[yellow][AUTO-BLOCK: OFF][/yellow]"
    webhook_tag = "[bold cyan][DISCORD: CONNECTED][/bold cyan]" if webhook_active else "[dim][DISCORD: NONE][/dim]"
    
    header_text = Text.from_markup(
        f"🛡️  [bold white]NetSentinel[/bold white] • [cyan]Host Network Traffic & Intrusion Monitor[/cyan]  |  {admin_tag}  {autoblock_tag}  {webhook_tag}"
    )
    layout["header"].update(Panel(header_text, style="bold blue", box=box.ROUNDED))

    # 2. Stats
    stat_msg = (
        f"[bold white]Total Active:[/bold white] [cyan]{stats['total']}[/cyan]  |  "
        f"[bold white]Established (WAN):[/bold white] [green]{stats['remote_established']}[/green]  |  "
        f"[bold white]Listening Ports:[/bold white] [yellow]{stats['listening']}[/yellow]  |  "
        f"[bold white]Firewall Blocked IPs:[/bold white] [red]{stats['blocked_count']}[/red]  |  "
        f"[bold white]Intrusion Threats:[/bold white] [bold red]{stats['threats_count']}[/bold red]"
    )
    layout["stats"].update(Panel(Text.from_markup(stat_msg), style="cyan", box=box.ROUNDED))

    # 3. Main Connection Table
    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_lines=False)
    table.add_column("PID", style="dim", width=7)
    table.add_column("Process", style="bold cyan", width=18)
    table.add_column("Proto", width=6)
    table.add_column("Local Port", width=11)
    table.add_column("Remote IP", style="bold white", width=18)
    table.add_column("Remote Port", width=12)
    table.add_column("Status", width=14)
    table.add_column("Location", style="green", width=18)
    table.add_column("ISP / Organization", style="magenta")

    # Apply filter if specified
    filtered = []
    for c in connections:
        if filter_query:
            q = filter_query.lower()
            if (
                q not in c["process_name"].lower()
                and q not in c["remote_ip"].lower()
                and q not in str(c["local_port"])
                and q not in str(c["remote_port"])
            ):
                continue
        filtered.append(c)

    # Sort so established remote connections and listening sockets appear prominent
    filtered.sort(key=lambda x: (x["conn_type"] == "REMOTE / WAN", x["status"] == "ESTABLISHED"), reverse=True)

    for c in filtered[:25]:  # Display top 25 active connections
        r_ip = c["remote_ip"] or "-"
        geo = c["geo"]
        loc_str = f"{geo.get('country', '-')}"
        if geo.get("city") and geo.get("city") != "Unknown" and geo.get("city") != "-":
            loc_str = f"{geo.get('city')}, {loc_str}"
        isp_str = geo.get("isp", "-")

        # Colorize status
        status_styled = c["status"]
        if c["status"] == "ESTABLISHED":
            status_styled = f"[bold green]{c['status']}[/bold green]"
        elif c["status"] == "LISTEN":
            status_styled = f"[yellow]{c['status']}[/yellow]"
        elif "WAIT" in c["status"]:
            status_styled = f"[dim]{c['status']}[/dim]"

        table.add_row(
            str(c["pid"]),
            c["process_name"][:18],
            c["proto"],
            f":{c['local_port']}",
            r_ip,
            str(c["remote_port"]) if c["remote_port"] else "-",
            status_styled,
            loc_str[:18],
            isp_str[:30]
        )

    layout["main"].update(Panel(table, title="[bold white]📡 Live Network Connections[/bold white]", box=box.ROUNDED))

    # 4. Threats & Alerts Panel
    alerts_table = Table(box=box.SIMPLE, expand=True, show_header=True)
    alerts_table.add_column("Time", width=10, style="dim")
    alerts_table.add_column("Severity", width=10)
    alerts_table.add_column("Attacker IP", width=17, style="bold red")
    alerts_table.add_column("Port", width=8)
    alerts_table.add_column("Target App", width=14)
    alerts_table.add_column("Reason / Activity", style="yellow")

    if not alerts:
        alerts_table.add_row("-", "[green]SECURE[/green]", "-", "-", "-", "No active threats detected. System traffic is normal.")
    else:
        for a in alerts[-5:]:
            sev = a.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                sev_styled = "[bold red]CRITICAL[/bold red]"
            elif sev == "HIGH":
                sev_styled = "[red]HIGH[/red]"
            else:
                sev_styled = "[yellow]MEDIUM[/yellow]"

            reasons = "; ".join(a.get("reasons", []))
            time_short = a.get("timestamp", "").split(" ")[-1]
            alerts_table.add_row(
                time_short,
                sev_styled,
                a.get("remote_ip", "-"),
                str(a.get("local_port", "-")),
                a.get("process_name", "-")[:14],
                reasons[:60]
            )

    layout["alerts"].update(Panel(alerts_table, title="[bold red]🚨 Intrusion Detection Log (IDS)[/bold red]", box=box.ROUNDED))

    return layout


import json

def load_config():
    config = {"auto_block": False, "webhook": "", "filter": ""}
    if os.path.exists("config.json"):
        try:
            with open("config.json", "r") as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception:
            pass
    return config

def main():

    parser = argparse.ArgumentParser(description="NetSentinel - Windows Network Monitor & Intrusion Blocker")
    parser.add_argument("--auto-block", action="store_true", help="Automatically block detected threats in Windows Firewall")
    parser.add_argument("--webhook", type=str, default="", help="Discord Webhook URL for intrusion notifications")
    parser.add_argument("--filter", type=str, default="", help="Filter connections by process name or IP")
    parser.add_argument("--block", type=str, help="Manually block a specific IP in Windows Firewall and exit")
    parser.add_argument("--unblock", type=str, help="Unblock a specific IP in Windows Firewall and exit")
    parser.add_argument("--unblock-all", action="store_true", help="Remove all NetSentinel firewall rules and exit")
    parser.add_argument("--list-blocked", action="store_true", help="List all IPs currently blocked by NetSentinel and exit")
    parser.add_argument("--once", action="store_true", help="Output a single snapshot table and exit")
    args = parser.parse_args()

    config = load_config()
    auto_block = args.auto_block or config.get('auto_block', False)
    webhook = args.webhook if args.webhook else config.get('webhook', '')
    filter_query = args.filter if args.filter else config.get('filter', '')


    # Handle manual CLI firewall actions
    if args.block:
        if not FirewallManager.is_admin():
            console.print("[bold red]❌ Error: Administrator privileges required to modify firewall rules. Please run PowerShell/CMD as Admin.[/bold red]")
            sys.exit(1)
        if FirewallManager.block_ip(args.block):
            console.print(f"[bold green]✅ Successfully blocked IP {args.block} in Windows Firewall (Inbound & Outbound).[/bold green]")
        else:
            console.print(f"[bold red]❌ Failed to block IP {args.block}.[/bold red]")
        return

    if args.unblock:
        if not FirewallManager.is_admin():
            console.print("[bold red]❌ Error: Administrator privileges required.[/bold red]")
            sys.exit(1)
        if FirewallManager.unblock_ip(args.unblock):
            console.print(f"[bold green]✅ Successfully unblocked IP {args.unblock}.[/bold green]")
        else:
            console.print(f"[bold red]❌ Failed to unblock IP {args.unblock}.[/bold red]")
        return

    if args.unblock_all:
        if not FirewallManager.is_admin():
            console.print("[bold red]❌ Error: Administrator privileges required.[/bold red]")
            sys.exit(1)
        count = FirewallManager.unblock_all()
        console.print(f"[bold green]✅ Successfully removed {count} NetSentinel firewall rules.[/bold green]")
        return

    if args.list_blocked:
        blocked = FirewallManager.list_blocked_ips()
        if not blocked:
            console.print("[yellow]No IPs currently blocked by NetSentinel.[/yellow]")
        else:
            console.print("[bold red]Blocked IPs in Windows Firewall:[/bold red]")
            for ip in blocked:
                console.print(f"  • {ip}")
        return

    # Initialize Core Components
    is_admin = FirewallManager.is_admin()
    geoip = GeoIPResolver()
    scanner = NetworkScanner(geoip)
    threat_engine = ThreatDetector()
    alerter = AlertManager(webhook if webhook else None)

    # Initial quick scan for one-time mode
    if args.once:
        connections = scanner.scan_connections()
        table = Table(title="NetSentinel Network Snapshot", box=box.ROUNDED)
        table.add_column("PID")
        table.add_column("Process")
        table.add_column("Proto")
        table.add_column("Local Port")
        table.add_column("Remote IP")
        table.add_column("Status")
        table.add_column("Location")
        table.add_column("ISP")

        for c in connections[:30]:
            r_ip = c["remote_ip"] or "-"
            geo = c["geo"]
            loc = f"{geo.get('city', '')} {geo.get('country', '-')}".strip()
            table.add_row(
                str(c["pid"]),
                c["process_name"],
                c["proto"],
                str(c["local_port"]),
                r_ip,
                c["status"],
                loc,
                geo.get("isp", "-")
            )
        console.print(table)
        return

    # Live Dashboard Mode
    console.clear()
    with Live(console=console, screen=True, auto_refresh=False) as live:
        try:
            while True:
                connections = scanner.scan_connections()
                blocked_ips = FirewallManager.list_blocked_ips() if is_admin else []

                stats = {
                    "total": len(connections),
                    "remote_established": sum(1 for c in connections if c["conn_type"] == "REMOTE / WAN" and c["status"] == "ESTABLISHED"),
                    "listening": sum(1 for c in connections if c["status"] == "LISTEN"),
                    "blocked_count": len(blocked_ips),
                    "threats_count": len(threat_engine.get_recent_alerts(100))
                }

                # Evaluate active connections for threats
                for c in connections:
                    if c["remote_ip"] and c["conn_type"] == "REMOTE / WAN":
                        threat = threat_engine.evaluate_connection(
                            remote_ip=c["remote_ip"],
                            remote_port=c["remote_port"],
                            local_port=c["local_port"],
                            status=c["status"],
                            process_name=c["process_name"],
                            is_local=c["geo"].get("is_local", False),
                            geo_info=c["geo"]
                        )
                        if threat:
                            auto_blocked = False
                            if auto_block and is_admin:
                                if threat.get("severity") in ("CRITICAL", "HIGH"):
                                    FirewallManager.block_ip(threat["remote_ip"])
                                    auto_blocked = True
                            alerter.send_discord_alert(threat, auto_blocked=auto_blocked)

                layout = generate_layout(
                    connections=connections,
                    alerts=threat_engine.get_recent_alerts(10),
                    stats=stats,
                    is_admin=is_admin,
                    auto_block=auto_block,
                    filter_query=filter_query,
                    webhook_active=bool(webhook)
                )

                live.update(layout, refresh=True)
                time.sleep(1.5)

        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
