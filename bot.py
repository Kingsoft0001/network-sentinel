import os
import sys
import asyncio
import discord
from discord.ext import commands, tasks
from discord import app_commands
from dotenv import load_dotenv

from geoip import GeoIPResolver
from scanner import NetworkScanner
from threat import ThreatDetector
from firewall import FirewallManager

# Load environment variables
load_dotenv()

TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
CHANNEL_ID_STR = os.getenv("DISCORD_CHANNEL_ID", "").strip()
ALERT_CHANNEL_ID = int(CHANNEL_ID_STR) if CHANNEL_ID_STR.isdigit() else None
AUTO_BLOCK = os.getenv("AUTO_BLOCK", "false").lower() in ("true", "1", "yes")
ADMIN_USER_IDS = [int(x.strip()) for x in os.getenv("ADMIN_USER_IDS", "").split(",") if x.strip().isdigit()]

# Initialize Core IDS Engines
geoip = GeoIPResolver()
scanner = NetworkScanner(geoip)
threat_engine = ThreatDetector()
is_admin = FirewallManager.is_admin()

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

def is_authorized(interaction_or_ctx) -> bool:
    """Checks if the invoking user is authorized to perform security actions."""
    user_id = interaction_or_ctx.user.id if hasattr(interaction_or_ctx, "user") else interaction_or_ctx.author.id
    if not ADMIN_USER_IDS:
        return True # Default to allowed if no admin IDs configured
    return user_id in ADMIN_USER_IDS

# Interactive Discord UI Button View for Threat Alerts
class ThreatAlertView(discord.ui.View):
    def __init__(self, remote_ip: str):
        super().__init__(timeout=None)
        self.remote_ip = remote_ip

    @discord.ui.button(label="🚫 Block in Firewall", style=discord.ButtonStyle.danger, custom_id="btn_block_ip")
    async def block_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not is_authorized(interaction):
            await interaction.response.send_message("❌ Unauthorized: You do not have permission to execute firewall commands.", ephemeral=True)
            return

        if not is_admin:
            await interaction.response.send_message("⚠️ Host Error: NetSentinel is not running with Administrator privileges on Windows.", ephemeral=True)
            return

        success = FirewallManager.block_ip(self.remote_ip)
        if success:
            button.label = "✅ Blocked in Firewall"
            button.style = discord.ButtonStyle.secondary
            button.disabled = True
            await interaction.response.edit_message(view=self)
            await interaction.followup.send(f"🛡️ **Firewall Rule Added:** `{self.remote_ip}` has been blocked on the host system.", ephemeral=False)
        else:
            await interaction.response.send_message(f"❌ Failed to block `{self.remote_ip}` in Windows Firewall.", ephemeral=True)

    @discord.ui.button(label="🔍 IP Lookup Info", style=discord.ButtonStyle.primary, custom_id="btn_lookup_ip")
    async def lookup_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        info = geoip.get_info(self.remote_ip)
        embed = discord.Embed(title=f"🔎 Threat Intel: {self.remote_ip}", color=0x3498DB)
        embed.add_field(name="Country", value=info.get("country", "Unknown"), inline=True)
        embed.add_field(name="City / Region", value=f"{info.get('city', 'Unknown')} ({info.get('region', '')})", inline=True)
        embed.add_field(name="ISP / Host", value=info.get("isp", "Unknown"), inline=False)
        embed.add_field(name="ASN", value=info.get("as", "N/A"), inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.event
async def on_ready():
    print(f"==================================================")
    print(f"🛡️  NetSentinel Discord Bot Online as {bot.user}")
    print(f"Host Admin Status: {'ACTIVE' if is_admin else 'NO ADMIN PRIVILEGES'}")
    print(f"Auto-Block Mode:   {'ENABLED' if AUTO_BLOCK else 'DISABLED'}")
    print(f"==================================================")

    # Sync Slash Commands with Discord
    try:
        synced = await bot.tree.sync()
        print(f"✅ Synced {len(synced)} Slash Commands.")
    except Exception as e:
        print(f"Failed to sync slash commands: {e}")

    # Start live background intrusion monitoring loop
    if not monitor_traffic_task.is_running():
        monitor_traffic_task.start()

# Background IDS Loop
@tasks.loop(seconds=3.0)
async def monitor_traffic_task():
    try:
        connections = scanner.scan_connections()
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
                    if AUTO_BLOCK and is_admin:
                        if threat.get("severity") in ("CRITICAL", "HIGH"):
                            FirewallManager.block_ip(threat["remote_ip"])
                            auto_blocked = True

                    # Dispatch alert to Discord Channel
                    if ALERT_CHANNEL_ID:
                        channel = bot.get_channel(ALERT_CHANNEL_ID)
                        if channel:
                            sev = threat.get("severity", "HIGH")
                            color = 0xFF0000 if sev == "CRITICAL" else (0xFF4500 if sev == "HIGH" else 0xFFA500)
                            ip = threat.get("remote_ip")
                            geo = threat.get("geo", {})
                            reasons = "\n".join([f"• {r}" for r in threat.get("reasons", [])])

                            embed = discord.Embed(
                                title=f"🚨 Intrusion Threat Intercepted [{sev}]",
                                description=f"An unauthorized or suspicious connection was detected on your host PC.\n\n**Reasons:**\n{reasons}",
                                color=color
                            )
                            embed.add_field(name="Attacker IP", value=f"`{ip}`", inline=True)
                            embed.add_field(name="Location", value=f"🌍 {geo.get('city', '')}, {geo.get('country', 'Unknown')}", inline=True)
                            embed.add_field(name="ISP / Provider", value=f"🏢 {geo.get('isp', 'Unknown')}", inline=False)
                            embed.add_field(name="Target Port", value=f"`{threat.get('local_port')}`", inline=True)
                            embed.add_field(name="Target Process", value=f"`{threat.get('process_name')}`", inline=True)
                            embed.add_field(name="Status", value=f"`{threat.get('status')}`", inline=True)

                            if auto_blocked:
                                embed.add_field(name="Action Taken", value="🚫 **AUTO-BLOCKED in Windows Firewall**", inline=False)
                                view = None
                            else:
                                embed.add_field(name="Action Taken", value="⚠️ Monitored (Awaiting manual response)", inline=False)
                                view = ThreatAlertView(remote_ip=ip)

                            await channel.send(embed=embed, view=view)

    except Exception as e:
        print(f"Error in IDS loop: {e}")

# ==================== SLASH COMMANDS ====================

@bot.tree.command(name="status", description="Get live host security status and active network summary.")
async def cmd_status(interaction: discord.Interaction):
    connections = scanner.scan_connections()
    blocked = FirewallManager.list_blocked_ips() if is_admin else []
    threats = threat_engine.get_recent_alerts(100)

    established = sum(1 for c in connections if c["conn_type"] == "REMOTE / WAN" and c["status"] == "ESTABLISHED")
    listening = sum(1 for c in connections if c["status"] == "LISTEN")

    embed = discord.Embed(title="🛡️ NetSentinel Host Status", color=0x2ECC71)
    embed.add_field(name="Windows Admin Rights", value="✅ Active" if is_admin else "❌ No Admin", inline=True)
    embed.add_field(name="Auto-Block Mode", value="🟢 Enabled" if AUTO_BLOCK else "⚪ Disabled", inline=True)
    embed.add_field(name="Total Sockets", value=f"`{len(connections)}`", inline=True)
    embed.add_field(name="Established WAN Connections", value=f"`{established}`", inline=True)
    embed.add_field(name="Open Listening Ports", value=f"`{listening}`", inline=True)
    embed.add_field(name="Firewall Blocked IPs", value=f"`{len(blocked)}`", inline=True)
    embed.add_field(name="Total Threats Flagged", value=f"`{len(threats)}`", inline=True)
    embed.set_footer(text="NetSentinel Real-time Host IDS")

    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="connections", description="List top active outbound and inbound network connections.")
async def cmd_connections(interaction: discord.Interaction):
    connections = scanner.scan_connections()
    remote_conns = [c for c in connections if c["conn_type"] == "REMOTE / WAN" and c["remote_ip"]]

    if not remote_conns:
        await interaction.response.send_message("ℹ️ No active external network connections found right now.")
        return

    embed = discord.Embed(title="📡 Active External Connections (Top 10)", color=0x3498DB)
    for c in remote_conns[:10]:
        geo = c["geo"]
        loc = f"{geo.get('city', '')} {geo.get('country', '')}".strip() or "Unknown"
        field_val = (
            f"**Remote IP:** `{c['remote_ip']}:{c['remote_port']}`\n"
            f"**Local Port:** `{c['local_port']}` | **Status:** `{c['status']}`\n"
            f"**Location:** {loc} ({geo.get('isp', 'Unknown')})"
        )
        embed.add_field(name=f"⚙️ {c['process_name']} (PID: {c['pid']})", value=field_val, inline=False)

    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="threats", description="View recent intrusion and port scan detection logs.")
async def cmd_threats(interaction: discord.Interaction):
    threats = threat_engine.get_recent_alerts(5)
    if not threats:
        embed = discord.Embed(title="🛡️ Intrusion Detection Log", description="✅ No intrusion threats recorded. Host is clean.", color=0x2ECC71)
        await interaction.response.send_message(embed=embed)
        return

    embed = discord.Embed(title="🚨 Recent Intercepted Threats", color=0xE74C3C)
    for t in threats:
        reasons = "; ".join(t.get("reasons", []))
        embed.add_field(
            name=f"[{t.get('severity')}] {t.get('remote_ip')} ➜ Port {t.get('local_port')}",
            value=f"**Time:** `{t.get('timestamp')}`\n**App:** `{t.get('process_name')}`\n**Reason:** {reasons}",
            inline=False
        )
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="block", description="Manually block an IP address in Windows Defender Firewall.")
@app_commands.describe(ip="The IPv4 or IPv6 address to block")
async def cmd_block(interaction: discord.Interaction, ip: str):
    if not is_authorized(interaction):
        await interaction.response.send_message("❌ Unauthorized.", ephemeral=True)
        return
    if not is_admin:
        await interaction.response.send_message("⚠️ Host Error: NetSentinel is not running as Administrator on Windows.", ephemeral=True)
        return

    if FirewallManager.block_ip(ip):
        await interaction.response.send_message(f"✅ Successfully added Windows Firewall rule blocking `{ip}` (Inbound & Outbound).")
    else:
        await interaction.response.send_message(f"❌ Failed to block `{ip}`.")

@bot.tree.command(name="unblock", description="Unblock an IP address from Windows Defender Firewall.")
@app_commands.describe(ip="The IP address to unblock")
async def cmd_unblock(interaction: discord.Interaction, ip: str):
    if not is_authorized(interaction):
        await interaction.response.send_message("❌ Unauthorized.", ephemeral=True)
        return
    if not is_admin:
        await interaction.response.send_message("⚠️ Host Error: NetSentinel is not running as Administrator on Windows.", ephemeral=True)
        return

    if FirewallManager.unblock_ip(ip):
        await interaction.response.send_message(f"✅ Successfully unblocked `{ip}` from Windows Firewall.")
    else:
        await interaction.response.send_message(f"❌ Failed to unblock `{ip}`.")

@bot.tree.command(name="blocked", description="List all IPs currently blocked by NetSentinel in Windows Firewall.")
async def cmd_blocked(interaction: discord.Interaction):
    if not is_admin:
        await interaction.response.send_message("⚠️ Run as Administrator to view firewall rules.", ephemeral=True)
        return

    blocked_list = FirewallManager.list_blocked_ips()
    if not blocked_list:
        await interaction.response.send_message("ℹ️ No IPs are currently blocked in Windows Firewall.")
        return

    ip_text = "\n".join([f"• `{ip}`" for ip in blocked_list])
    embed = discord.Embed(title="🚫 Blocked IPs in Windows Firewall", description=ip_text, color=0xE74C3C)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="lookup", description="Lookup GeoIP, ISP and location information for any IP address.")
@app_commands.describe(ip="The IP address to lookup")
async def cmd_lookup(interaction: discord.Interaction, ip: str):
    info = geoip.get_info(ip)
    embed = discord.Embed(title=f"🌍 GeoIP Intelligence: `{ip}`", color=0x9B59B6)
    embed.add_field(name="Country", value=info.get("country", "Unknown"), inline=True)
    embed.add_field(name="City", value=info.get("city", "Unknown"), inline=True)
    embed.add_field(name="ISP / Org", value=info.get("isp", "Unknown"), inline=False)
    await interaction.response.send_message(embed=embed)

def start_bot():
    if not TOKEN:
        print("❌ Error: DISCORD_BOT_TOKEN is not set in .env file.")
        print("Please edit .env and add your Discord Bot Token.")
        sys.exit(1)
    bot.run(TOKEN)

if __name__ == "__main__":
    start_bot()
