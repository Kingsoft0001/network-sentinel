import json
import os
import threading
import requests
from typing import Dict, Any, Optional

ALERTS_LOG = os.path.join(os.path.dirname(__file__), "intrusion_alerts.log")

SEVERITY_COLORS = {
    "CRITICAL": 0xFF0000, # Red
    "HIGH": 0xFF4500,     # Orange-Red
    "MEDIUM": 0xFFA500,   # Orange
    "LOW": 0x00FF00,      # Green
    "INFO": 0x3498DB      # Blue
}

class AlertManager:
    """Dispatches intrusion and security alerts to Discord Webhook and local log file."""

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url

    def set_webhook(self, webhook_url: str):
        self.webhook_url = webhook_url.strip() if webhook_url else None

    def log_locally(self, alert_data: Dict[str, Any]):
        try:
            with open(ALERTS_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_data) + "\n")
        except Exception:
            pass

    def send_discord_alert(self, alert_data: Dict[str, Any], auto_blocked: bool = False):
        self.log_locally(alert_data)

        if not self.webhook_url:
            return

        def _send():
            try:
                severity = alert_data.get("severity", "MEDIUM")
                color = SEVERITY_COLORS.get(severity, 0xFFA500)
                ip = alert_data.get("remote_ip", "Unknown")
                geo = alert_data.get("geo", {})
                country = geo.get("country", "Unknown")
                city = geo.get("city", "Unknown")
                isp = geo.get("isp", "Unknown")
                reasons = "\n".join([f"• {r}" for r in alert_data.get("reasons", [])])

                action_text = "🚫 **AUTO-BLOCKED in Windows Firewall**" if auto_blocked else "⚠️ Monitored (Action Required)"

                embed = {
                    "title": f"🚨 [NetSentinel] Intrusion Threat Detected! [{severity}]",
                    "description": f"An unsolicited or suspicious connection attempt was intercepted.\n\n**Reasons:**\n{reasons}",
                    "color": color,
                    "fields": [
                        {"name": "Remote Attacker IP", "value": f"`{ip}`", "inline": True},
                        {"name": "Origin / Location", "value": f"🌍 {city}, {country}", "inline": True},
                        {"name": "ISP / Host", "value": f"🏢 {isp}", "inline": False},
                        {"name": "Target Local Port", "value": f"`{alert_data.get('local_port')}`", "inline": True},
                        {"name": "Target Process", "value": f"`{alert_data.get('process_name', 'Unknown')}`", "inline": True},
                        {"name": "Status", "value": f"`{alert_data.get('status')}`", "inline": True},
                        {"name": "Action Taken", "value": action_text, "inline": False}
                    ],
                    "footer": {"text": f"NetSentinel Host IDS • {alert_data.get('timestamp')}"}
                }

                payload = {
                    "username": "NetSentinel Security",
                    "embeds": [embed]
                }

                requests.post(self.webhook_url, json=payload, timeout=5)
            except Exception:
                pass

        threading.Thread(target=_send, daemon=True).start()
