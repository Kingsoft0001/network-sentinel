import ctypes
import os
import subprocess
from typing import List, Dict

RULE_PREFIX = "NetSentinel_Block_"

class FirewallManager:
    """Manages Windows Firewall rules for blocking/unblocking suspicious IP addresses."""

    @staticmethod
    def is_admin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @classmethod
    def block_ip(cls, ip: str) -> bool:
        """Blocks inbound and outbound traffic for the given IP address in Windows Firewall."""
        if not cls.is_admin():
            return False

        # Inbound block
        rule_name = f"{RULE_PREFIX}{ip}"
        # Delete any existing rule with same name first
        cls.unblock_ip(ip)

        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip} description="Blocked by NetSentinel IDS"'
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip} description="Blocked by NetSentinel IDS"'

        try:
            subprocess.run(cmd_in, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            subprocess.run(cmd_out, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
        except Exception:
            return False

    @classmethod
    def unblock_ip(cls, ip: str) -> bool:
        """Removes NetSentinel firewall block rules for the specified IP."""
        if not cls.is_admin():
            return False

        rule_name = f"{RULE_PREFIX}{ip}"
        cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name}_IN"'
        cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'

        try:
            subprocess.run(cmd_in, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(cmd_out, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    @classmethod
    def list_blocked_ips(cls) -> List[str]:
        """Lists all IPs currently blocked by NetSentinel."""
        cmd = f'netsh advfirewall firewall show rule name=all | findstr /i "{RULE_PREFIX}"'
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            lines = res.stdout.splitlines()
            blocked_ips = set()
            for line in lines:
                if "Rule Name:" in line or "Regelname:" in line or RULE_PREFIX in line:
                    parts = line.split(RULE_PREFIX)
                    if len(parts) > 1:
                        ip_part = parts[1].split("_")[0].strip()
                        if ip_part:
                            blocked_ips.add(ip_part)
            return sorted(list(blocked_ips))
        except Exception:
            return []

    @classmethod
    def unblock_all(cls) -> int:
        """Removes all NetSentinel rules."""
        blocked = cls.list_blocked_ips()
        count = 0
        for ip in blocked:
            if cls.unblock_ip(ip):
                count += 1
        return count
