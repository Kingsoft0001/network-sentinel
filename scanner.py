import psutil
from typing import List, Dict, Any, Optional
from geoip import GeoIPResolver

class NetworkScanner:
    """Scans and parses all active network sockets on the host system."""

    def __init__(self, geoip_resolver: GeoIPResolver):
        self.geoip = geoip_resolver
        self._proc_cache = {}

    def get_process_name(self, pid: Optional[int]) -> str:
        if pid is None or pid == 0:
            return "System"
        if pid in self._proc_cache:
            return self._proc_cache[pid]
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            self._proc_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return f"PID {pid}"

    def scan_connections(self) -> List[Dict[str, Any]]:
        """Returns a snapshot of all active network connections."""
        results = []
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return []

        for conn in connections:
            laddr = conn.laddr
            raddr = conn.raddr
            status = conn.status
            pid = conn.pid
            proto = "TCP" if conn.type == 1 else "UDP"

            local_ip = laddr.ip if laddr else "0.0.0.0"
            local_port = laddr.port if laddr else 0
            remote_ip = raddr.ip if raddr else ""
            remote_port = raddr.port if raddr else 0

            proc_name = self.get_process_name(pid)
            geo_info = self.geoip.get_info(remote_ip) if remote_ip else {"country": "-", "city": "-", "isp": "-", "is_local": True}

            # Classify connection type
            if status == "LISTEN":
                conn_type = "LISTENING"
            elif not remote_ip:
                conn_type = "IDLE"
            elif geo_info.get("is_local"):
                conn_type = "LOCAL / LAN"
            else:
                conn_type = "REMOTE / WAN"

            results.append({
                "proto": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": status,
                "pid": pid or 0,
                "process_name": proc_name,
                "conn_type": conn_type,
                "geo": geo_info
            })

        return results
