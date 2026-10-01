import time
import csv
import os
from ml_detector import MLAnomalyDetector
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Tuple

SENSITIVE_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Remote Shell)",
    23: "Telnet (Unencrypted Remote Access)",
    25: "SMTP (Mail Relay)",
    53: "DNS",
    80: "HTTP",
    135: "RPC Endpoint Mapper",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    445: "SMB (Direct Host / WannaCry target)",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL Database",
    3389: "RDP (Windows Remote Desktop)",
    5432: "PostgreSQL Database",
    5900: "VNC (Remote Desktop)",
    6379: "Redis (In-memory DB)",
    8080: "HTTP Alternate / Proxy",
    8443: "HTTPS Alternate",
    27017: "MongoDB",
}

class ThreatDetector:
    """Analyzes live connection patterns to detect intrusion attempts, port scans, and anomalies."""

    def __init__(self, export_csv: bool = True):
        # Maps remote_ip -> deque of (timestamp, local_port)
        self._ip_history = defaultdict(lambda: deque(maxlen=50))
        self._alert_history = []
        self.export_csv = export_csv
        self.csv_file = "threat_logs.csv"
        self.ml_engine = MLAnomalyDetector()
        
        if self.export_csv and not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Severity", "Remote_IP", "Local_Port", "Process", "Reasons", "Country", "ISP"])

    def _log_to_csv(self, alert):
        if not self.export_csv:
            return
        with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            geo = alert.get("geo", {})
            writer.writerow([
                alert["timestamp"],
                alert["severity"],
                alert["remote_ip"],
                alert["local_port"],
                alert["process_name"],
                "; ".join(alert["reasons"]),
                geo.get("country", "-"),
                geo.get("isp", "-")
            ])

    def evaluate_connection(
        self,
        remote_ip: str,
        remote_port: int,
        local_port: int,
        status: str,
        process_name: str,
        is_local: bool,
        geo_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates a connection for threat indicators.
        Returns a threat report dict if suspicious, else None.
        """
        if is_local or not remote_ip or remote_ip in ("0.0.0.0", "127.0.0.1", "::1"):
            return None

        now = time.time()
        self._ip_history[remote_ip].append((now, local_port))

        threat_score = 0
        reasons = []
        severity = "INFO"

        # --- AI / ML Anomaly Detection ---
        self.ml_engine.observe(remote_ip, local_port, status)
        is_anomaly, ml_msg = self.ml_engine.predict(remote_ip, local_port, status)
        if is_anomaly:
            threat_score += 45
            reasons.append(f"[AI Alert] {ml_msg}")
            
        # 1. Check if the connection is targeting a high-risk sensitive port
        if local_port in SENSITIVE_PORTS:
            service = SENSITIVE_PORTS[local_port]
            if status in ("SYN_RECV", "LISTEN", "ESTABLISHED"):
                threat_score += 40
                reasons.append(f"Targeting sensitive port {local_port} ({service})")

        # 2. Port Scan Detection: Multiple distinct ports contacted by the same IP within 30 seconds
        recent_hits = [p for t, p in self._ip_history[remote_ip] if now - t < 30]
        distinct_ports = set(recent_hits)
        if len(distinct_ports) >= 3:
            threat_score += 50
            reasons.append(f"Port Scan pattern detected ({len(distinct_ports)} distinct ports targeted in 30s)")

        # 3. Connection rate anomaly
        if len(recent_hits) >= 15:
            threat_score += 30
            reasons.append(f"High connection frequency ({len(recent_hits)} requests in 30s)")

        # 4. Unknown/Suspicious process handling inbound connections
        if process_name and process_name.lower() in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
            threat_score += 60
            reasons.append(f"Scripting host ({process_name}) establishing external network socket")

        # Determine severity level
        if threat_score >= 70:
            severity = "CRITICAL"
        elif threat_score >= 40:
            severity = "HIGH"
        elif threat_score >= 20:
            severity = "MEDIUM"
        else:
            return None

        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local_port": local_port,
            "process_name": process_name,
            "status": status,
            "severity": severity,
            "score": threat_score,
            "reasons": reasons,
            "geo": geo_info
        }

        # Keep last 100 alerts
        self._alert_history.append(alert)
        if len(self._alert_history) > 100:
            self._alert_history.pop(0)

        self._log_to_csv(alert)

        return alert

    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self._alert_history[-limit:]
