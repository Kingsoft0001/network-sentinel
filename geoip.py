import ipaddress
import json
import os
import threading
import time
from typing import Dict, Any, Optional
import requests

CACHE_FILE = os.path.join(os.path.dirname(__file__), "geoip_cache.json")

class GeoIPResolver:
    """Resolves IP addresses to geographic and ISP information with caching."""
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load_cache()
        self._pending_queue = set()
        self._worker_thread = threading.Thread(target=self._batch_worker, daemon=True)
        self._worker_thread.start()

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def _save_cache(self):
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass

    def is_private_or_local(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            )
        except ValueError:
            return True

    def get_info(self, ip_str: str) -> Dict[str, Any]:
        """Returns cached info or queues IP for asynchronous lookup."""
        if not ip_str or ip_str == "*" or ip_str == "0.0.0.0" or ip_str == "::":
            return {"country": "Local", "city": "Localhost", "isp": "System", "is_local": True}

        if self.is_private_or_local(ip_str):
            return {"country": "LAN / Private", "city": "Local Network", "isp": "Local Network", "is_local": True}

        with self._lock:
            if ip_str in self._cache:
                return self._cache[ip_str]
            if ip_str not in self._pending_queue:
                self._pending_queue.add(ip_str)

        return {"country": "Resolving...", "city": "...", "isp": "...", "is_local": False}

    def _batch_worker(self):
        """Background worker that queries ip-api.com in batches to avoid rate limits."""
        while True:
            ips_to_query = []
            with self._lock:
                while self._pending_queue and len(ips_to_query) < 45:
                    ips_to_query.append(self._pending_queue.pop())

            if not ips_to_query:
                time.sleep(0.5)
                continue

            try:
                # ip-api batch endpoint accepts up to 100 queries per request
                url = "http://ip-api.com/batch"
                payload = [
                    {"query": ip, "fields": "status,message,country,countryCode,regionName,city,isp,org,as,query"}
                    for ip in ips_to_query
                ]
                resp = requests.post(url, json=payload, timeout=5)
                if resp.status_code == 200:
                    results = resp.json()
                    with self._lock:
                        for res in results:
                            ip = res.get("query")
                            if res.get("status") == "success":
                                self._cache[ip] = {
                                    "country": res.get("country", "Unknown"),
                                    "country_code": res.get("countryCode", "??"),
                                    "city": res.get("city", "Unknown"),
                                    "region": res.get("regionName", ""),
                                    "isp": res.get("isp") or res.get("org") or "Unknown ISP",
                                    "as": res.get("as", ""),
                                    "is_local": False
                                }
                            else:
                                self._cache[ip] = {
                                    "country": "Unknown",
                                    "country_code": "??",
                                    "city": "Unknown",
                                    "isp": "Unknown",
                                    "is_local": False
                                }
                        self._save_cache()
            except Exception:
                # Re-queue on failure if needed
                pass

            time.sleep(1.0)
