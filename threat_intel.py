import requests
import json

class ThreatIntelligence:
    def __init__(self, api_key=""):
        self.api_key = api_key
        self.cache = {} # IP -> score

    def get_ip_reputation(self, ip: str) -> int:
        """Returns Abuse Score (0-100). 0 is safe, 100 is highly malicious."""
        if not self.api_key or ip in ("0.0.0.0", "127.0.0.1", "::1", "localhost"):
            return 0
            
        if ip in self.cache:
            return self.cache[ip]

        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }
            response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=3)
            if response.status_code == 200:
                data = response.json()
                score = data['data']['abuseConfidenceScore']
                self.cache[ip] = score
                return score
            else:
                self.cache[ip] = 0
                return 0
        except Exception:
            self.cache[ip] = 0
            return 0
