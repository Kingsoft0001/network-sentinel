# 🛡️ NetSentinel - Windows Host Traffic Monitor & Intrusion Blocker

A standalone, real-time network traffic and intrusion detection system (IDS) built in Python for Windows.

## 🚀 Features
- **Live Traffic Monitoring**: Inspects active sockets, processes, protocols, ports, and connection states.
- **GeoIP & ISP Identification**: Automatically maps remote IP addresses to their Country, City, and ISP/Organization.
- **Intrusion Detection System (IDS)**:
  - Detects port scanning patterns.
  - Detects unauthorized access attempts to sensitive ports (e.g. RDP 3389, SMB 445, SSH 22, Databases).
  - Flags abnormal scripting engine network activity (`powershell.exe`, `cmd.exe`).
- **Windows Firewall Integration**:
  - 1-Click block and unblock remote attacker IPs via Windows Firewall.
  - Optional `--auto-block` mode for critical threats.
- **Discord Alerts**: Real-time push notifications via Discord Webhook with rich embeds.

---

## 💻 How to Run

### 1. Live Terminal Dashboard (Recommended):
Run PowerShell/CMD as **Administrator** and execute:
```powershell
python main.py
```
Or double-click `run_sentinel.bat` (Run as Administrator).

### 2. Auto-Block Mode (Actively blocks attackers in Windows Firewall):
```powershell
python main.py --auto-block
```

### 3. Connect to Discord Webhook for Mobile Alerts:
```powershell
python main.py --webhook "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL" --auto-block
```

### 4. Filter Traffic by Application or IP:
```powershell
python main.py --filter "chrome"
```

### 5. Manual Firewall IP Blocking / Unblocking:
```powershell
# Block a suspicious IP
python main.py --block 185.220.101.5

# List all blocked IPs
python main.py --list-blocked

# Unblock an IP
python main.py --unblock 185.220.101.5

# Unblock all NetSentinel rules
python main.py --unblock-all
```
