<div align="center">
  <h1>🛡️ NetSentinel</h1>
  <p><b>Windows Host Traffic Monitor & Intrusion Blocker</b></p>

  <p>
    <a href="https://github.com/Kingsoft0001/network-sentinel/releases"><img src="https://img.shields.io/github/v/release/Kingsoft0001/network-sentinel?color=blue&style=flat-square" alt="Release"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square" alt="Python"></a>
    <a href="https://github.com/Kingsoft0001/network-sentinel/stargazers"><img src="https://img.shields.io/github/stars/Kingsoft0001/network-sentinel?style=flat-square" alt="Stars"></a>
    <a href="https://github.com/Kingsoft0001/network-sentinel/network/members"><img src="https://img.shields.io/github/forks/Kingsoft0001/network-sentinel?style=flat-square" alt="Forks"></a>
  </p>
</div>

---

A standalone, real-time network traffic and intrusion detection system (IDS) built in Python for Windows. NetSentinel acts as your personal security guard, actively monitoring connections and blocking malicious actors automatically.

## 📑 Table of Contents
- [Features](#-features)
- [Screenshots](#-screenshots)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Features

- **📡 Live Traffic Monitoring:** Inspects active sockets, processes, protocols, ports, and connection states in real-time.
- **🌍 GeoIP & ISP Identification:** Automatically maps remote IP addresses to their Country, City, and ISP/Organization.
- **🛡️ Intrusion Detection System (IDS):**
  - Detects aggressive port scanning patterns.
  - Monitors unauthorized access attempts to sensitive ports (e.g. RDP 3389, SMB 445, SSH 22, Databases).
  - Flags abnormal scripting engine network activity (`powershell.exe`, `cmd.exe`).
- **🧱 Windows Firewall Integration:**
  - 1-Click block and unblock remote attacker IPs via Windows Firewall.
  - Optional `--auto-block` mode for mitigating critical threats instantly.
- **📱 Discord Alerts:** Real-time push notifications via Discord Webhooks with rich embedded messages.

## 📸 Screenshots

*(⚠️ Developer Tip: Edit this README on GitHub and paste your screenshots below by deleting the placeholder links and pressing `Ctrl+V`!)*

### 1. Web Dashboard (Live Traffic & AI Analysis)
> <img src="https://via.placeholder.com/800x400.png?text=Add+Web+Dashboard+Screenshot+Here" alt="Web Dashboard">

### 2. Live Terminal (IDS Engine)
> <img src="https://via.placeholder.com/800x400.png?text=Add+Terminal+Screenshot+Here" alt="Terminal UI">

### 3. Discord Threat Alerts
> <img src="https://via.placeholder.com/400x200.png?text=Add+Discord+Alert+Screenshot+Here" alt="Discord Alerts">

## 🛠 Prerequisites

- **OS:** Windows 10 / 11 (Requires Administrator Privileges for Firewall rules).
- **Python:** Python 3.8 or newer.

## 📥 Installation

1. **Clone the repository:**
   ```cmd
   git clone https://github.com/Kingsoft0001/network-sentinel.git
   cd network-sentinel
   ```

2. **Install required dependencies:**
   ```cmd
   pip install -r requirements.txt
   ```

## 💻 Usage

> **Note:** You must run your Command Prompt or PowerShell as **Administrator** for firewall and socket monitoring features to work properly.

### 1. Live Terminal Dashboard (Recommended)
Start the standard monitoring dashboard:
```cmd
python main.py
```
*(Alternatively, you can just right-click `run_sentinel.bat` and select "Run as Administrator".)*

### 2. Auto-Block Mode (Active IDS)
Automatically add firewall rules to block IPs exhibiting malicious behavior:
```cmd
python main.py --auto-block
```

### 3. Connect to Discord Webhook for Mobile Alerts
Receive notifications directly to your Discord server:
```cmd
python main.py --webhook "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL" --auto-block
```

### 4. Filter Traffic by Application or IP
Focus monitoring on a specific application (e.g., Chrome):
```cmd
python main.py --filter "chrome"
```

### 5. Manual Firewall Management
You can use NetSentinel to quickly manage your Windows Firewall rules:
```cmd
# Block a suspicious IP
python main.py --block 185.220.101.5

# List all blocked IPs
python main.py --list-blocked

# Unblock an IP
python main.py --unblock 185.220.101.5

# Unblock all NetSentinel rules (Reset)
python main.py --unblock-all
```

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! 
Feel free to check the [issues page](https://github.com/Kingsoft0001/network-sentinel/issues). 

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License
This project is open-source. *(Note: Make sure to add a LICENSE file to your repo, e.g., MIT License)*

---
<div align="center">
  <i>Developed with ❤️ by Kingsoft0001</i>
</div>
