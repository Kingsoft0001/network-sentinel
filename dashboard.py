import os
import json
from flask import Flask, render_template_string, jsonify
from geoip import GeoIPResolver
from scanner import NetworkScanner
from threat import ThreatDetector
from firewall import FirewallManager

app = Flask(__name__)

# Core components initialize karte hain
geoip = GeoIPResolver()
scanner = NetworkScanner(geoip)
threat_engine = ThreatDetector()

# Single-file template (Bootstrap for styling)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0d1117; color: #c9d1d9; }
        .card { background-color: #161b22; border-color: #30363d; }
        .table { color: #c9d1d9; }
        .text-cyan { color: #58a6ff !important; }
        .text-green { color: #3fb950 !important; }
        .text-yellow { color: #d29922 !important; }
        .text-red { color: #f85149 !important; }
        .border-danger-subtle { border-color: #f85149 !important; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark mb-4 border-bottom" style="border-color: #30363d !important; background-color: #010409 !important;">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">🛡️ NetSentinel Live Dashboard</span>
        </div>
    </nav>
    <div class="container-fluid px-4">
        <!-- Stats Row -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card p-3 text-center shadow-sm">
                    <h6 class="text-muted">Total Active Connections</h6>
                    <h2 class="text-cyan mb-0" id="stat-total">0</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center shadow-sm">
                    <h6 class="text-muted">Remote / WAN (Established)</h6>
                    <h2 class="text-green mb-0" id="stat-remote">0</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center shadow-sm">
                    <h6 class="text-muted">Listening Ports</h6>
                    <h2 class="text-yellow mb-0" id="stat-listening">0</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center shadow-sm">
                    <h6 class="text-muted">Threats Detected</h6>
                    <h2 class="text-red mb-0" id="stat-threats">0</h2>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Connections Table -->
            <div class="col-md-8">
                <div class="card p-3 shadow-sm h-100">
                    <h5 class="mb-3 border-bottom pb-2 border-secondary">📡 Live Network Traffic</h5>
                    <div class="table-responsive">
                        <table class="table table-hover table-sm border-secondary">
                            <thead>
                                <tr>
                                    <th>PID</th>
                                    <th>Process</th>
                                    <th>Proto</th>
                                    <th>Local Port</th>
                                    <th>Remote IP</th>
                                    <th>Status</th>
                                    <th>Location</th>
                                </tr>
                            </thead>
                            <tbody id="connections-tbody">
                                <!-- Data injected via JS -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <!-- Alerts Panel -->
            <div class="col-md-4">
                <div class="card p-3 shadow-sm h-100">
                    <h5 class="text-danger mb-3 border-bottom pb-2 border-secondary">🚨 Intrusion Alerts (IDS)</h5>
                    <div id="alerts-container">
                        <p class="text-success text-center mt-4">✅ No active threats detected.<br><small>System traffic is normal.</small></p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function updateDashboard() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                
                // Update Stats
                document.getElementById('stat-total').innerText = data.stats.total;
                document.getElementById('stat-remote').innerText = data.stats.remote_established;
                document.getElementById('stat-listening').innerText = data.stats.listening;
                document.getElementById('stat-threats').innerText = data.stats.threats_count;

                // Update Table
                const tbody = document.getElementById('connections-tbody');
                tbody.innerHTML = '';
                
                // Sort to show important connections on top
                let filtered = data.connections.sort((a, b) => {
                    if (a.conn_type === "REMOTE / WAN" && b.conn_type !== "REMOTE / WAN") return -1;
                    if (a.conn_type !== "REMOTE / WAN" && b.conn_type === "REMOTE / WAN") return 1;
                    return 0;
                }).slice(0, 25);

                filtered.forEach(c => {
                    const tr = document.createElement('tr');
                    
                    let statusColor = "";
                    if(c.status === "ESTABLISHED") statusColor = "text-green fw-bold";
                    else if(c.status === "LISTEN") statusColor = "text-yellow";
                    else statusColor = "text-secondary";

                    let loc = c.geo.country || "-";
                    if(c.geo.city && c.geo.city !== "Unknown") loc = c.geo.city + ", " + loc;

                    tr.innerHTML = `
                        <td class="text-secondary">${c.pid}</td>
                        <td class="text-cyan fw-semibold">${c.process_name}</td>
                        <td>${c.proto}</td>
                        <td>:${c.local_port}</td>
                        <td>${c.remote_ip || "-"}</td>
                        <td class="${statusColor}">${c.status}</td>
                        <td>${loc}</td>
                    `;
                    tbody.appendChild(tr);
                });

                // Update Alerts
                const alertsContainer = document.getElementById('alerts-container');
                if (data.alerts.length === 0) {
                    alertsContainer.innerHTML = '<p class="text-success text-center mt-4">✅ No active threats detected.<br><small>System traffic is normal.</small></p>';
                } else {
                    alertsContainer.innerHTML = '';
                    data.alerts.slice(-6).reverse().forEach(a => {
                        let badgeClass = a.severity === "CRITICAL" ? "text-bg-danger" : "text-bg-warning";
                        let timeString = (a.timestamp || "").split(" ")[1] || "Just now";
                        
                        alertsContainer.innerHTML += `
                            <div class="border border-danger-subtle rounded p-2 mb-2" style="background-color: rgba(248, 81, 73, 0.1);">
                                <div class="d-flex justify-content-between align-items-center mb-1">
                                    <span class="badge ${badgeClass}">${a.severity}</span>
                                    <small class="text-muted">${timeString}</small>
                                </div>
                                <div><strong>${a.remote_ip || "-"}</strong> attacked port <strong>${a.local_port || "-"}</strong> (${a.process_name})</div>
                                <div class="small text-danger mt-1">${a.reasons.join('; ')}</div>
                            </div>
                        `;
                    });
                }
            } catch (e) {
                console.error("Error fetching data:", e);
            }
        }

        // Har 2 second mein data refresh karo
        setInterval(updateDashboard, 2000);
        updateDashboard();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/data')
def api_data():
    # Scan network 
    connections = scanner.scan_connections()
    
    # Analyze for threats (IDS)
    for c in connections:
        if c["remote_ip"] and c["conn_type"] == "REMOTE / WAN":
            threat_engine.evaluate_connection(
                remote_ip=c["remote_ip"],
                remote_port=c["remote_port"],
                local_port=c["local_port"],
                status=c["status"],
                process_name=c["process_name"],
                is_local=c["geo"].get("is_local", False),
                geo_info=c["geo"]
            )

    stats = {
        "total": len(connections),
        "remote_established": sum(1 for c in connections if c["conn_type"] == "REMOTE / WAN" and c["status"] == "ESTABLISHED"),
        "listening": sum(1 for c in connections if c["status"] == "LISTEN"),
        "threats_count": len(threat_engine.get_recent_alerts(100))
    }
    
    alerts = threat_engine.get_recent_alerts(10)
    
    return jsonify({
        "stats": stats,
        "connections": connections,
        "alerts": alerts
    })

if __name__ == '__main__':
    print("=====================================================")
    print("🚀 Starting NetSentinel Web Dashboard...")
    print("👉 Open your browser and go to: http://127.0.0.1:5000")
    print("=====================================================")
    # Production mein Waitress ya Gunicorn use karte hain, par development ke liye run() thik hai
    app.run(host='127.0.0.1', port=5000, debug=False)
