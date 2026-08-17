from fastapi import APIRouter, status
from fastapi.responses import HTMLResponse
from app.config import settings

router = APIRouter(tags=["Dashboard"])

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Reputation Score API - Security Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-dark: #090d16;
            --bg-card: rgba(18, 26, 43, 0.7);
            --border-card: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-indigo: #6366f1;
            --accent-emerald: #10b981;
            --accent-amber: #f59e0b;
            --accent-rose: #ef4444;
            --accent-cyan: #06b6d4;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(6, 182, 212, 0.1) 0px, transparent 50%);
            padding: 2rem;
        }

        .container {
            max-width: 1300px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-card);
        }

        .logo-group {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .shield-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent-indigo), var(--accent-cyan));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 20px rgba(99, 102, 241, 0.4);
        }

        .shield-icon svg {
            width: 22px;
            height: 22px;
            fill: white;
        }

        h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(to right, #ffffff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .badge-pii {
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .badge-pii::before {
            content: "";
            width: 8px;
            height: 8px;
            background-color: var(--accent-emerald);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px var(--accent-emerald);
        }

        .grid-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .card {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-card);
            border-radius: 16px;
            padding: 1.5rem;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .card:hover {
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.15);
        }

        .card-header {
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: 500;
            margin-bottom: 0.75rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .card-value {
            font-family: 'Outfit', sans-serif;
            font-size: 1.8rem;
            font-weight: 700;
            color: #ffffff;
        }

        .card-subtext {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }

        .grid-main {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        @media (max-width: 900px) {
            .grid-main {
                grid-template-columns: 1fr;
            }
        }

        .form-group {
            margin-bottom: 1.25rem;
        }

        label {
            display: block;
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
            font-weight: 500;
        }

        input[type="text"] {
            width: 100%;
            background: rgba(10, 15, 26, 0.8);
            border: 1px solid var(--border-card);
            border-radius: 10px;
            padding: 0.75rem 1rem;
            color: #ffffff;
            font-size: 0.95rem;
            outline: none;
            transition: border-color 0.2s;
        }

        input[type="text"]:focus {
            border-color: var(--accent-indigo);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }

        .btn {
            background: linear-gradient(135deg, var(--accent-indigo), #4f46e5);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 0.75rem 1.5rem;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            width: 100%;
            transition: opacity 0.2s, box-shadow 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn:hover {
            opacity: 0.95;
            box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4);
        }

        .btn-outline {
            background: transparent;
            border: 1px solid var(--border-card);
            color: var(--text-primary);
        }

        .btn-outline:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .result-container {
            margin-top: 1.5rem;
            padding: 1.25rem;
            border-radius: 12px;
            background: rgba(10, 15, 26, 0.6);
            border: 1px solid var(--border-card);
            display: none;
        }

        .gauge-meter {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }

        .score-circle {
            width: 70px;
            height: 70px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Outfit', sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            color: white;
        }

        .score-low { background: linear-gradient(135deg, #10b981, #059669); }
        .score-medium { background: linear-gradient(135deg, #f59e0b, #d97706); }
        .score-high { background: linear-gradient(135deg, #ef4444, #dc2626); }
        .score-critical { background: linear-gradient(135deg, #881337, #e11d48); }

        .flags-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 8px;
            margin-top: 1rem;
        }

        .flag-tag {
            background: rgba(255, 255, 255, 0.05);
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .flag-active {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .signals-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 0.75rem;
        }

        .signal-pill {
            background: rgba(99, 102, 241, 0.2);
            color: #a5b4fc;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 500;
        }

        pre {
            background: #060911;
            padding: 1rem;
            border-radius: 8px;
            font-size: 0.8rem;
            color: #38bdf8;
            overflow-x: auto;
            max-height: 250px;
        }

        .chart-container {
            position: relative;
            height: 240px;
            width: 100%;
        }

        .feed-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 0.82rem;
        }

        .feed-item:last-child {
            border-bottom: none;
        }

        .flex-between {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-group">
                <div class="shield-icon">
                    <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
                </div>
                <div>
                    <h1>IP Reputation Score API</h1>
                    <div style="font-size: 0.8rem; color: var(--text-secondary);">Enterprise Security Dashboard v1.1.0</div>
                </div>
            </div>
            <div class="badge-pii">PII Zero Active & Audited</div>
        </header>

        <!-- Stats Overview -->
        <div class="grid-stats">
            <div class="card">
                <div class="card-header">Botnet C2 (Abuse.ch)</div>
                <div class="card-value" id="cnt-c2">--</div>
                <div class="card-subtext">IPs C2 Activas</div>
            </div>
            <div class="card">
                <div class="card-header">Active Phishing Hosts</div>
                <div class="card-value" id="cnt-phish">--</div>
                <div class="card-subtext">OpenPhish & PhishTank</div>
            </div>
            <div class="card">
                <div class="card-header">Bogon Subnets</div>
                <div class="card-value" id="cnt-bogon">--</div>
                <div class="card-subtext">Team Cymru Fullbogons</div>
            </div>
            <div class="card">
                <div class="card-header">Nodos Tor Exit</div>
                <div class="card-value" id="cnt-tor">--</div>
                <div class="card-subtext">Cargados in-memory</div>
            </div>
            <div class="card">
                <div class="card-header">CDN Egress CIDRs</div>
                <div class="card-value" id="cnt-cdn">--</div>
                <div class="card-subtext">Cloudflare & Fastly</div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="grid-main">
            <!-- Left: Interactive IP Tester Playground -->
            <div class="card">
                <div class="card-header">
                    <span>IP Risk Scoring Playground</span>
                    <span style="font-size: 0.75rem; color: var(--accent-cyan);">Zero Persistence</span>
                </div>
                
                <div class="form-group">
                    <label for="input-key">X-API-Key</label>
                    <input type="text" id="input-key" value="sk_admin_9876543210fedcba" placeholder="sk_live_...">
                </div>

                <div class="form-group">
                    <label for="input-ip">Dirección IP (IPv4 / IPv6)</label>
                    <input type="text" id="input-ip" value="185.220.101.5" placeholder="Ej. 185.220.101.5 o 2001:db8::1">
                </div>

                <div class="form-group" style="display: flex; align-items: center; gap: 8px; margin-bottom: 1rem;">
                    <input type="checkbox" id="chk-allow-private" style="width: 16px; height: 16px; cursor: pointer;">
                    <label for="chk-allow-private" style="margin: 0; cursor: pointer; font-size: 0.8rem; color: var(--accent-cyan);">Permitir IPs Privadas (Testing Mode)</label>
                </div>

                <button class="btn" id="btn-eval">
                    <span>Evaluar Riesgo de IP</span>
                </button>

                <div class="result-container" id="result-box">
                    <div class="gauge-meter">
                        <div>
                            <div style="font-size: 0.8rem; color: var(--text-secondary);">Risk Level & Action</div>
                            <div style="font-size: 1.3rem; font-weight: 700; text-transform: uppercase;" id="res-level">--</div>
                            <div style="font-size: 0.85rem; color: var(--accent-cyan);" id="res-recommendation">--</div>
                        </div>
                        <div class="score-circle" id="res-score-circle">--</div>
                    </div>

                    <div style="margin-top: 1rem;">
                        <label>Red & ASN:</label>
                        <div style="font-size: 0.9rem;" id="res-network">--</div>
                    </div>

                    <div style="margin-top: 1rem;">
                        <label>Señales de Riesgo Evaluadas:</label>
                        <div class="signals-list" id="res-signals"></div>
                    </div>

                    <div style="margin-top: 1rem;">
                        <label>Flags de Red:</label>
                        <div class="flags-grid" id="res-flags"></div>
                    </div>

                    <div style="margin-top: 1rem;">
                        <label>Respuesta JSON Raw:</label>
                        <pre id="res-json"></pre>
                    </div>
                </div>
            </div>

            <!-- Right: Feed Control & System Status -->
            <div class="card">
                <div class="flex-between" style="margin-bottom: 1.25rem;">
                    <div class="card-header" style="margin: 0;">Estado de Inteligencia de Amenazas</div>
                    <button class="btn btn-outline" id="btn-refresh" style="width: auto; padding: 6px 14px; font-size: 0.8rem;">
                        🔄 Recargar Feeds
                    </button>
                </div>

                <div style="margin-bottom: 1.5rem;">
                    <div class="feed-item">
                        <span>Botnet C2 Server List (Abuse.ch)</span>
                        <strong id="item-c2">--</strong>
                    </div>
                    <div class="feed-item">
                        <span>Active Phishing Hosts (OpenPhish/PhishTank)</span>
                        <strong id="item-phish">--</strong>
                    </div>
                    <div class="feed-item">
                        <span>Team Cymru Fullbogons</span>
                        <strong id="item-bogon">--</strong>
                    </div>
                    <div class="feed-item">
                        <span>Tor Exit Nodes</span>
                        <strong id="item-tor">--</strong>
                    </div>
                    <div class="feed-item">
                        <span>Cloudflare & Fastly CDN Egress</span>
                        <strong id="item-cdn">--</strong>
                    </div>
                    <div class="feed-item">
                        <span>Cloud / Datacenter CIDRs (AWS/GCP/Azure/OCI/DO/Aliyun/Tencent/Vultr)</span>
                        <strong id="item-dc">--</strong>
                    </div>
                    <div class="feed-item">
                        <span>Spamhaus & FireHOL Blocklists</span>
                        <strong id="item-abuse">--</strong>
                    </div>
                    <div class="feed-item">
                        <span>Apple Private Relay Ranges</span>
                        <strong id="item-apple">--</strong>
                    </div>
                    <div class="feed-item">
                        <span>Última Actualización</span>
                        <strong id="item-updated">--</strong>
                    </div>
                </div>

                <div class="card-header">Distribución de Ponderación por Regla</div>
                <div class="chart-container">
                    <canvas id="scoringChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Live Security Audit Log Stream (PII-Zero) -->
        <div class="card" style="margin-bottom: 2rem;">
            <div class="flex-between" style="margin-bottom: 1rem;">
                <div>
                    <div class="card-header" style="margin: 0; font-size: 1rem; color: #ffffff;">Visor de Trazas & Eventos PII-Zero en Tiempo Real</div>
                    <div style="font-size: 0.78rem; color: var(--text-secondary);">Flujo de auditoría anónima en memoria (Cero datos personales almacenados)</div>
                </div>
                <span class="badge-pii" id="audit-total-badge">0 Eventos Evaluados</span>
            </div>
            
            <div style="font-family: monospace; font-size: 0.82rem; background: #050811; padding: 1rem; border-radius: 10px; border: 1px solid var(--border-card); max-height: 280px; overflow-y: auto;" id="audit-log-terminal">
                <div style="color: #64748b;">[System] Esperando primeras evaluaciones de riesgo de IP...</div>
            </div>
        </div>
    </div>

    <script>
        async function fetchAuditLogs() {
            try {
                const res = await fetch('/api/v1/dashboard/stats');
                if (!res.ok) return;
                const data = await res.json();
                
                document.getElementById('audit-total-badge').innerText = `${data.total_evaluations || 0} Eventos Evaluados`;
                
                const term = document.getElementById('audit-log-terminal');
                if (data.recent_events && data.recent_events.length > 0) {
                    term.innerHTML = '';
                    data.recent_events.forEach(ev => {
                        const line = document.createElement('div');
                        line.style.marginBottom = '6px';
                        
                        let color = '#34d399';
                        if (ev.risk_level === 'critical') color = '#f43f5e';
                        else if (ev.risk_level === 'high') color = '#fb7185';
                        else if (ev.risk_level === 'medium') color = '#fbbf24';

                        const sigs = (ev.signals_used || []).join(', ') || 'clean_traffic';
                        const timeStr = ev.timestamp.includes('T') ? new Date(ev.timestamp).toLocaleTimeString() : ev.timestamp;
                        line.innerHTML = `<span style="color:#64748b;">[${timeStr}]</span> <span style="color:${color}; font-weight:bold;">[${ev.risk_level.toUpperCase()} ${ev.risk_score}/100]</span> <span style="color:#38bdf8;">ACTION: ${ev.recommendation.toUpperCase()}</span> | Type: ${ev.network_type} | Signals: <span style="color:#a5b4fc;">${sigs}</span> <span style="color:#64748b; font-size:0.75rem;">(${ev.latency_ms} ms)</span>`;
                        term.appendChild(line);
                    });
                }
            } catch (e) {
                console.error(e);
            }
        }
        async function fetchReadiness() {
            try {
                const res = await fetch('/api/v1/health/readiness');
                if (!res.ok) return;
                const data = await res.json();
                const feeds = data.feeds || {};
                
                document.getElementById('cnt-c2').innerText = (feeds.botnet_c2_ips_loaded || 0).toLocaleString();
                document.getElementById('cnt-phish').innerText = (feeds.phishing_ips_loaded || 0).toLocaleString();
                document.getElementById('cnt-bogon').innerText = (feeds.bogons_loaded || 0).toLocaleString();
                document.getElementById('cnt-tor').innerText = (feeds.tor_exits_loaded || 0).toLocaleString();
                document.getElementById('cnt-cdn').innerText = (feeds.cdn_cidrs_loaded || 0).toLocaleString();

                document.getElementById('item-c2').innerText = (feeds.botnet_c2_ips_loaded || 0).toLocaleString();
                document.getElementById('item-phish').innerText = (feeds.phishing_ips_loaded || 0).toLocaleString();
                document.getElementById('item-bogon').innerText = (feeds.bogons_loaded || 0).toLocaleString();
                document.getElementById('item-tor').innerText = (feeds.tor_exits_loaded || 0).toLocaleString();
                document.getElementById('item-cdn').innerText = (feeds.cdn_cidrs_loaded || 0).toLocaleString();
                document.getElementById('item-dc').innerText = (feeds.datacenter_cidrs_loaded || 0).toLocaleString();
                document.getElementById('item-abuse').innerText = (feeds.abuse_ips_loaded || 0).toLocaleString();
                document.getElementById('item-apple').innerText = (feeds.apple_relay_cidrs_loaded || 0).toLocaleString();

                if (feeds.last_updated) {
                    const dt = new Date(feeds.last_updated * 1000);
                    document.getElementById('item-updated').innerText = dt.toLocaleTimeString();
                } else {
                    document.getElementById('item-updated').innerText = "Cargando...";
                }
            } catch (e) {
                console.error(e);
            }
        }

        async function evaluateIp() {
            const apiKey = document.getElementById('input-key').value.trim();
            const ip = document.getElementById('input-ip').value.trim();
            const allowPrivate = document.getElementById('chk-allow-private').checked;
            const resultBox = document.getElementById('result-box');

            if (!ip) return;

            try {
                const res = await fetch('/api/v1/score', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': apiKey
                    },
                    body: JSON.stringify({ ip: ip, allow_private: allowPrivate })
                });

                const data = await res.json();
                resultBox.style.display = 'block';
                document.getElementById('res-json').innerText = JSON.stringify(data, null, 2);

                if (!res.ok) {
                    document.getElementById('res-level').innerText = "Error";
                    document.getElementById('res-recommendation').innerText = data.detail || "Error en la consulta";
                    document.getElementById('res-score-circle').innerText = "!";
                    document.getElementById('res-score-circle').className = "score-circle score-critical";
                    return;
                }

                // Render Gauge
                const score = data.risk_score;
                const circle = document.getElementById('res-score-circle');
                circle.innerText = score;

                if (data.risk_level === 'critical') circle.className = 'score-circle score-critical';
                else if (data.risk_level === 'high') circle.className = 'score-circle score-high';
                else if (data.risk_level === 'medium') circle.className = 'score-circle score-medium';
                else circle.className = 'score-circle score-low';

                document.getElementById('res-level').innerText = data.risk_level;
                document.getElementById('res-recommendation').innerText = `Recomendación: ${data.recommendation.toUpperCase()}`;

                // Network & Location
                const net = data.network || {};
                const loc = data.location || {};
                const countryStr = loc.country_code ? ` | País: ${loc.country_name} (${loc.country_code})` : '';
                document.getElementById('res-network').innerText = `ASN ${net.asn || 'N/A'} - ${net.asn_org} (${net.network_type})${countryStr}`;

                // Signals
                const sigsContainer = document.getElementById('res-signals');
                sigsContainer.innerHTML = '';
                if (data.signals_used && data.signals_used.length > 0) {
                    data.signals_used.forEach(s => {
                        const pill = document.createElement('span');
                        pill.className = 'signal-pill';
                        pill.innerText = s;
                        sigsContainer.appendChild(pill);
                    });
                } else {
                    sigsContainer.innerHTML = '<span style="font-size:0.8rem; color:var(--text-secondary);">Ninguna señal de riesgo activa</span>';
                }

                // Flags
                const flagsContainer = document.getElementById('res-flags');
                flagsContainer.innerHTML = '';
                const flags = data.flags || {};
                Object.keys(flags).forEach(k => {
                    const tag = document.createElement('div');
                    const isActive = flags[k];
                    tag.className = `flag-tag ${isActive ? 'flag-active' : ''}`;
                    tag.innerHTML = `<span>${k}</span><strong>${isActive ? 'TRUE' : 'FALSE'}</strong>`;
                    flagsContainer.appendChild(tag);
                });

                // Update audit stream
                fetchAuditLogs();

            } catch (err) {
                alert('Error al conectar con la API: ' + err.message);
            }
        }

        async function triggerRefresh() {
            const apiKey = document.getElementById('input-key').value.trim();
            try {
                const res = await fetch('/api/v1/admin/feeds/refresh', {
                    method: 'POST',
                    headers: { 'X-API-Key': apiKey }
                });
                if (res.ok) {
                    alert('Feeds recargados exitosamente');
                    fetchReadiness();
                    fetchAuditLogs();
                } else {
                    alert('Error o falta de permisos para recargar feeds');
                }
            } catch (e) {
                alert('Error: ' + e.message);
            }
        }

        // Initialize Chart
        function initChart() {
            const ctx = document.getElementById('scoringChart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Botnet C2', 'Phishing Host', 'Bogon Range', 'Tor Exit', 'GreenSnow', 'Open Proxy', 'Abuse List', 'VPN', 'Tor Relay', 'Datacenter', 'CDN Egress'],
                    datasets: [{
                        label: 'Puntos de Riesgo Max',
                        data: [100, 95, 95, 90, 75, 75, 70, 50, 40, 35, 10],
                        backgroundColor: [
                            'rgba(136, 19, 55, 0.9)',
                            'rgba(190, 18, 60, 0.85)',
                            'rgba(225, 29, 72, 0.85)',
                            'rgba(239, 68, 68, 0.8)',
                            'rgba(217, 119, 6, 0.85)',
                            'rgba(245, 158, 11, 0.8)',
                            'rgba(249, 115, 22, 0.8)',
                            'rgba(99, 102, 241, 0.8)',
                            'rgba(168, 85, 247, 0.8)',
                            'rgba(6, 182, 212, 0.8)',
                            'rgba(16, 185, 129, 0.8)'
                        ],
                        borderRadius: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: '#9ca3af' }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { color: '#9ca3af', font: { size: 10 } }
                        }
                    }
                }
            });
        }

        document.getElementById('btn-eval').addEventListener('click', evaluateIp);
        document.getElementById('btn-refresh').addEventListener('click', triggerRefresh);

        // Load initially
        fetchReadiness();
        fetchAuditLogs();
        initChart();
        evaluateIp();
        setInterval(fetchAuditLogs, 5000);
    </script>
</body>
</html>
"""


from app.security.audit_stream import audit_stream


@router.get(
    "/dashboard",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    summary="Security Dashboard UI",
    description="Serves an embedded PII Zero interactive security dashboard for inspecting feeds, testing scoring playground, and monitoring system health."
)
async def get_dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)


@router.get(
    "/dashboard/stats",
    status_code=status.HTTP_200_OK,
    summary="Live PII-Zero Security Audit Stream & Metrics Stats",
    description="Returns realtime operational counters, risk distribution statistics, and PII-Zero audit stream event logs."
)
async def get_dashboard_stats():
    return audit_stream.get_data()
