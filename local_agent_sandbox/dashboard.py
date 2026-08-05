"""
Web-Based Visualization Dashboard Server (AC5).
Provides real-time interactive visualization of N-dimensional sandbox ecology,
mesh topology graph, God Mode GraphQL playground, and state metrics.
"""

import http.server
import socketserver
import json
import threading
import urllib.parse
from typing import Optional

from .orchestrator import UniverseOrchestrator
from .mesh import MeshNetworkManager
from .graphql_api import GodModeGraphQLAPI

HTML_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Verse Agent Ecology | God Mode Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --panel-bg: rgba(17, 24, 39, 0.85);
            --border-color: rgba(255, 255, 255, 0.1);
            --accent-cyan: #06b6d4;
            --accent-violet: #8b5cf6;
            --accent-green: #10b981;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow: hidden;
        }

        header {
            background: var(--panel-bg);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.25rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-violet));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .stats-banner {
            display: flex;
            gap: 1.5rem;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.5rem 1rem;
            display: flex;
            flex-direction: column;
        }

        .stat-value {
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--accent-cyan);
        }

        .stat-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .main-container {
            display: grid;
            grid-template-columns: 2fr 1fr;
            flex: 1;
            gap: 1rem;
            padding: 1rem;
            overflow: hidden;
        }

        .panel {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            backdrop-filter: blur(8px);
        }

        .panel-header {
            padding: 0.75rem 1.25rem;
            background: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .panel-body {
            flex: 1;
            position: relative;
            overflow: auto;
            padding: 1rem;
        }

        canvas {
            width: 100%;
            height: 100%;
            display: block;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th { color: var(--text-muted); font-weight: 600; }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .badge-running { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }
        .badge-meshed { background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); }

        textarea {
            width: 100%;
            height: 140px;
            background: #050811;
            border: 1px solid var(--border-color);
            color: #38bdf8;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            padding: 0.75rem;
            border-radius: 6px;
            resize: none;
        }

        button {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-violet));
            border: none;
            color: #fff;
            padding: 0.5rem 1.25rem;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }

        button:hover { opacity: 0.9; }

        #graphql-output {
            background: #050811;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.75rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            color: #a7f3d0;
            max-height: 200px;
            overflow-y: auto;
            white-space: pre-wrap;
            margin-top: 0.75rem;
        }
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path>
                <path d="M2 12h20"></path>
            </svg>
            Multi-Verse Agent Ecology Dashboard
        </div>
        <div class="stats-banner">
            <div class="stat-card">
                <span class="stat-value" id="stat-total">0</span>
                <span class="stat-label">Universes</span>
            </div>
            <div class="stat-card">
                <span class="stat-value" id="stat-meshed">0</span>
                <span class="stat-label">Meshed Channels</span>
            </div>
            <div class="stat-card">
                <span class="stat-value" id="stat-ops">0</span>
                <span class="stat-label">File Ops</span>
            </div>
        </div>
    </header>

    <div class="main-container">
        <div class="panel">
            <div class="panel-header">
                <span>N-Dimensional Mesh Topology Canvas</span>
                <button onclick="refreshData()">Refresh State</button>
            </div>
            <div class="panel-body">
                <canvas id="topologyCanvas"></canvas>
            </div>
        </div>

        <div style="display: flex; flex-direction: column; gap: 1rem;">
            <div class="panel" style="flex: 1;">
                <div class="panel-header">
                    <span>Active Sandboxes</span>
                </div>
                <div class="panel-body" style="padding: 0;">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="universe-table-body">
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="panel" style="height: 340px;">
                <div class="panel-header">
                    <span>God Mode GraphQL Console</span>
                    <button onclick="runGraphQL()">Execute</button>
                </div>
                <div class="panel-body">
                    <textarea id="graphql-query">{
  systemMetrics {
    total_universes
    running_universes
    meshed_universes
  }
}</textarea>
                    <div id="graphql-output">// Response will appear here</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const canvas = document.getElementById('topologyCanvas');
        const ctx = canvas.getContext('2d');

        function resizeCanvas() {
            canvas.width = canvas.parentElement.clientWidth;
            canvas.height = canvas.parentElement.clientHeight;
        }
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();

        let topologyData = { nodes: [], links: [] };

        async function refreshData() {
            try {
                const res = await fetch('/api/metrics');
                const data = await res.json();
                document.getElementById('stat-total').innerText = data.metrics.total_universes;
                document.getElementById('stat-meshed').innerText = data.metrics.meshed_universes;
                document.getElementById('stat-ops').innerText = data.metrics.total_file_ops;

                const topRes = await fetch('/api/topology');
                topologyData = await topRes.json();

                renderUniverses(data.universes);
                drawTopology();
            } catch (err) {
                console.error(err);
            }
        }

        function renderUniverses(universes) {
            const tbody = document.getElementById('universe-table-body');
            tbody.innerHTML = universes.slice(0, 15).map(u => `
                <tr>
                    <td><code>${u.id}</code></td>
                    <td>${u.name}</td>
                    <td><span class="badge badge-${u.status.toLowerCase()}">${u.status}</span></td>
                </tr>
            `).join('');
        }

        function drawTopology() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            const nodes = topologyData.nodes || [];
            const links = topologyData.links || [];

            if (nodes.length === 0) {
                ctx.fillStyle = '#6b7280';
                ctx.font = '14px Inter';
                ctx.fillText('No active sandbox universes detected.', canvas.width / 2 - 110, canvas.height / 2);
                return;
            }

            const cx = canvas.width / 2;
            const cy = canvas.height / 2;
            const radius = Math.min(cx, cy) * 0.7;

            const coords = {};
            nodes.forEach((n, idx) => {
                const angle = (idx / nodes.length) * 2 * Math.PI;
                coords[n.id] = {
                    x: cx + radius * Math.cos(angle),
                    y: cy + radius * Math.sin(angle),
                };
            });

            ctx.strokeStyle = '#06b6d4';
            ctx.lineWidth = 1.5;
            links.forEach(l => {
                const p1 = coords[l.source];
                const p2 = coords[l.target];
                if (p1 && p2) {
                    ctx.beginPath();
                    ctx.moveTo(p1.x, p1.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.stroke();
                }
            });

            nodes.forEach(n => {
                const p = coords[n.id];
                if (p) {
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, 8, 0, 2 * Math.PI);
                    ctx.fillStyle = '#8b5cf6';
                    ctx.fill();
                    ctx.lineWidth = 2;
                    ctx.strokeStyle = '#38bdf8';
                    ctx.stroke();

                    ctx.fillStyle = '#f3f4f6';
                    ctx.font = '11px Inter';
                    ctx.fillText(n.id, p.x + 12, p.y + 4);
                }
            });
        }

        async function runGraphQL() {
            const query = document.getElementById('graphql-query').value;
            const output = document.getElementById('graphql-output');
            output.innerText = 'Executing query...';

            try {
                const res = await fetch('/api/graphql', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query }),
                });
                const data = await res.json();
                output.innerText = JSON.stringify(data, null, 2);
            } catch (err) {
                output.innerText = 'Error executing GraphQL: ' + err.message;
            }
        }

        setInterval(refreshData, 3000);
        refreshData();
    </script>
</body>
</html>
"""


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class DashboardRequestHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD_TEMPLATE.encode("utf-8"))

        elif parsed.path == "/api/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            metrics = self.server.orchestrator.get_system_metrics()  # type: ignore
            universes = [u.to_dict() for u in self.server.orchestrator.list_universes(limit=50)]  # type: ignore

            payload = {
                "metrics": metrics,
                "universes": universes,
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))

        elif parsed.path == "/api/topology":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            topo = self.server.mesh_manager.get_mesh_topology()  # type: ignore
            self.wfile.write(json.dumps(topo).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/graphql":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            
            try:
                payload = json.loads(body)
                query_str = payload.get("query", "")
                variables = payload.get("variables", {})

                res = self.server.graphql_api.execute(query_str, variables)  # type: ignore

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(res).encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"errors": [{"message": str(e)}]}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class DashboardServer:
    """
    Http Server for Web-Based Visualization Dashboard.
    """

    def __init__(
        self,
        orchestrator: UniverseOrchestrator,
        mesh_manager: MeshNetworkManager,
        host: str = "127.0.0.1",
        port: int = 8080,
    ):
        self.orchestrator = orchestrator
        self.mesh_manager = mesh_manager
        self.graphql_api = GodModeGraphQLAPI(orchestrator, mesh_manager)
        self.host = host
        self.port = port
        self.httpd: Optional[ReusableTCPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Starts the dashboard server in a non-blocking background thread."""
        self.httpd = ReusableTCPServer((self.host, self.port), DashboardRequestHandler)
        self.httpd.orchestrator = self.orchestrator  # type: ignore
        self.httpd.mesh_manager = self.mesh_manager  # type: ignore
        self.httpd.graphql_api = self.graphql_api  # type: ignore

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def start_blocking(self):
        """Starts the dashboard server in blocking mode."""
        self.httpd = ReusableTCPServer((self.host, self.port), DashboardRequestHandler)
        self.httpd.orchestrator = self.orchestrator  # type: ignore
        self.httpd.mesh_manager = self.mesh_manager  # type: ignore
        self.httpd.graphql_api = self.graphql_api  # type: ignore
        self.httpd.serve_forever()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
