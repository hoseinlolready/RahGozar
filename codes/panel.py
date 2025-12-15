# Rahgozar
import sqlite3
import json
import hashlib
import secrets
import sys
import time
import os
from http.server import BaseHTTPRequestHandler , ThreadingHTTPServer
from http import cookies
from datetime import datetime
import urllib.request

try:
    with urllib.request.urlopen('https://api.ipify.org', timeout=3) as response:
        ip = response.read().decode('utf-8')
except:
    ip = "127.0.0.1"
DB_NAME = "forwarder.db"
PORT = 9090

def get_system_stats():
    mem_str = "N/A"
    mem_pct = 0
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()
            info = {}
            for line in lines:
                parts = line.split(':')
                if len(parts) == 2:
                    info[parts[0].strip()] = int(parts[1].strip().split()[0])
            total = info.get('MemTotal', 1)
            available = info.get('MemAvailable', 0)
            used = total - available
            gb_used = round(used / 1024 / 1024, 2)
            gb_total = round(total / 1024 / 1024, 2)
            mem_str = f"{gb_used} GB / {gb_total} GB"
            mem_pct = int((used / total) * 100)
    except: pass
    return {"text": mem_str, "percent": mem_pct}

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                listen_port INTEGER UNIQUE,
                target_ip TEXT,
                target_port INTEGER,
                limit_bytes INTEGER,
                bytes_used INTEGER DEFAULT 0,
                expiry_date INTEGER,
                note TEXT,
                active BOOLEAN DEFAULT 1,
                created_at INTEGER
            )
        """)
        conn.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, created_at INTEGER)")

def verify_password(stored_hash, salt, provided_password):
    hash_obj = hashlib.sha256((provided_password + salt).encode())
    return hash_obj.hexdigest() == stored_hash

HTML_UI = """
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rahgozar Panel</title>
    <link rel="icon" type="image/x-icon" href="https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/assest/RahGozar.png">
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <!-- CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #6366f1; /* Indigo */
            --accent-hover: #4f46e5;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --glass-bg: rgba(30, 41, 59, 0.7);
            --glass-border: rgba(255, 255, 255, 0.05);
        }

        body {
            background-color: var(--bg-dark);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            background-image: radial-gradient(circle at top right, #1e1b4b 0%, transparent 40%), radial-gradient(circle at bottom left, #1e1b4b 0%, transparent 40%);
            min-height: 100vh;
        }

        .navbar {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--glass-border);
            padding: 1rem 0;
        }
        .navbar-brand { font-weight: 700; letter-spacing: -0.5px; font-size: 1.25rem; }
        .navbar-brand img { border-radius: 8px; }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            transition: transform 0.2s;
        }
        
        .stat-card { padding: 1.5rem; display: flex; align-items: center; gap: 1.5rem; }
        .stat-icon-box {
            width: 56px; height: 56px;
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.75rem;
        }
        .icon-blue { background: rgba(59, 130, 246, 0.1); color: #3b82f6; }
        .icon-purple { background: rgba(168, 85, 247, 0.1); color: #a855f7; }
        .icon-green { background: rgba(16, 185, 129, 0.1); color: #10b981; }
        .stat-info h6 { color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
        .stat-info h3 { margin: 0; font-weight: 700; letter-spacing: -0.5px; }

        .custom-table-container {
            background: var(--bg-card);
            border-radius: 16px;
            border: 1px solid var(--glass-border);
            overflow: hidden;
        }
        .table { margin-bottom: 0; color: var(--text-primary); vertical-align: middle; }
        .table thead th {
            background: rgba(15, 23, 42, 0.5);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--glass-border);
            padding: 1rem 1.5rem;
        }
        .table tbody td { padding: 1rem 1.5rem; border-bottom: 1px solid var(--glass-border); }
        .table tbody tr:last-child td { border-bottom: none; }
        .table tbody tr:hover { background: rgba(255,255,255,0.02); }

        .badge-status {
            padding: 0.35em 0.8em;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 0.75rem;
        }
        .badge-active { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.2); }
        .badge-inactive { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.2); }
        .badge-expired { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.2); }

        .port-tag { font-family: 'Monaco', 'Consolas', monospace; color: var(--accent); background: rgba(99, 102, 241, 0.1); padding: 2px 6px; border-radius: 4px; font-size: 0.9rem; }

        .progress-wrapper { min-width: 120px; }
        .progress { height: 6px; background: rgba(255,255,255,0.1); border-radius: 10px; overflow: hidden; margin-bottom: 4px; }
        .progress-bar { background: linear-gradient(90deg, var(--accent), #818cf8); border-radius: 10px; }
        .progress-text { font-size: 0.75rem; color: var(--text-secondary); }

        .btn-primary { background: var(--accent); border: none; font-weight: 500; padding: 0.6rem 1.2rem; border-radius: 10px; }
        .btn-primary:hover { background: var(--accent-hover); }
        
        .btn-icon { 
            width: 32px; height: 32px; 
            border-radius: 8px; 
            display: inline-flex; align-items: center; justify-content: center; 
            color: var(--text-secondary); 
            transition: all 0.2s;
            border: 1px solid transparent;
            background: transparent;
        }
        .btn-icon:hover { background: rgba(255,255,255,0.05); color: #fff; border-color: var(--glass-border); }
        .btn-icon.delete:hover { background: rgba(239, 68, 68, 0.1); color: var(--danger); border-color: rgba(239, 68, 68, 0.2); }
        .btn-icon.edit:hover { background: rgba(99, 102, 241, 0.1); color: var(--accent); border-color: rgba(99, 102, 241, 0.2); }

        .form-control, .form-select {
            background: #0f172a; border: 1px solid var(--glass-border); color: #fff; border-radius: 10px; padding: 0.7rem 1rem;
        }
        .form-control:focus { background: #0f172a; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2); color: #fff; }

        .login-card {
            background: rgba(30, 41, 59, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        
        .modal-content { background: var(--bg-card); border: 1px solid var(--glass-border); border-radius: 16px; }
        .modal-header { border-bottom: 1px solid var(--glass-border); }
        .modal-footer { border-top: 1px solid var(--glass-border); }
        .btn-close { filter: invert(1); }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg sticky-top">
    <div class="container-fluid px-4">
        <a class="navbar-brand d-flex align-items-center gap-2" href="#">
            <img src="https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/assest/RahGozar.png" width="40" height="40">
            <span style="background: linear-gradient(to right, #fff, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">RahGozar</span>
        </a>
        <button class="btn btn-sm btn-outline-danger border-0 bg-danger bg-opacity-10 text-danger d-none" id="logout-btn" onclick="logout()">
            <i class="bi bi-box-arrow-right me-1"></i> Logout
        </button>
    </div>
</nav>

<div id="login-view" class="container d-flex align-items-center justify-content-center" style="min-height: 80vh;">
    <div class="col-md-4">
        <div class="card login-card p-4">
            <div class="text-center mb-4">
                <img src="https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/assest/RahGozar.png" width="80" class="mb-3 rounded-3 shadow-lg">
                <h4 class="fw-bold">Welcome Back</h4>
                <p class="text-secondary small">Sign in to manage your tunnels</p>
            </div>
            <div class="mb-3">
                <label class="form-label text-secondary small">Username</label>
                <div class="input-group">
                    <span class="input-group-text bg-transparent border-secondary border-opacity-25 text-secondary"><i class="bi bi-person"></i></span>
                    <input type="text" id="l_user" class="form-control border-start-0 ps-0" placeholder="Admin">
                </div>
            </div>
            <div class="mb-4">
                <label class="form-label text-secondary small">Password</label>
                <div class="input-group">
                    <span class="input-group-text bg-transparent border-secondary border-opacity-25 text-secondary"><i class="bi bi-key"></i></span>
                    <input type="password" id="l_pass" class="form-control border-start-0 ps-0" placeholder="••••••">
                </div>
            </div>
            <button onclick="login()" class="btn btn-primary w-100 py-2 shadow-lg">Sign In</button>
        </div>
    </div>
</div>

<div id="dashboard-view" class="container-fluid px-4 py-4 d-none">
    
    <div class="row g-4 mb-4">
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="stat-icon-box icon-blue"><i class="bi bi-hdd-network"></i></div>
                <div class="stat-info">
                    <h6>Active Tunnels</h6>
                    <h3 id="stat-active">0</h3>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="stat-icon-box icon-purple"><i class="bi bi-activity"></i></div>
                <div class="stat-info">
                    <h6>Total Traffic</h6>
                    <h3 id="stat-traffic">0 GB</h3>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card">
                <div class="stat-icon-box icon-green"><i class="bi bi-memory"></i></div>
                <div class="stat-info">
                    <h6>Memory Usage</h6>
                    <h3 id="stat-mem">Loading...</h3>
                    <div class="progress mt-2" style="height: 4px; width: 100px;">
                        <div class="progress-bar bg-success" id="stat-mem-bar" style="width: 0%"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="d-flex justify-content-between align-items-center mb-4">
        <div class="position-relative w-100" style="max-width: 400px;">
            <i class="bi bi-search position-absolute text-secondary" style="left: 15px; top: 10px;"></i>
            <input type="text" id="search-input" onkeyup="filterTable()" class="form-control ps-5" placeholder="Search users, ports...">
        </div>
        <button class="btn btn-primary shadow-sm" data-bs-toggle="modal" data-bs-target="#createModal">
            <i class="bi bi-plus-lg me-2"></i>Create Tunnel
        </button>
    </div>

    <div class="custom-table-container">
        <div class="table-responsive">
            <table class="table">
                <thead>
                    <tr>
                        <th>User / Port</th>
                        <th>Destination</th>
                        <th>Data Usage</th>
                        <th>Expiry</th>
                        <th>Status</th>
                        <th class="text-end">Actions</th>
                    </tr>
                </thead>
                <tbody id="rules-table"></tbody>
            </table>
        </div>
    </div>
</div>

<div class="modal fade" id="createModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content p-3">
            <div class="modal-header border-0 pb-0">
                <h5 class="modal-title fw-bold">New Tunnel</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="createForm">
                    <label class="form-label small text-secondary text-uppercase fw-bold">Identity</label>
                    <div class="input-group mb-3">
                        <input type="text" id="m_username" class="form-control" required placeholder="Username">
                        <button class="btn btn-outline-secondary border-secondary border-opacity-25" type="button" onclick="genUsername('m_username')"><i class="bi bi-magic"></i></button>
                    </div>

                    <div class="row g-3 mb-3">
                         <div class="col-6">
                            <label class="form-label small text-secondary text-uppercase fw-bold">Listen Port</label>
                            <input type="number" id="m_lport" class="form-control" required placeholder="8080">
                        </div>
                        <div class="col-6">
                            <label class="form-label small text-secondary text-uppercase fw-bold">Data Limit</label>
                            <div class="input-group">
                                <input type="number" id="m_limit" class="form-control" value="10">
                                <span class="input-group-text bg-transparent border-secondary border-opacity-25 text-secondary">GB</span>
                            </div>
                        </div>
                    </div>

                    <label class="form-label small text-secondary text-uppercase fw-bold">Destination</label>
                    <div class="input-group mb-3">
                        <input type="text" id="m_tip" class="form-control" placeholder="IP (e.g. 1.1.1.1)">
                        <span class="input-group-text bg-transparent border-secondary border-opacity-25 text-secondary">:</span>
                        <input type="number" id="m_tport" class="form-control" placeholder="Port" style="max-width: 90px;">
                    </div>

                    <div class="mb-3">
                        <label class="form-label small text-secondary text-uppercase fw-bold">Expiration</label>
                        <input type="date" id="m_expiry" class="form-control">
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label small text-secondary text-uppercase fw-bold">Note</label>
                        <textarea id="m_note" class="form-control" rows="2" placeholder="Optional remarks..."></textarea>
                    </div>
                    
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="m_active" checked>
                        <label class="form-check-label text-secondary">Enable Tunnel</label>
                    </div>
                </form>
            </div>
            <div class="modal-footer border-0 pt-0">
                <button type="button" class="btn btn-link text-secondary text-decoration-none" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary px-4" onclick="createRule()">Create</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="editModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content p-3">
            <div class="modal-header border-0 pb-0">
                <h5 class="modal-title fw-bold">Edit Tunnel</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="e_id">
                <div class="mb-3">
                    <label class="form-label small text-secondary">Username</label>
                    <input type="text" id="e_username" class="form-control" required>
                </div>
                <div class="row g-3 mb-3">
                     <div class="col-6">
                        <label class="form-label small text-secondary">Listen Port</label>
                        <input type="number" id="e_lport" class="form-control" required>
                    </div>
                    <div class="col-6">
                        <label class="form-label small text-secondary">Limit (GB)</label>
                        <input type="number" id="e_limit" class="form-control" required>
                    </div>
                </div>
                <div class="input-group mb-3">
                    <input type="text" id="e_tip" class="form-control" placeholder="IP">
                    <span class="input-group-text bg-transparent border-secondary border-opacity-25 text-secondary">:</span>
                    <input type="number" id="e_tport" class="form-control" placeholder="Port" style="max-width: 90px;">
                </div>
                <div class="mb-3">
                    <label class="form-label small text-secondary">Expiration</label>
                    <input type="date" id="e_expiry" class="form-control">
                </div>
                <div class="mb-3">
                    <label class="form-label small text-secondary">Note</label>
                    <textarea id="e_note" class="form-control" rows="2"></textarea>
                </div>
                <div class="form-check form-switch">
                    <input class="form-check-input" type="checkbox" id="e_active">
                    <label class="form-check-label text-secondary">Active</label>
                </div>
            </div>
            <div class="modal-footer border-0 pt-0">
                <button type="button" class="btn btn-link text-secondary text-decoration-none" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary px-4" onclick="saveEdit()">Save Changes</button>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function genUsername(id) {
    document.getElementById(id).value = 'User_' + Math.random().toString(36).substr(2, 6).toUpperCase();
}

async function api(endpoint, method="GET", body=null) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    try {
        const res = await fetch(endpoint, opts);
        if (res.status === 401) { showLogin(); return null; }
        return res.json();
    } catch(e) { return null; }
}

function showLogin() {
    document.getElementById('login-view').classList.remove('d-none');
    document.getElementById('dashboard-view').classList.add('d-none');
    document.getElementById('logout-btn').classList.add('d-none');
}

function showDash() {
    document.getElementById('login-view').classList.add('d-none');
    document.getElementById('dashboard-view').classList.remove('d-none');
    document.getElementById('logout-btn').classList.remove('d-none');
    loadData();
}

async function login() {
    const u = document.getElementById('l_user').value;
    const p = document.getElementById('l_pass').value;
    const res = await api('/api/login', 'POST', { u, p });
    if (res && res.success) showDash();
    else alert('Invalid Credentials');
}

async function logout() {
    try { await api('/api/logout', 'POST'); } catch(e) {}
    document.cookie = "token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;";
    showLogin();
}

let allRules = [];

async function loadData() {
    const res = await api('/api/rules');
    if (!res) return;
    
    if (res.sys) {
        document.getElementById('stat-mem').innerText = res.sys.text;
        document.getElementById('stat-mem-bar').style.width = res.sys.percent + "%";
    }

    allRules = res.rules;
    renderTable(allRules);
}

function renderTable(rules) {
    const tbody = document.getElementById('rules-table');
    let totalBytes = 0;
    let activeCount = 0;

    tbody.innerHTML = rules.map(r => {
        totalBytes += r.bytes_used;
        if(r.active) activeCount++;

        const pct = r.limit_bytes > 0 ? Math.min((r.bytes_used / r.limit_bytes) * 100, 100) : 0;
        const isExpired = r.expiry_date && (Date.now()/1000 > r.expiry_date);
        
        let statusBadge = '<span class="badge badge-status badge-active">Active</span>';
        if (!r.active) statusBadge = '<span class="badge badge-status badge-inactive">Disabled</span>';
        else if (isExpired) statusBadge = '<span class="badge badge-status badge-expired">Expired</span>';
        
        let expireText = r.expiry_date ? new Date(r.expiry_date*1000).toLocaleDateString() : '∞';

        return `
        <tr>
            <td>
                <div class="d-flex flex-column">
                    <span class="fw-semibold text-white">${r.username}</span>
                    <span class="port-tag mt-1 w-auto">:${r.listen_port}</span>
                </div>
            </td>
            <td>
                <div class="d-flex align-items-center text-secondary">
                    <i class="bi bi-arrow-right-short me-1"></i>
                    ${r.target_ip}:${r.target_port}
                </div>
            </td>
            <td>
                <div class="progress-wrapper">
                    <div class="d-flex justify-content-between progress-text mb-1">
                        <span>${formatBytes(r.bytes_used)}</span>
                        <span>${formatBytes(r.limit_bytes)}</span>
                    </div>
                    <div class="progress">
                        <div class="progress-bar" style="width: ${pct}%"></div>
                    </div>
                </div>
            </td>
            <td class="text-secondary small">${expireText}</td>
            <td>${statusBadge}</td>
            <td class="text-end">
                <button class="btn-icon edit" onclick="openEdit(${r.id})" title="Edit"><i class="bi bi-pencil"></i></button>
                <button class="btn-icon" onclick="resetRule(${r.id})" title="Reset"><i class="bi bi-arrow-clockwise"></i></button>
                <button class="btn-icon delete" onclick="delRule(${r.id})" title="Delete"><i class="bi bi-trash"></i></button>
            </td>
        </tr>
        `;
    }).join('');

    document.getElementById('stat-active').innerText = activeCount + " / " + rules.length;
    document.getElementById('stat-traffic').innerText = formatBytes(totalBytes);
}

function filterTable() {
    const term = document.getElementById('search-input').value.toLowerCase();
    const filtered = allRules.filter(r => 
        (r.username && r.username.toLowerCase().includes(term)) || 
        r.listen_port.toString().includes(term)
    );
    renderTable(filtered);
}

async function createRule() {
    const limitVal = parseFloat(document.getElementById('m_limit').value);
    const mult = 1024*1024*1024; // GB
    const expiryVal = document.getElementById('m_expiry').value; 
    const expiryTs = expiryVal ? new Date(expiryVal).getTime() / 1000 : 0;

    const body = {
        username: document.getElementById('m_username').value,
        listen_port: parseInt(document.getElementById('m_lport').value),
        target_ip: document.getElementById('m_tip').value,
        target_port: parseInt(document.getElementById('m_tport').value),
        limit_bytes: limitVal * mult,
        active: document.getElementById('m_active').checked,
        expiry_date: expiryTs,
        note: document.getElementById('m_note').value
    };

    const res = await api('/api/rules', 'POST', body);
    if(res && res.success) {
        bootstrap.Modal.getInstance(document.getElementById('createModal')).hide();
        document.getElementById('createForm').reset();
        loadData();
    } else {
        alert('Error: Port may be in use');
    }
}

function openEdit(id) {
    const r = allRules.find(x => x.id === id);
    if(!r) return;

    document.getElementById('e_id').value = r.id;
    document.getElementById('e_username').value = r.username;
    document.getElementById('e_lport').value = r.listen_port;
    document.getElementById('e_tip').value = r.target_ip;
    document.getElementById('e_tport').value = r.target_port;
    document.getElementById('e_active').checked = r.active;
    document.getElementById('e_note').value = r.note || '';
    
    let limit = r.limit_bytes / (1024*1024*1024);
    document.getElementById('e_limit').value = Math.round(limit);

    if(r.expiry_date) {
        document.getElementById('e_expiry').value = new Date(r.expiry_date * 1000).toISOString().split('T')[0];
    } else {
        document.getElementById('e_expiry').value = '';
    }

    new bootstrap.Modal(document.getElementById('editModal')).show();
}

async function saveEdit() {
    // 1. Handle Limit safely (prevent NaN crash)
    const limitVal = parseInt(document.getElementById('e_limit').value) || 0;

    const body = {
        id: parseInt(document.getElementById('e_id').value),
        username: document.getElementById('e_username').value,
        listen_port: parseInt(document.getElementById('e_lport').value),
        target_ip: document.getElementById('e_tip').value,
        target_port: parseInt(document.getElementById('e_tport').value),
        limit: limitVal, // Send 'limit' (Python handles GB conversion)
        active: document.getElementById('e_active').checked,
        expiry: document.getElementById('e_expiry').value, // Send date string (Python parses it)
        note: document.getElementById('e_note').value
    };

    const res = await api('/api/rules', 'PUT', body);
    
    if(res && res.success) {
        const modalEl = document.getElementById('editModal');
        const modal = bootstrap.Modal.getInstance(modalEl);
        if(modal) modal.hide();
        loadData();
    } else {
        // Show actual error from server
        alert('Error: ' + (res ? res.error : 'Unknown'));
    }
}

async function delRule(id) {
    if(confirm("Delete this tunnel?")) {
        await api('/api/rules', 'DELETE', { id });
        loadData();
    }
}
async function resetRule(id) {
    await api('/api/reset', 'POST', { id });
    loadData();
}

genUsername('m_username');
api('/api/check').then(r => { if(r && r.auth) showDash(); else showLogin(); });
setInterval(() => {
    if(!document.getElementById('dashboard-view').classList.contains('d-none')) loadData();
}, 3000);
</script>
</body>
</html>
"""

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        if getattr(self, 'path', '') == '/api/rules': return
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), format%args))

    def get_session(self):
        if 'Cookie' not in self.headers: return None
        c = cookies.SimpleCookie(self.headers['Cookie'])
        if 'token' not in c: return None
        token = c['token'].value
        with get_db() as conn:
            return conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()

    def send_json(self, data, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_UI.encode())
            return
        
        if self.path == '/api/check':
            self.send_json({'auth': self.get_session() is not None})
            return

        if not self.get_session(): return self.send_json({}, 401)

        if self.path == '/api/rules':
            stats = get_system_stats()
            with get_db() as conn:
                cur = conn.execute("SELECT * FROM rules ORDER BY created_at DESC")
                rules = [dict(row) for row in cur.fetchall()]
            self.send_json({'rules': rules, 'sys': stats})

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = {}
        if length > 0:
            try: body = json.loads(self.rfile.read(length))
            except: pass

        if self.path == '/api/login':
            with get_db() as conn:
                user = conn.execute("SELECT * FROM users WHERE username = ?", (body.get('u'),)).fetchone()
                if user and verify_password(user['password_hash'], user['salt'], body.get('p')):
                    token = secrets.token_hex(16)
                    conn.execute("INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)", 
                                (token, body.get('u'), int(time.time())))
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('Set-Cookie', f'token={token}; Path=/; Max-Age=2592000; SameSite=Lax')
                    self.end_headers()
                    self.wfile.write(json.dumps({'success': True}).encode())
                else:
                    self.send_json({'success': False}, 401)
            return

        if self.path == '/api/logout':
            if 'Cookie' in self.headers:
                c = cookies.SimpleCookie(self.headers['Cookie'])
                if 'token' in c:
                    with get_db() as conn:
                        conn.execute("DELETE FROM sessions WHERE token = ?", (c['token'].value,))
                        conn.commit()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Set-Cookie', 'token=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True}).encode())
            return

        if not self.get_session(): return self.send_json({}, 401)

        if self.path == '/api/rules':
            try:
                limit_val = body.get('limit') or 0
                limit_bytes = int(limit_val) * 1073741824
                
                exp = int(time.mktime(time.strptime(body['expiry'], '%Y-%m-%d'))) if body.get('expiry') else 0
                
                with get_db() as conn:
                    conn.execute(
                        """INSERT INTO rules (username, listen_port, target_ip, target_port, limit_bytes, active, expiry_date, note, created_at) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (body['username'], body['listen_port'], body['target_ip'], body['target_port'], 
                         limit_bytes, body['active'], exp, body['note'], int(time.time()))
                    )
                self.send_json({'success': True})
            except sqlite3.IntegrityError:
                self.send_json({'error': f"Port {body['listen_port']} is already in use by another rule."}, 409)
            except Exception as e:
                self.send_json({'error': str(e)}, 500)

        elif self.path == '/api/reset':
            with get_db() as conn: conn.execute("UPDATE rules SET bytes_used = 0 WHERE id = ?", (body['id'],))
            self.send_json({'success': True})

    def do_PUT(self):
        if not self.get_session(): return self.send_json({}, 401)
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length))
        
        if self.path == '/api/rules':
            try:
                limit_val = body.get('limit') or 0
                limit_bytes = int(limit_val) * 1073741824
                
                exp = int(time.mktime(time.strptime(body['expiry'], '%Y-%m-%d'))) if body.get('expiry') else 0
                
                with get_db() as conn:
                    conn.execute(
                        """INSERT INTO rules (username, listen_port, target_ip, target_port, limit_bytes, active, expiry_date, note, created_at) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (body['username'], body['listen_port'], body['target_ip'], body['target_port'], 
                         limit_bytes, body['active'], exp, body['note'], int(time.time()))
                    )
                self.send_json({'success': True})
            except sqlite3.IntegrityError:
                self.send_json({'error': f"Port {body['listen_port']} is already in use by another rule."}, 409)
            except Exception as e:
                self.send_json({'error': str(e)}, 500)

    def do_DELETE(self):
        if not self.get_session(): return self.send_json({}, 401)
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length))
        if self.path == '/api/rules':
            with get_db() as conn: conn.execute("DELETE FROM rules WHERE id = ?", (body['id'],))
            self.send_json({'success': True})

if __name__ == "__main__":
    init_db()
    print(f"RahGozar Panel running on http://Localhost:{PORT}")
    print(f"RahGozar Panel running on http://{ip}:{PORT}")
    try:
        ThreadingHTTPServer(('0.0.0.0', PORT), APIHandler).serve_forever()
    except KeyboardInterrupt:
        pass
