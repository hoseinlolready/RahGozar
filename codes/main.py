#!/usr/bin/env python3

import sys
import os
import subprocess
import time
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PANEL_SCRIPT = os.path.join(BASE_DIR, "panel.py")
CORE_SCRIPT = os.path.join(BASE_DIR, "Rahgozar_Core_AMD64")

p_panel = None
p_core = None
running = True

def log(msg):
    print(f"[Rahgozar Runner] {msg}", flush=True)

def cleanup_processes():
    global p_panel, p_core
    
    procs = [p for p in [p_panel, p_core] if p is not None]
    
    if not procs:
        return

    log("Stopping services...")
    
    for p in procs:
        if p.poll() is None:
            p.terminate()

    start_wait = time.time()
    while time.time() - start_wait < 3:
        if all(p.poll() is not None for p in procs):
            break
        time.sleep(0.1)

    for p in procs:
        if p.poll() is None:
            log(f"Process {p.pid} did not exit, forcing kill.")
            p.kill()

def handle_signal(signum, frame):
    global running
    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    log(f"Received {sig_name}. Shutting down...")
    running = False

def start_services():
    global p_panel, p_core, running

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    log(f"Starting services from {BASE_DIR}...")

    try:
        p_panel = subprocess.Popen(
            [sys.executable, PANEL_SCRIPT], 
            stdout=sys.stdout, 
            stderr=sys.stderr
        )
        p_core = subprocess.Popen(
            [sys.executable, CORE_SCRIPT], 
            stdout=sys.stdout, 
            stderr=sys.stderr
        )

        log(f"Panel PID: {p_panel.pid}, Core PID: {p_core.pid}")

        while running:
            panel_status = p_panel.poll()
            core_status = p_core.poll()
            if panel_status is not None:
                log(f"CRITICAL: Panel script exited unexpectedly (Code: {panel_status}).")
                running = False
            
            if core_status is not None:
                log(f"CRITICAL: Core script exited unexpectedly (Code: {core_status}).")
                running = False

            time.sleep(1)

    except Exception as e:
        log(f"Runner Error: {e}")
    finally:
        cleanup_processes()
        log("Exited.")
        sys.exit(0)

if __name__ == "__main__":
    start_services()
