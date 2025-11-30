#!/usr/bin/env python3

import sqlite3
import hashlib
import secrets
import sys
import os
import subprocess
import getpass
import argparse
from time import sleep

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "forwarder.db")
SERVICE_NAME = "Rahgozar"

class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_msg(msg, type="info"):
    if type == "info": print(f"{Color.BLUE}[INFO]{Color.ENDC} {msg}")
    elif type == "ok": print(f"{Color.GREEN}[OK]{Color.ENDC} {msg}")
    elif type == "err": print(f"{Color.FAIL}[ERROR]{Color.ENDC} {msg}")
    elif type == "warn": print(f"{Color.WARNING}[WARN]{Color.ENDC} {msg}")

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        with get_db() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)""")
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
            conn.execute("""CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, created_at INTEGER)""")
    except Exception as e:
        print_msg(f"Database initialization failed: {e}", "err")

def hash_password(password):
    salt = secrets.token_hex(8)
    hash_obj = hashlib.sha256((password + salt).encode())
    return hash_obj.hexdigest(), salt

def add_user(username, password):
    ph, salt = hash_password(password)
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, ph, salt))
        print_msg(f"User '{username}' added successfully.", "ok")
    except sqlite3.IntegrityError:
        print_msg(f"User '{username}' already exists.", "err")
    except Exception as e:
        print_msg(f"Error adding user: {e}", "err")

def delete_user(username):
    try:
        with get_db() as conn:
            cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            if cursor.rowcount > 0:
                print_msg(f"User '{username}' deleted.", "ok")
            else:
                print_msg(f"User '{username}' not found.", "warn")
    except Exception as e:
        print_msg(f"Error deleting user: {e}", "err")

def list_users():
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT username FROM users")
            users = cursor.fetchall()
            if not users:
                print(f"  {Color.WARNING}(No users found){Color.ENDC}")
            else:
                print(f"\n{Color.HEADER}--- Current Users ---{Color.ENDC}")
                for idx, row in enumerate(users, 1):
                    print(f"  {idx}. {Color.CYAN}{row['username']}{Color.ENDC}")
                print("")
    except Exception as e:
        print_msg(f"Error listing users: {e}", "err")

def get_service_status():
    try:
        result = subprocess.check_output(["systemctl", "is-active", SERVICE_NAME], stderr=subprocess.STDOUT)
        status = result.decode().strip()
        
        if status == "active":
            return f"{Color.GREEN}ACTIVE{Color.ENDC}"
        elif status == "inactive":
            return f"{Color.FAIL}STOPPED{Color.ENDC}"
        elif status == "failed":
            return f"{Color.FAIL}FAILED{Color.ENDC}"
        else:
            return f"{Color.WARNING}{status.upper()}{Color.ENDC}"
    except subprocess.CalledProcessError:
        return f"{Color.FAIL}NOT FOUND / ERROR{Color.ENDC}"
    except FileNotFoundError:
        return f"{Color.FAIL}SYSTEMCTL MISSING{Color.ENDC}"

def control_service(action):
    valid_actions = ["start", "stop", "restart"]
    if action not in valid_actions:
        return

    print_msg(f"Attempting to {action} {SERVICE_NAME}...", "info")
    
    try:
        subprocess.run(["systemctl", action, SERVICE_NAME], check=True)
        print_msg(f"Command '{action}' sent successfully.", "ok")
        sleep(1.5) 
    except subprocess.CalledProcessError:
        print_msg(f"Failed to {action} service. Do you have sudo privileges?", "err")
    except Exception as e:
        print_msg(f"Error: {e}", "err")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    clear_screen()
    status = get_service_status()
    print(f"{Color.CYAN}")
    print(r"""
██████╗  █████╗ ██╗  ██╗ ██████╗  ██████╗ ███████╗ █████╗ ██████╗ 
██╔══██╗██╔══██╗██║  ██║██╔════╝ ██╔═══██╗╚══███╔╝██╔══██╗██╔══██╗
██████╔╝███████║███████║██║  ███╗██║   ██║  ███╔╝ ███████║██████╔╝
██╔══██╗██╔══██║██╔══██║██║   ██║██║   ██║ ███╔╝  ██╔══██║██╔══██╗
██║  ██║██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████╗██║  ██║██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝                                                                     
    """)
    print(f"{Color.ENDC}")
    print(f"{Color.HEADER}Rahgozar Service Manager{Color.ENDC}")
    print(f"Service Name: {Color.BOLD}{SERVICE_NAME}{Color.ENDC}")
    print(f"Current Status: {status}")
    print("-" * 50)

def interactive_menu():
    while True:
        show_banner()
        
        print(f"{Color.BOLD}1){Color.ENDC} Start Service")
        print(f"{Color.BOLD}2){Color.ENDC} Stop Service")
        print(f"{Color.BOLD}3){Color.ENDC} Restart Service")
        print(f"{Color.BOLD}4){Color.ENDC} Add Admin User")
        print(f"{Color.BOLD}5){Color.ENDC} Delete Admin User")
        print(f"{Color.BOLD}6){Color.ENDC} List Users")
        print(f"{Color.BOLD}7){Color.ENDC} Exit")
        print("-" * 50)
        
        choice = input(f"{Color.GREEN}Select option > {Color.ENDC}").strip()

        if choice == "1":
            control_service("start")
        elif choice == "2":
            control_service("stop")
        elif choice == "3":
            control_service("restart")
        
        elif choice == "4":
            print(f"\n{Color.HEADER}--- Add User ---{Color.ENDC}")
            u = input("Username: ").strip()
            if u:
                p = getpass.getpass("Password: ").strip()
                p2 = getpass.getpass("Confirm Password: ").strip()
                if p != p2: print_msg("Passwords do not match!", "err")
                elif not p: print_msg("Password cannot be empty.", "err")
                else: add_user(u, p)
            input("Press Enter to continue...")

        elif choice == "5":
            print(f"\n{Color.HEADER}--- Delete User ---{Color.ENDC}")
            list_users()
            u = input("Enter username to delete: ").strip()
            if u: delete_user(u)
            input("Press Enter to continue...")

        elif choice == "6":
            list_users()
            input("Press Enter to continue...")

        elif choice == "7":
            print(f"{Color.CYAN}Goodbye!{Color.ENDC}")
            sys.exit(0)
        else:
            print_msg("Invalid selection.", "warn")
            sleep(1)

if __name__ == "__main__":
    init_db()

    parser = argparse.ArgumentParser(description="Rahgozar Manager CLI")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("start", help="Start Rahgozar service")
    subparsers.add_parser("stop", help="Stop Rahgozar service")
    subparsers.add_parser("restart", help="Restart Rahgozar service")
    subparsers.add_parser("status", help="Check service status")

    add_parser = subparsers.add_parser("add", help="Add a new user")
    add_parser.add_argument("username", type=str)
    add_parser.add_argument("password", type=str)

    del_parser = subparsers.add_parser("del", help="Delete a user")
    del_parser.add_argument("username", type=str)

    args = parser.parse_args()

    if args.command == "start":
        control_service("start")
    elif args.command == "stop":
        control_service("stop")
    elif args.command == "restart":
        control_service("restart")
    elif args.command == "status":
        print(get_service_status())
    elif args.command == "add":
        add_user(args.username, args.password)
    elif args.command == "del":
        delete_user(args.username)
    else:
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print(f"\n{Color.CYAN}Exiting.{Color.ENDC}")
            sys.exit(0)
