# Rahgozar
import asyncio
import logging
import socket
import sys
import time
from requests import get
import aiosqlite

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    print("[CORE] UVLoop optimization enabled.")
except ImportError:
    print("[CORE] UVLoop not found. Using standard asyncio.")

DB_NAME = "forwarder.db"
POLL_INTERVAL = 3
SAVE_INTERVAL = 5
SOCKET_BUF_SIZE = 512 * 1024

logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(message)s')

try:
    PUBLIC_IP = get('https://api.ipify.org', timeout=3).text
except:
    PUBLIC_IP = "127.0.0.1"

class BridgeProtocol(asyncio.Protocol):
    def __init__(self):
        self.peer: asyncio.Protocol = None
        self.transport = None
        self.buffer = []
        self.paused = False

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info('socket')
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUF_SIZE)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUF_SIZE)
        except:
            pass

    def data_received(self, data):
        if self.peer and self.peer.transport:
            self.peer.transport.write(data)
            TrafficController.add_usage(len(data))
        else:
            self.buffer.append(data)

    def connection_lost(self, exc):
        if self.peer and self.peer.transport:
            self.peer.transport.close()

class TargetProtocol(BridgeProtocol):
    def __init__(self, client_protocol, on_connect_event):
        super().__init__()
        self.peer = client_protocol
        self.on_connect_event = on_connect_event

    def connection_made(self, transport):
        super().connection_made(transport)
        self.peer.peer = self
        
        if self.peer.buffer:
            for chunk in self.peer.buffer:
                self.transport.write(chunk)
            self.peer.buffer = []
        
        self.on_connect_event.set()

class ClientProtocol(BridgeProtocol):
    def __init__(self, target_ip, target_port, loop):
        super().__init__()
        self.target_ip = target_ip
        self.target_port = target_port
        self.loop = loop
        self.connected_event = asyncio.Event()

    def connection_made(self, transport):
        super().connection_made(transport)
        task = self.loop.create_task(self.connect_to_target())

    async def connect_to_target(self):
        try:
            await self.loop.create_connection(
                lambda: TargetProtocol(self, self.connected_event),
                self.target_ip, 
                self.target_port
            )
        except Exception:
            self.transport.close()

class TrafficController:
    pending_bytes = 0
    
    @classmethod
    def add_usage(cls, amount):
        cls.pending_bytes += amount

    @classmethod
    def flush(cls):
        val = cls.pending_bytes
        cls.pending_bytes = 0
        return val

class Core:
    def __init__(self):
        self.servers = {}
        self.loop = asyncio.get_event_loop()
        self.active_config = {}

    async def get_rules(self):
        try:
            async with aiosqlite.connect(DB_NAME) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("SELECT * FROM rules WHERE active=1") as cur:
                    rows = await cur.fetchall()
                    return {r['id']: dict(r) for r in rows}
        except:
            return {}

    async def stats_saver(self):
        while True:
            await asyncio.sleep(SAVE_INTERVAL)
            usage = TrafficController.flush()
            if usage > 0:
                try:
                    async with aiosqlite.connect(DB_NAME) as db:
                        await db.execute("UPDATE rules SET bytes_used = bytes_used + ? WHERE active=1", (usage // len(self.servers) if self.servers else 0,))
                        await db.commit()
                except: pass

    def start_server_protocol(self, r_id, port, t_ip, t_port):
        def client_factory():
            return ClientProtocol(t_ip, t_port, self.loop)

        coro = self.loop.create_server(
            client_factory, 
            '0.0.0.0', 
            port, 
            reuse_port=True,
            backlog=4096
        )
        server = self.loop.run_until_complete(coro)
        self.servers[r_id] = server
        self.active_config[r_id] = (port, t_ip, t_port)
        print(f"[+] Started {port} -> {t_ip}:{t_port}")

    def stop_server(self, r_id):
        if r_id in self.servers:
            self.servers[r_id].close()
            del self.servers[r_id]
            del self.active_config[r_id]

    async def monitor(self):
        print(f"[CORE] Running on {PUBLIC_IP}")
        while True:
            rules = await self.get_rules()
            
            for rid, r in rules.items():
                cfg = (r['listen_port'], r['target_ip'], r['target_port'])
                
                valid = True
                if r['limit_bytes'] and r['bytes_used'] >= r['limit_bytes']: valid = False
                if r['expiry_date'] and time.time() > r['expiry_date']: valid = False

                if valid:
                    if rid not in self.servers:
                        self.start_server_protocol(rid, *cfg)
                    elif self.active_config[rid] != cfg:
                        self.stop_server(rid)
                        self.start_server_protocol(rid, *cfg)
                else:
                    if rid in self.servers: self.stop_server(rid)

            active_ids = list(self.servers.keys())
            for rid in active_ids:
                if rid not in rules:
                    self.stop_server(rid)

            await asyncio.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    core = Core()
    core.loop.create_task(core.stats_saver())
    core.loop.run_until_complete(core.monitor())