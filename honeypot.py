"""
honeypot.py — Main SSH honeypot server using Paramiko.

Usage:
    python honeypot.py [--port PORT] [--host HOST]
    python honeypot.py --clear-db

Default: listens on 0.0.0.0:2222
"""

from __future__ import annotations

import argparse
import socket
import threading
import time
import sys
import os
import logging
from pathlib import Path

import paramiko

import logger as log_db
from shell import FakeShell
from filesystem import SSH_PASSWORD

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("honeypot")
paramiko.util.log_to_file(os.devnull)   # silence paramiko noise

# ---------------------------------------------------------------------------
# Generate (or load) the server RSA host key
# ---------------------------------------------------------------------------
HOST_KEY_PATH = Path(__file__).parent / "server.key"

def _get_host_key() -> paramiko.RSAKey:
    if HOST_KEY_PATH.exists():
        return paramiko.RSAKey(filename=str(HOST_KEY_PATH))
    log.info("Generating new RSA host key …")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_PATH))
    log.info(f"Host key saved to {HOST_KEY_PATH}")
    return key

HOST_KEY = _get_host_key()

# ---------------------------------------------------------------------------
# SSH Server Interface (auth + channel routing)
# ---------------------------------------------------------------------------
BANNER = (
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
)

class HoneypotServerInterface(paramiko.ServerInterface):
    """Handles Paramiko auth callbacks for one client connection."""

    def __init__(self, client_ip: str, client_port: int):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.attempt_id: int | None = None
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        success = (password == SSH_PASSWORD)
        self.attempt_id = log_db.log_attempt(
            self.client_ip, self.client_port, username, password, success
        )
        if success:
            log.info(f"✅  AUTH SUCCESS  {self.client_ip}:{self.client_port}  user={username!r}  pass={password!r}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            log.info(f"❌  AUTH FAIL     {self.client_ip}:{self.client_port}  user={username!r}  pass={password!r}")
            time.sleep(0.5)   # rate-limit brute-force
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        # Log the attempt, reject it
        self.attempt_id = log_db.log_attempt(
            self.client_ip, self.client_port, username, f"<pubkey:{key.get_name()}>", False
        )
        log.info(f"🔑  PUBKEY ATTEMPT {self.client_ip}  user={username!r}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        # Allow exec requests (e.g. scp, sftp-server) — just reject silently
        return False


# ---------------------------------------------------------------------------
# Per-client handler thread
# ---------------------------------------------------------------------------

def handle_client(client_sock: socket.socket, client_addr: tuple):
    client_ip, client_port = client_addr
    log.info(f"🔌  New connection from {client_ip}:{client_port}")

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = BANNER
        transport.add_server_key(HOST_KEY)

        server_iface = HoneypotServerInterface(client_ip, client_port)
        transport.start_server(server=server_iface)

        # Wait for the client to open a channel (30 s timeout)
        channel = transport.accept(30)
        if channel is None:
            log.info(f"⚠️   No channel opened by {client_ip}:{client_port}")
            return

        # Wait for the shell request (10 s timeout)
        server_iface.event.wait(10)

        # Open logging session
        session_id = log_db.open_session(server_iface.attempt_id)
        log.info(f"🖥️   Shell session #{session_id} opened for {client_ip}:{client_port}")

        # Hand off to the fake shell
        shell = FakeShell(
            session_id=session_id,
            client_ip=client_ip,
            send=channel.send,
        )
        shell.greet()

        channel.setblocking(False)

        while shell.is_running and transport.is_active():
            try:
                data = channel.recv(256)
                if not data:
                    break
                shell.feed(data)
            except socket.timeout:
                pass
            except Exception:
                break
            time.sleep(0.01)

    except Exception as exc:
        log.warning(f"⚠️   Error handling {client_ip}: {exc}")
    finally:
        try:
            log_db.close_session(session_id)
        except Exception:
            pass
        if transport:
            transport.close()
        client_sock.close()
        log.info(f"🔌  Connection closed: {client_ip}:{client_port}")


# ---------------------------------------------------------------------------
# Main server loop
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CTF SSH Honeypot")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=2222,  help="SSH port (default: 2222)")
    parser.add_argument("--clear-db", action="store_true", help="Wipe all data from the database and exit")
    args = parser.parse_args()

    if args.clear_db:
        log_db.init_db()
        log_db.clear_db()
        log.info("🗑️   Database cleared — all attempts, sessions and commands deleted.")
        return

    log_db.init_db()
    log.info(f"🍯  SSH Honeypot starting on {args.host}:{args.port}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen(100)

    log.info(f"🍯  Listening for connections …")
    log.info(f"📊  Dashboard: http://127.0.0.1:8080")
    log.info(f"    (run dashboard/app.py in a separate terminal)")

    try:
        while True:
            client_sock, client_addr = server_sock.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
