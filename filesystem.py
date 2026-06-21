"""
filesystem.py — Virtual filesystem definition for the SSH honeypot.

The flag is hidden at /home/admin/.secret, Base64-encoded.
The SSH password hint is embedded in /etc/motd.
"""

import base64

# --- Challenge config (edit these to customize) ---
SSH_PASSWORD = "h0n3yp0t"
FLAG         = "flag{y0u_f0und_th3_h1dd3n_k3y}"
# ---------------------------------------------------

# Encode the flag and password hint
_ENCODED_FLAG    = base64.b64encode(FLAG.encode()).decode()
_ENCODED_PASS    = base64.b64encode(SSH_PASSWORD.encode()).decode()

# Fake /etc/passwd content
_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
admin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash
"""

# Fake /etc/hostname
_HOSTNAME = "prod-srv-01\n"

# Fake /etc/motd — contains the password hint (Base64-encoded)
_MOTD = f"""\
 ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
 ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
 ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║   
 ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║   
 ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║   
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝   

 Welcome to prod-srv-01 — Authorized access only.

 Last login: Fri Jun  6 09:11:42 2025 from 192.168.1.42
"""

# Fake bash history — hints toward .secret
_BASH_HISTORY = """\
ls -la
cd /home/admin
cat /etc/passwd
nano .bashrc
python3 encrypt.py
cat .secret
base64 -d .secret
ls -la /var/log/
sudo cat /root/backup.key
exit
"""

# The encoded flag (players must run base64 -d on this)
_SECRET_FILE = f"{_ENCODED_FLAG}\n"

# Fake /etc/shadow — juicy-looking but useless
_SHADOW = """\
root:$6$rounds=4096$randomsalt$fakehashfakehashfakehashfakehashfakehashfakehash:18000:0:99999:7:::
admin:$6$rounds=4096$anothersalt$fakehashfakehashfakehashfakehashfakehashfakehsh:18500:0:99999:7:::
"""

# Fake /var/log/auth.log — red herring
_AUTH_LOG = """\
Jun  5 08:00:01 prod-srv-01 sshd[1234]: Server listening on 0.0.0.0 port 22.
Jun  5 08:03:11 prod-srv-01 sshd[1337]: Failed password for invalid user hacker from 10.0.0.5 port 54321 ssh2
Jun  5 08:03:14 prod-srv-01 sshd[1337]: Failed password for root from 10.0.0.5 port 54322 ssh2
Jun  5 08:04:00 prod-srv-01 sshd[1338]: Accepted password for admin from 192.168.1.42 port 51200 ssh2
Jun  5 08:04:00 prod-srv-01 sshd[1338]: pam_unix(sshd:session): session opened for user admin
Jun  5 09:11:42 prod-srv-01 sshd[1401]: Accepted password for admin from 192.168.1.42 port 51300 ssh2
Jun  6 07:55:10 prod-srv-01 sshd[1501]: Failed password for root from 172.16.0.3 port 60001 ssh2
"""

# Fake crontab
_CRONTAB = """\
# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *   * * *   admin   /home/admin/cleanup.sh
"""

# Fake /home/admin/cleanup.sh
_CLEANUP_SH = """\
#!/bin/bash
# Cleanup temp files
find /tmp -name "*.tmp" -mtime +1 -delete
find /var/log -name "*.gz" -mtime +30 -delete
"""

# Fake /home/admin/.bashrc
_BASHRC = """\
# .bashrc
export PS1='admin@prod-srv-01:\\w\\$ '
export PATH=$PATH:/usr/local/bin
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'

# Note to self: remember to delete .secret after moving the key
"""

# Fake /root/ directory — permission denied (tease)
_ROOT_BACKUP_KEY = "PERMISSION DENIED"

# ---------------------------------------------------------------------------
# Virtual Filesystem Tree
# Each node is either:
#   - A string → file content
#   - A dict   → directory (keys are filenames)
#   - "__perm__" key in a dict → "denied" (triggers permission error)
# ---------------------------------------------------------------------------

FILESYSTEM = {
    "/": {
        "etc": {
            "passwd":   _PASSWD,
            "shadow":   {"__perm__": "denied"},
            "hostname": _HOSTNAME,
            "motd":     _MOTD,
            "crontab":  _CRONTAB,
            "hosts": (
                "127.0.0.1\tlocalhost\n"
                "127.0.1.1\tprod-srv-01\n"
                "::1\t\tlocalhost ip6-localhost\n"
            ),
            "os-release": (
                'NAME="Ubuntu"\n'
                'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
                'ID=ubuntu\n'
                'ID_LIKE=debian\n'
                'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
                'VERSION_ID="22.04"\n'
            ),
        },
        "home": {
            "admin": {
                ".bashrc":       _BASHRC,
                ".bash_history": _BASH_HISTORY,
                ".secret":       _SECRET_FILE,
                "cleanup.sh":    _CLEANUP_SH,
                "README.txt": (
                    "This server hosts critical infrastructure.\n"
                    "Contact: admin@company.internal\n"
                ),
            },
        },
        "root": {"__perm__": "denied"},
        "var": {
            "log": {
                "auth.log": _AUTH_LOG,
                "syslog":   "Jun  6 00:00:01 prod-srv-01 kernel: [    0.000000] Booting Linux 5.15.0-91-generic\n",
                "dpkg.log": "2025-06-01 10:00:00 startup archives install\n",
            },
        },
        "tmp": {},
        "bin": {},
        "usr": {
            "bin": {},
            "local": {"bin": {}},
        },
        "proc": {
            "version": "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-032) (gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n",
            "uptime":  "123456.78 234567.89\n",
            "1": {
                "cmdline": "/sbin/init\x00",
                "status":  "Name:\tinit\nPid:\t1\nState:\tS (sleeping)\n",
            },
        },
    }
}


def resolve_path(cwd: str, path: str) -> str:
    """Resolve a path string relative to cwd, returning an absolute path."""
    if not path.startswith("/"):
        path = cwd.rstrip("/") + "/" + path
    # Normalize: handle '..' and '.'
    parts = []
    for part in path.split("/"):
        if part == "" or part == ".":
            continue
        elif part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    return "/" + "/".join(parts)


def get_node(path: str):
    """
    Walk the FILESYSTEM tree and return the node at `path`.
    Returns:
        - dict  → directory node
        - str   → file content
        - None  → path not found
        - "denied" → permission denied
    """
    if path == "/":
        return FILESYSTEM["/"]

    parts = [p for p in path.split("/") if p]
    node = FILESYSTEM["/"]
    for part in parts:
        if not isinstance(node, dict):
            return None  # tried to descend into a file
        if "__perm__" in node:
            return "denied"
        if part not in node:
            return None
        node = node[part]

    if isinstance(node, dict) and "__perm__" in node:
        return "denied"
    return node


def list_dir(path: str):
    """Return (entries, error_string) for ls on a directory."""
    node = get_node(path)
    if node is None:
        return None, f"ls: cannot access '{path}': No such file or directory"
    if node == "denied":
        return None, f"ls: cannot open directory '{path}': Permission denied"
    if isinstance(node, str):
        return None, f"ls: cannot access '{path}': Not a directory"
    entries = [k for k in node.keys() if k != "__perm__"]
    return entries, None


def read_file(path: str):
    """Return (content, error_string) for cat on a file."""
    node = get_node(path)
    if node is None:
        return None, f"cat: {path}: No such file or directory"
    if node == "denied":
        return None, f"cat: {path}: Permission denied"
    if isinstance(node, dict):
        return None, f"cat: {path}: Is a directory"
    return node, None


def is_dir(path: str) -> bool:
    node = get_node(path)
    return isinstance(node, dict) and node != "denied"


def exists(path: str) -> bool:
    return get_node(path) is not None
