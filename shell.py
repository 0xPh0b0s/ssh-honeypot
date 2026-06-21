"""
shell.py — Fake interactive bash shell for the SSH honeypot.

Supports: ls, cat, cd, pwd, whoami, id, uname, echo, file,
          strings, base64, history, clear, env, ps, w, exit/quit
"""

from __future__ import annotations

import base64
import shlex
import textwrap
import time
from typing import Callable

from filesystem import (
    SSH_PASSWORD, FLAG,
    resolve_path, get_node, list_dir, read_file, is_dir, exists,
)
import logger

# Fake environment
_ENV = {
    "USER":    "admin",
    "HOME":    "/home/admin",
    "SHELL":   "/bin/bash",
    "TERM":    "xterm-256color",
    "LANG":    "en_US.UTF-8",
    "PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PWD":     "/home/admin",
    "LOGNAME": "admin",
    "MAIL":    "/var/mail/admin",
    "HOSTNAME":"prod-srv-01",
}

# Fake process list
_PS_OUTPUT = """\
  PID TTY          TIME CMD
    1 ?        00:00:03 init
  412 ?        00:00:00 sshd
  413 pts/0    00:00:00 bash
  501 ?        00:00:01 cron
  502 ?        00:02:14 apache2
  503 ?        00:00:00 mysql
  999 pts/0    00:00:00 ps
"""

_W_OUTPUT = """\
 {time} up 1 day, 10:23,  1 user,  load average: 0.01, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE JIFFIES WHAT
admin    pts/0    {ip}      08:00    0.00s  0.00s bash
"""

# Colorize helpers (ANSI)
RESET   = "\r\n"
BOLD    = "\x1b[1m"
BLUE    = "\x1b[34m"
CYAN    = "\x1b[36m"
GREEN   = "\x1b[32m"
RED     = "\x1b[31m"
YELLOW  = "\x1b[33m"
ENDC    = "\x1b[0m"


def _ls_format(entries: list[str], cwd: str) -> str:
    """Format ls output with colors: blue for dirs, white for files."""
    colored = []
    for name in sorted(entries):
        if name.startswith("."):
            # hidden — still show with -a (we show all)
            path = resolve_path(cwd, name)
            if is_dir(path):
                colored.append(f"{BOLD}{BLUE}{name}{ENDC}")
            else:
                colored.append(name)
        else:
            path = resolve_path(cwd, name)
            if is_dir(path):
                colored.append(f"{BOLD}{BLUE}{name}{ENDC}")
            elif name.endswith(".sh"):
                colored.append(f"{GREEN}{name}{ENDC}")
            else:
                colored.append(name)
    # Print in columns (simple: one per line for safety over SSH)
    return "  ".join(colored)


class FakeShell:
    """Stateful fake shell instance for one SSH session."""

    def __init__(self, session_id: int, client_ip: str, send: Callable[[bytes], None]):
        self.session_id = session_id
        self.client_ip  = client_ip
        self.send       = send          # callback to write bytes to the SSH channel
        self.cwd        = "/home/admin"
        self._history: list[str] = []
        self._running   = True
        self._cmd_buf   = ""            # line buffer

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    def _write(self, text: str):
        self.send(text.replace("\n", "\r\n").encode())

    def _prompt(self) -> str:
        return f"{GREEN}admin@prod-srv-01{ENDC}:{BLUE}{self._short_cwd()}{ENDC}$ "

    def _short_cwd(self) -> str:
        if self.cwd.startswith("/home/admin"):
            return "~" + self.cwd[len("/home/admin"):]
        return self.cwd

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def greet(self):
        """Send MOTD and first prompt."""
        from filesystem import FILESYSTEM
        motd = FILESYSTEM["/"]["etc"]["motd"]
        self._write("\r\n" + motd + "\r\n")
        self._write(self._prompt())

    def feed(self, data: bytes):
        """
        Process incoming keystrokes byte-by-byte (raw SSH channel data).
        Handles: printable chars, Enter, Backspace, Ctrl-C, Ctrl-D.
        """
        for byte in data:
            ch = chr(byte)
            if byte in (13, 10):   # Enter / CR
                self._write("\r\n")
                line = self._cmd_buf.strip()
                self._cmd_buf = ""
                if line:
                    self._history.append(line)
                    logger.log_command(self.session_id, line)
                    self._execute(line)
                if self._running:
                    self._write(self._prompt())
            elif byte == 127 or byte == 8:  # Backspace / DEL
                if self._cmd_buf:
                    self._cmd_buf = self._cmd_buf[:-1]
                    self._write("\x08 \x08")   # erase char
            elif byte == 3:  # Ctrl-C
                self._cmd_buf = ""
                self._write("^C\r\n" + self._prompt())
            elif byte == 4:  # Ctrl-D (EOF → exit)
                self._write("\r\nlogout\r\n")
                self._running = False
            elif 32 <= byte < 127:  # printable ASCII
                self._cmd_buf += ch
                self._write(ch)

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    def _execute(self, line: str):
        try:
            parts = shlex.split(line)
        except ValueError:
            self._write(f"bash: syntax error near unexpected token\r\n")
            return

        if not parts:
            return

        cmd, *args = parts

        # Handle pipes very naively: just execute first command
        if "|" in parts:
            # Split on first pipe
            pipe_idx = parts.index("|")
            left_parts  = parts[:pipe_idx]
            right_parts = parts[pipe_idx+1:]
            # Execute left side and capture output
            output = self._capture(left_parts)
            # Feed output to right side (only base64 support)
            if right_parts and right_parts[0] in ("base64", "base64"):
                flag_str = "-d" in right_parts
                if flag_str:
                    try:
                        decoded = base64.b64decode(output.strip()).decode()
                        self._write(decoded + "\r\n")
                    except Exception:
                        self._write("base64: invalid input\r\n")
                else:
                    self._write(base64.b64encode(output.encode()).decode() + "\r\n")
            else:
                self._write(output)
            return

        dispatch = {
            "ls":     self._cmd_ls,
            "ll":     self._cmd_ls,      # alias
            "la":     self._cmd_ls,      # alias
            "l":      self._cmd_ls,      # alias
            "cat":    self._cmd_cat,
            "cd":     self._cmd_cd,
            "pwd":    self._cmd_pwd,
            "whoami": self._cmd_whoami,
            "id":     self._cmd_id,
            "uname":  self._cmd_uname,
            "echo":   self._cmd_echo,
            "file":   self._cmd_file,
            "strings":self._cmd_strings,
            "base64": self._cmd_base64,
            "history":self._cmd_history,
            "clear":  self._cmd_clear,
            "env":    self._cmd_env,
            "printenv":self._cmd_env,
            "ps":     self._cmd_ps,
            "w":      self._cmd_w,
            "exit":   self._cmd_exit,
            "quit":   self._cmd_exit,
            "logout": self._cmd_exit,
            "sudo":   self._cmd_sudo,
            "su":     self._cmd_su,
            "python": self._cmd_python,
            "python3":self._cmd_python,
            "sh":     self._cmd_sh,
            "bash":   self._cmd_sh,
            "man":    self._cmd_man,
            "less":   self._cmd_less,
            "more":   self._cmd_less,
            "grep":   self._cmd_grep,
            "find":   self._cmd_find,
            "touch":  self._cmd_touch,
            "rm":     self._cmd_rm,
            "mkdir":  self._cmd_mkdir,
            "cp":     self._cmd_cp,
            "mv":     self._cmd_cp,
            "chmod":  self._cmd_chmod,
            "chown":  self._cmd_chmod,
            "wget":   self._cmd_wget,
            "curl":   self._cmd_wget,
            "ssh":    self._cmd_ssh,
            "ping":   self._cmd_ping,
            "ifconfig":self._cmd_ifconfig,
            "ip":     self._cmd_ip,
            "netstat":self._cmd_netstat,
            "ss":     self._cmd_netstat,
            "hostname":self._cmd_hostname,
            "date":   self._cmd_date,
            "uptime": self._cmd_uptime,
            "df":     self._cmd_df,
            "du":     self._cmd_du,
            "which":  self._cmd_which,
            "type":   self._cmd_which,
            "head":   self._cmd_head,
            "tail":   self._cmd_tail,
            "wc":     self._cmd_wc,
            "xxd":    self._cmd_xxd,
            "hexdump":self._cmd_xxd,
        }

        handler = dispatch.get(cmd)
        if handler:
            handler(args)
        else:
            self._write(f"bash: {cmd}: command not found\r\n")

    def _capture(self, parts: list[str]) -> str:
        """Run a command and capture its output as a string (for pipe support)."""
        buf = []
        orig_send = self.send
        def capture_send(data: bytes):
            buf.append(data.decode(errors="replace"))
        self.send = capture_send
        if parts:
            cmd, *args = parts
            dispatch = {
                "cat": self._cmd_cat,
                "echo": self._cmd_echo,
                "base64": self._cmd_base64,
            }
            h = dispatch.get(cmd)
            if h:
                h(args)
        self.send = orig_send
        return "".join(buf).replace("\r\n", "\n").replace("\r", "\n")

    # ------------------------------------------------------------------
    # Individual command implementations
    # ------------------------------------------------------------------

    def _cmd_ls(self, args: list[str]):
        # Filter flags
        flags  = [a for a in args if a.startswith("-")]
        paths  = [a for a in args if not a.startswith("-")] or [self.cwd]
        show_hidden = any("a" in f for f in flags)
        long_fmt    = any("l" in f for f in flags)

        for path_arg in paths:
            path = resolve_path(self.cwd, path_arg)
            entries, err = list_dir(path)
            if err:
                self._write(err + "\r\n")
                continue

            if not show_hidden:
                entries = [e for e in entries if not e.startswith(".")]

            if long_fmt:
                self._write(f"total {len(entries) * 4}\r\n")
                for name in sorted(entries):
                    full = resolve_path(path, name)
                    node = get_node(full)
                    is_directory = isinstance(node, dict)
                    perm = "drwxr-xr-x" if is_directory else "-rw-r--r--"
                    size = len(node) if isinstance(node, str) else 4096
                    color_name = (f"{BOLD}{BLUE}{name}{ENDC}" if is_directory
                                  else (f"{GREEN}{name}{ENDC}" if name.endswith(".sh") else name))
                    self._write(
                        f"{perm}  1 admin admin {size:>8}  Jun  5 09:11 {color_name}\r\n"
                    )
            else:
                if entries:
                    self._write(_ls_format(entries, path) + "\r\n")

    def _cmd_cat(self, args: list[str]):
        if not args:
            # cat with no args waits for stdin — simulate blocking
            self._write("")
            return
        for arg in args:
            if arg.startswith("-"):
                continue
            path = resolve_path(self.cwd, arg)
            content, err = read_file(path)
            if err:
                self._write(err + "\r\n")
            else:
                self._write(content)
                if not content.endswith("\n"):
                    self._write("\r\n")

    def _cmd_cd(self, args: list[str]):
        if not args:
            self.cwd = "/home/admin"
            return
        target = resolve_path(self.cwd, args[0])
        node = get_node(target)
        if node is None:
            self._write(f"bash: cd: {args[0]}: No such file or directory\r\n")
        elif node == "denied":
            self._write(f"bash: cd: {args[0]}: Permission denied\r\n")
        elif isinstance(node, str):
            self._write(f"bash: cd: {args[0]}: Not a directory\r\n")
        else:
            self.cwd = target

    def _cmd_pwd(self, args: list[str]):
        self._write(self.cwd + "\r\n")

    def _cmd_whoami(self, args: list[str]):
        self._write("admin\r\n")

    def _cmd_id(self, args: list[str]):
        self._write("uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)\r\n")

    def _cmd_uname(self, args: list[str]):
        if "-a" in args:
            self._write("Linux prod-srv-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n")
        elif "-r" in args:
            self._write("5.15.0-91-generic\r\n")
        elif "-n" in args:
            self._write("prod-srv-01\r\n")
        else:
            self._write("Linux\r\n")

    def _cmd_echo(self, args: list[str]):
        # Handle $VAR expansion
        out_parts = []
        for a in args:
            if a.startswith("$"):
                varname = a[1:].strip("{}")
                out_parts.append(_ENV.get(varname, ""))
            else:
                out_parts.append(a)
        self._write(" ".join(out_parts) + "\r\n")

    def _cmd_file(self, args: list[str]):
        for arg in args:
            if arg.startswith("-"):
                continue
            path = resolve_path(self.cwd, arg)
            node = get_node(path)
            if node is None:
                self._write(f"{arg}: ERROR: No such file or directory\r\n")
            elif node == "denied":
                self._write(f"{arg}: ERROR: Permission denied\r\n")
            elif isinstance(node, dict):
                self._write(f"{arg}: directory\r\n")
            else:
                self._write(f"{arg}: ASCII text\r\n")

    def _cmd_strings(self, args: list[str]):
        for arg in args:
            if arg.startswith("-"):
                continue
            path = resolve_path(self.cwd, arg)
            content, err = read_file(path)
            if err:
                self._write(err + "\r\n")
            else:
                for line in content.splitlines():
                    if len(line) >= 4:
                        self._write(line + "\r\n")

    def _cmd_base64(self, args: list[str]):
        decode = "-d" in args or "--decode" in args
        file_args = [a for a in args if not a.startswith("-")]

        if not file_args:
            self._write("")   # would read stdin
            return

        for arg in file_args:
            path = resolve_path(self.cwd, arg)
            content, err = read_file(path)
            if err:
                self._write(err + "\r\n")
                continue
            if decode:
                try:
                    decoded = base64.b64decode(content.strip()).decode()
                    self._write(decoded + "\r\n")
                except Exception:
                    self._write(f"base64: invalid input\r\n")
            else:
                encoded = base64.b64encode(content.encode()).decode()
                self._write(encoded + "\r\n")

    def _cmd_history(self, args: list[str]):
        for i, cmd in enumerate(self._history, 1):
            self._write(f"  {i:>4}  {cmd}\r\n")

    def _cmd_clear(self, args: list[str]):
        self._write("\x1b[2J\x1b[H")

    def _cmd_env(self, args: list[str]):
        for k, v in _ENV.items():
            self._write(f"{k}={v}\r\n")

    def _cmd_ps(self, args: list[str]):
        self._write(_PS_OUTPUT)

    def _cmd_w(self, args: list[str]):
        t = time.strftime("%H:%M:%S")
        self._write(_W_OUTPUT.format(time=t, ip=self.client_ip).strip() + "\r\n")

    def _cmd_exit(self, args: list[str]):
        self._write("logout\r\n")
        self._running = False

    def _cmd_sudo(self, args: list[str]):
        if not args:
            self._write("usage: sudo command\r\n")
            return
        self._write("[sudo] password for admin: \r\n")
        time.sleep(1)
        self._write("Sorry, try again.\r\n")
        time.sleep(0.5)
        self._write("sudo: 3 incorrect password attempts\r\n")

    def _cmd_su(self, args: list[str]):
        self._write("Password: \r\n")
        time.sleep(1)
        self._write("su: Authentication failure\r\n")

    def _cmd_python(self, args: list[str]):
        self._write(
            "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\r\n"
            "Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n"
            ">>> \r\n"
        )
        # We don't actually implement an interactive Python REPL here
        self._write("(Python REPL not available in this environment)\r\n")

    def _cmd_sh(self, args: list[str]):
        self._write(f"bash: spawning subshells is not permitted\r\n")

    def _cmd_man(self, args: list[str]):
        if not args:
            self._write("What manual page do you want?\r\n")
        else:
            self._write(f"No manual entry for {args[0]}\r\n")

    def _cmd_less(self, args: list[str]):
        # Just cat the file
        file_args = [a for a in args if not a.startswith("-")]
        if file_args:
            self._cmd_cat(file_args)

    def _cmd_grep(self, args: list[str]):
        flags    = [a for a in args if a.startswith("-")]
        non_flag = [a for a in args if not a.startswith("-")]
        if len(non_flag) < 1:
            self._write("Usage: grep [OPTION]... PATTERN [FILE]...\r\n")
            return
        pattern = non_flag[0]
        files   = non_flag[1:]
        if not files:
            self._write("")
            return
        import re
        case_flag = re.IGNORECASE if "-i" in flags else 0
        for f in files:
            path = resolve_path(self.cwd, f)
            content, err = read_file(path)
            if err:
                self._write(err + "\r\n")
                continue
            for line in content.splitlines():
                try:
                    if re.search(pattern, line, case_flag):
                        prefix = f"{f}:" if len(files) > 1 else ""
                        self._write(prefix + line + "\r\n")
                except re.error:
                    pass

    def _cmd_find(self, args: list[str]):
        # Super simplified find
        start = self.cwd
        non_flags = [a for a in args if not a.startswith("-")]
        if non_flags:
            start = resolve_path(self.cwd, non_flags[0])

        def _walk(path: str, depth: int = 0):
            if depth > 5:
                return
            node = get_node(path)
            if node is None or node == "denied":
                return
            self._write(path + "\r\n")
            if isinstance(node, dict):
                for child in node:
                    if child == "__perm__":
                        continue
                    _walk(path.rstrip("/") + "/" + child, depth + 1)

        _walk(start)

    def _cmd_touch(self, args: list[str]):
        for a in args:
            if not a.startswith("-"):
                self._write(f"touch: cannot touch '{a}': Read-only file system\r\n")

    def _cmd_rm(self, args: list[str]):
        files = [a for a in args if not a.startswith("-")]
        for f in files:
            self._write(f"rm: cannot remove '{f}': Read-only file system\r\n")

    def _cmd_mkdir(self, args: list[str]):
        dirs = [a for a in args if not a.startswith("-")]
        for d in dirs:
            self._write(f"mkdir: cannot create directory '{d}': Read-only file system\r\n")

    def _cmd_cp(self, args: list[str]):
        self._write("cp: Read-only file system\r\n")

    def _cmd_chmod(self, args: list[str]):
        self._write("chmod: changing permissions: Operation not permitted\r\n")

    def _cmd_wget(self, args: list[str]):
        self._write("wget: unable to resolve host address (no network access)\r\n")

    def _cmd_ssh(self, args: list[str]):
        self._write("ssh: connect to host: Connection refused\r\n")

    def _cmd_ping(self, args: list[str]):
        host = next((a for a in args if not a.startswith("-")), "localhost")
        self._write(f"PING {host}: Network is unreachable\r\n")

    def _cmd_ifconfig(self, args: list[str]):
        self._write(
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255\r\n"
            "        ether de:ad:be:ef:00:42  txqueuelen 1000  (Ethernet)\r\n"
            "lo:   flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
        )

    def _cmd_ip(self, args: list[str]):
        if args and args[0] in ("a", "addr", "address"):
            self._cmd_ifconfig([])
        else:
            self._write("ip: unsupported operation\r\n")

    def _cmd_netstat(self, args: list[str]):
        self._write(
            "Active Internet connections (only servers)\r\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\r\n"
        )

    def _cmd_hostname(self, args: list[str]):
        self._write("prod-srv-01\r\n")

    def _cmd_date(self, args: list[str]):
        self._write(time.strftime("%a %b %d %H:%M:%S %Z %Y") + "\r\n")

    def _cmd_uptime(self, args: list[str]):
        self._write(" 09:00:00 up 1 day, 10:23,  1 user,  load average: 0.01, 0.03, 0.00\r\n")

    def _cmd_df(self, args: list[str]):
        self._write(
            "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n"
            "/dev/sda1       20511312 4231488  15224108  22% /\r\n"
            "tmpfs             512000       0    512000   0% /dev/shm\r\n"
        )

    def _cmd_du(self, args: list[str]):
        self._write("4\t.\r\n")

    def _cmd_which(self, args: list[str]):
        known = {"ls", "cat", "cd", "pwd", "whoami", "id", "uname", "echo",
                 "base64", "grep", "find", "python3", "bash", "sh"}
        for a in args:
            if a in known:
                self._write(f"/usr/bin/{a}\r\n")
            else:
                self._write("")

    def _cmd_head(self, args: list[str]):
        n = 10
        files = []
        i = 0
        while i < len(args):
            if args[i] in ("-n",) and i + 1 < len(args):
                try:
                    n = int(args[i+1])
                except ValueError:
                    pass
                i += 2
            elif args[i].startswith("-") and args[i][1:].isdigit():
                n = int(args[i][1:])
                i += 1
            else:
                files.append(args[i])
                i += 1

        for f in files:
            path = resolve_path(self.cwd, f)
            content, err = read_file(path)
            if err:
                self._write(err + "\r\n")
            else:
                lines = content.splitlines()[:n]
                self._write("\r\n".join(lines) + "\r\n")

    def _cmd_tail(self, args: list[str]):
        n = 10
        files = []
        i = 0
        while i < len(args):
            if args[i] in ("-n",) and i + 1 < len(args):
                try:
                    n = int(args[i+1])
                except ValueError:
                    pass
                i += 2
            else:
                if not args[i].startswith("-"):
                    files.append(args[i])
                i += 1

        for f in files:
            path = resolve_path(self.cwd, f)
            content, err = read_file(path)
            if err:
                self._write(err + "\r\n")
            else:
                lines = content.splitlines()[-n:]
                self._write("\r\n".join(lines) + "\r\n")

    def _cmd_wc(self, args: list[str]):
        files = [a for a in args if not a.startswith("-")]
        for f in files:
            path = resolve_path(self.cwd, f)
            content, err = read_file(path)
            if err:
                self._write(err + "\r\n")
            else:
                lines = content.count("\n")
                words = len(content.split())
                chars = len(content)
                self._write(f" {lines} {words} {chars} {f}\r\n")

    def _cmd_xxd(self, args: list[str]):
        files = [a for a in args if not a.startswith("-")]
        for f in files:
            path = resolve_path(self.cwd, f)
            content, err = read_file(path)
            if err:
                self._write(err + "\r\n")
            else:
                data = content.encode()[:128]  # Show first 128 bytes only
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    hex_part  = " ".join(f"{b:02x}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    self._write(f"{i:08x}: {hex_part:<48}  {ascii_part}\r\n")
