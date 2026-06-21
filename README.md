# CTF SSH Honeypot

A multi-layered SSH honeypot CTF challenge built in Python.  
Players connect via SSH, find the hidden credentials, explore a fake Linux filesystem, and decode the flag.

---

## Quick Start

### 1. Install dependencies
```bash
cd ssh-honeypot
pip install -r requirements.txt
```

### 2. Start the SSH honeypot
```bash
python honeypot.py
# Listens on port 2222 by default
```

### 3. Start the web dashboard (separate terminal)
```bash
python dashboard/app.py
# Browse to http://127.0.0.1:8080
```

---

## Challenge Design

Players must:

| Step | Task | Hint |
|------|------|------|
| 1 | Connect via SSH (`ssh -p 2222 admin@<host>`) | Port scan / challenge brief |
| 2 | Find the SSH password | Base64 token in the pre-auth SSH banner |
| 3 | Explore the fake Linux shell | `ls -la`, `cat .bash_history` |
| 4 | Find the encoded flag file | `/home/admin/.secret` |
| 5 | Decode it | `base64 -d .secret` |

**Flag:** `flag{y0u_f0und_th3_h1dd3n_k3y}`  
**SSH Password:** `h0n3yp0t`

---

## Customization

Edit the top of `filesystem.py`:
```python
SSH_PASSWORD = "h0n3yp0t"           # Change the SSH password
FLAG         = "flag{your_flag}"    # Change the embedded flag
```

---

## Architecture

```
honeypot.py        SSH server (Paramiko) — auth logging, banner, shell handoff
shell.py           Fake interactive bash shell (40+ commands)
filesystem.py      Virtual Linux filesystem (dict tree)
logger.py          SQLite session/command logger
dashboard/app.py   Flask web dashboard (http://127.0.0.1:8080)
```

---

## Supported Shell Commands

`ls` `cat` `cd` `pwd` `whoami` `id` `uname` `echo` `env` `ps` `w`  
`file` `strings` `base64` `grep` `find` `head` `tail` `wc` `xxd`  
`history` `clear` `date` `uptime` `df` `du` `hostname` `which`  
`sudo` `su` `ping` `ssh` `curl` `wget` `ifconfig` `ip` `netstat`  
`chmod` `chown` `cp` `mv` `rm` `mkdir` `touch` `python3` `man`

---

## Options

```
python honeypot.py --host 0.0.0.0 --port 2222
python dashboard/app.py
```

---

## Security Note

This tool is for **CTF / educational use only**. Do not expose it on public infrastructure without proper isolation.
