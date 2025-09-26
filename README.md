# pyHoneypot — SSH honeypot

A small Python SSH honeypot implemented with `paramiko`.  
It accepts SSH connections, logs attempted credentials and commands, and presents an emulated shell prompt to capture attacker activity.

> **Important — ethics & safety**  
> Use this code only in controlled, isolated environments (VM/container) and only on networks/systems where you have explicit permission. Restrict outbound traffic so the honeypot cannot be abused as a pivot. Running services on public IPs or without authorization can be illegal or disruptive.

---

## Contents

- `ssh_honeypot.py` — main honeypot script
- `server.key` — RSA host key (must be present next to the script)
- `audit.log` — connection / credential audit (rotating)
- `cmd_audit.log` — commands/session audit (rotating)

---

## Features

- Accepts SSH connections (password auth).
- Logs attempted usernames & passwords.
- Presents a simple emulated shell prompt and captures commands.
- Rotating logs for connection and command auditing.
- Built-in fake responses for common commands to increase attacker interaction:
  - `exit`, `pwd`, `whoami`, `ls`, `cat <file>`, `uname -a`, `sudo <...>`, `wget <...>` / `curl <...>`

---

## Requirements

- Python 3.8+
- `paramiko`

Install dependency:

```bash
python -m pip install paramiko
