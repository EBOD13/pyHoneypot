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

### Generate a new RSA key with NO passphrase, in PEM format (Paramiko-friendly)
ssh-keygen -t rsa -b 4096 -m PEM -f server.key -N ""

### Install dependency:

```bash
python -m pip install paramiko

```

## Usage

The SSH honeypot runs as a fake SSH server.  
You interact with it the same way an attacker would: by connecting over SSH from another terminal (or another machine).

The workflow always uses **two terminals**:

- **Terminal 1** → runs the honeypot (server)
- **Terminal 2** → connects via SSH (client / attacker simulation)

---

### 1. Start the Honeypot (Server)

From the project directory containing `ssh_honeypot.py` and `server.key`:

```bash
python3 ssh_honeypot.py
````

If everything is set up correctly, you should see:

```text
SSH server is listening on 127.0.0.1:2223.
```

Leave this terminal **running**.
This is now your fake SSH server.

---

### 2. Connect to the Honeypot (Client / Attacker Simulation)

Open a **new terminal window or tab**.

By default, the honeypot listens on:

* Host: `127.0.0.1`
* Port: `2223`
* Username: `username`
* Password: `password`

Connect using SSH:

```bash
ssh -p 2223 username@127.0.0.1
```

On first connection, SSH will warn about an unknown host key:

```text
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
Are you sure you want to continue connecting (yes/no)?
```

Type:

```text
yes
```

When prompted for the password, enter:

```text
password
```

If authentication succeeds, you will see:

```text
Welcome to Ubuntu 24.02 LTS (Jammy Jellyfish)!

corporate-jumpbox2$
```

You are now inside the **emulated shell**.

---

### 3. Interacting with the Emulated Shell

The honeypot does **not** execute real commands.
Instead, it responds with predefined outputs while logging all activity.

Try the following commands:

```bash
pwd
whoami
ls
cat secrets.txt
cat /etc/passwd
uname -a
sudo apt update
curl http://example.com
exit
```

Example session:

```text
corporate-jumpbox2$ whoami
corpuser1

corporate-jumpbox2$ ls
jumpbox1.conf
secrets.txt

corporate-jumpbox2$ cat secrets.txt
API_KEY=REDACTED
DO_NOT_SHARE

corporate-jumpbox2$ exit
Goodbye!
```

---

### 4. Reviewing Captured Logs

After one or more sessions, the honeypot generates two rotating log files:

* **`audit.log`**
  Records connection attempts and credentials:

  * source IP
  * usernames
  * passwords

* **`cmd_audit.log`**
  Records commands executed during sessions.

View them with:

```bash
cat audit.log
cat cmd_audit.log
```

These logs represent the *intelligence* gathered by the honeypot.

---

### 5. Localhost vs Network Exposure

By default, the honeypot is bound to **localhost only**:

```python
honeypot("127.0.0.1", 2223, "username", "password")
```

This means **only your own machine** can connect.

To listen on all interfaces (LAN / internet):

```python
honeypot("0.0.0.0", 2223, "username", "password")
```

**Important**
Only expose the honeypot on networks or servers where you have **explicit permission**.
If exposing publicly:

* Run inside a VM or container
* Restrict outbound traffic
* Never reuse real SSH keys
* Monitor logs regularly

---

### 6. Stopping the Honeypot

To stop the server, return to the terminal running the honeypot and press:

```text
Ctrl + C
```

The server will shut down cleanly.

---

## Summary

1. Start the honeypot in one terminal:

   ```bash
   python3 ssh_honeypot.py
   ```

2. Connect from another terminal:

   ```bash
   ssh -p 2223 username@127.0.0.1
   ```

3. Execute commands to simulate attacker behavior.

4. Review `audit.log` and `cmd_audit.log` for captured activity.

This setup provides a controlled environment to study SSH attack behavior and credential harvesting techniques without exposing real systems.
