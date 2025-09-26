# ssh_honeypot.py
# SSH honeypot using paramiko
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading

# Constants
logging_format = logging.Formatter("%(asctime)s %(message)s")
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
host_key = paramiko.RSAKey(filename="server.key")

# Configure loggers
funnel_logger = logging.getLogger("FunnelLogger")  # connection / credential audit
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler("audit.log", maxBytes=10 * 1024 * 1024, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Command / session logger
creds_logger = logging.getLogger("CmdLogger")
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler("cmd_audit.log", maxBytes=10 * 1024 * 1024, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


# Emulated Shell
def emulated_shell(channel, client_ip):
    try:
        prompt = b"corporate-jumpbox2$ "
        channel.send(prompt)
    except Exception:
        return

    command = b""
    while True:
        try:
            char = channel.recv(1)
        except Exception:
            break

        # Peer closed or no data
        if not char:
            try:
                channel.close()
            except Exception:
                pass
            break

        # Echo character back to the client (typical terminal behavior)
        try:
            channel.send(char)
        except Exception:
            pass

        command += char

        # consider both \n and \r as end-of-line
        if char in (b"\n", b"\r"):
            cmd_str = command.strip().decode(errors="ignore")
            # Log the raw command
            creds_logger.info(f"{client_ip} executed command: {cmd_str}")

            response = b""
            # Commands and responses
            if cmd_str == "exit":
                response = b"\nGoodbye!\r\n"
                try:
                    channel.send(response)
                except Exception:
                    pass
                try:
                    channel.close()
                except Exception:
                    pass
                break

            elif cmd_str == "pwd":
                response = b"\n/usr/local\r\n"

            elif cmd_str == "whoami":
                response = b"\ncorpuser1\r\n"

            elif cmd_str == "ls":
                response = b"\njumpbox1.conf\nsecrets.txt\r\n"

            elif cmd_str.startswith("cat "):
                # simple fake files
                arg = cmd_str[4:].strip()
                if arg in ("secrets.txt", "/etc/secrets"):
                    response = b"\nAPI_KEY=REDACTED\nDO_NOT_SHARE\r\n"
                elif arg in ("/etc/passwd", "passwd"):
                    response = b"\nroot:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User:/home/user:/bin/bash\r\n"
                else:
                    response = b"\n" + arg.encode() + b": No such file or directory\r\n"

            elif cmd_str == "uname -a":
                response = b"\nLinux jumpbox 5.15.0-0-generic #1 SMP Thu Sep 1 00:00:00 UTC 2025 x86_64 GNU/Linux\r\n"

            elif cmd_str.startswith("sudo "):
                # fake sudo prompt and response without real escalation
                response = b"\n[sudo] password for corpuser1: \r\nSorry, try again.\r\n"

            elif cmd_str.startswith("wget ") or cmd_str.startswith("curl "):
                response = b"\nFetching... failed: network unreachable\r\n"

            elif cmd_str == "":
                response = b"\r\n"

            else:
                # default: echo the command back as output
                response = b"\n" + cmd_str.encode(errors="ignore") + b"\r\n"

            # send the response and prompt back
            try:
                channel.send(response)
                channel.send(prompt)
            except Exception:
                # if we fail to send (channel closed), break
                break

            command = b""


# Paramiko Server interface implementation
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return None

    # Paramiko expects get_allowed_auths(self, username)
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(
            f"Client {self.client_ip} attempted connection with username={username} password={password}"
        )
        creds_logger.info(f"{self.client_ip}, {username}, {password}")
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        # command is bytes in many paramiko versions
        try:
            cmd_repr = command.decode() if isinstance(command, bytes) else str(command)
        except Exception:
            cmd_repr = repr(command)
        creds_logger.info(f"Exec request from {self.client_ip}: {cmd_repr}")
        return True


def client_handle(client_sock, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = SSH_BANNER

        server = Server(client_ip=client_ip, input_password=password, input_username=username)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(10)  # wait up to 10s for a channel
        if channel is None:
            print("No channel was opened.")
            return

        standard_banner = "Welcome to Ubuntu 24.02 LTS (Jammy Jellyfish)!\r\n\r\n"
        # paramiko channel.send expects bytes
        try:
            channel.send(standard_banner.encode())
        except Exception:
            pass

        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print("Error in client_handle:", error)
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass


# Honeypot listener
def honeypot(address, port, username=None, password=None):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH server is listening on {address}:{port}.")

    while True:
        try:
            client, addr = socks.accept()
            t = threading.Thread(target=client_handle, args=(client, addr, username, password), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("Shutting down honeypot.")
            break
        except Exception as error:
            print("Listener error:", error)


if __name__ == "__main__":
    # default run (modify or refactor to argparse if you want)
    honeypot("127.0.0.1", 2223, "username", "password")
