# Import libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading

# Constants
logging_format = logging.Formatter(
    "%(message)s"
)  # Set up how we want our logs to be formatted
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
host_key = paramiko.RSAKey(filename="server.key")
# Configure our loggers
# Set the handlers
# This will redirect us to where we want to log out outputs
# Set the logs levels

funnel_logger = logging.getLogger(
    "FunnelLogger"
)  # This will capture those using password IP addresses
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler("audit.log", maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)


# This is to harvest the credentials (IPs) the atteackers are using

# Set the logs levels
# Set the handlers
# This will redirect us to where we want to log out outputs

creds_logger = logging.getLogger(
    "FunnelLogger"
)  # This will capture those using password IP addresses

creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler("cmd_audit.log", maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


# Emulated Shell
def emulated_shell(channel, client_ip):
    channel.send(b"corporate-jumpbox2$ ")  # Default prompt that will be sent out

    # Provide the opportunity to recieve commands, so we need to listen to them
    # Essentially what the following code is doing is listening to the user inputs and then after they press the send request, we are able to put all the characters into a single string and then evaluate the logic
    command = b""
    while True:
        char = channel.recv(1)  # Listen to user inputs
        channel.send(char)
        if not char:
            channel.close()  # close the channel if there is not input
        command += char

        if char == b"\r":
            if command.strip() == b"exit":
                response = b"\n Goodbye!\n"
                channel.close()
            elif command.strip() == b"pwd":
                response = b"\n" + b"\\usr\\local" + b"\r\n"
                creds_logger.info(
                    f"Command {command.strip()}" + "executed by " f"{client_ip}"
                )
            elif command.strip() == b"whoami":
                response = b"\n" + b"corpuser1" + b"\r\n"
                creds_logger.info(
                    f"Command {command.strip()}" + "executed by " f"{client_ip}"
                )
            elif command.strip() == b"ls":
                response = b"\n" + b"jumpbox1.conf" + b"\r\n"
                creds_logger.info(
                    f"Command {command.strip()}" + "executed by " f"{client_ip}"
                )
            elif command.strip() == b"cat":
                response = b"\n" + b"Go to deeboodah.com" + b"\r\n"
                creds_logger.info(
                    f"Command {command.strip()}" + "executed by " f"{client_ip}"
                )
            else:
                response == b"\n" + bytes(command.strip()) + b"\r\n"
                creds_logger.info(
                    f"Command {command.strip()}" + "executed by " f"{client_ip}"
                )
            channel.send(response)
            channel.send(b"corporate-jumpbox2$ ")
            command = b""


# Sending the SSH server - Use Pamiriko
# Create the SSH server
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = (
            threading.Event()
        )  # Adding this since we are creating some threads, so we need to keep track of the events
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if (
            kind == "session"
        ):  # If the channel time is session, we are sending a message
            return paramiko.OPEN_SUCCEEDED

    # Authentication
    def get_allowed_auth(self):
        return "password"

    # Define what is going to be used for this SSH Server
    def check_auth_password(self, username, password):
        funnel_logger.info(
            f"Client {self.client_ip} attempted connection with username {username} and password: {password}"
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

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    # Handle the commands that are being input
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True


# Create an instance of the paramiko SSH library and using the socket library to allow the server to bind to specific adrres and port so as to allow clients to connect to our server


def client_handle(client, addr, username, password):
    client_ip = addr[0]

    print(f"{client_ip} has connected to the server.")
    try:
        # Initialize a new transport library
        transport = paramiko.Transport(client)

        # Set the SSH inner version for the transport
        transport.local_version = SSH_BANNER

        # Create an initialize a server
        server = Server(
            client_ip=client_ip, input_password=password, input_username=username
        )

        # Pass that SSH session into the server clAA
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to Ubuntu 24.02 LTS (Jammy Jellyfish)!\r\n\r\n"
        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print(error)
        print("!!! Error !!!")
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("!!! Error !!!")
        client.close()


# Provision SSH-based Honeypot


def honeypot(address, port, username, password):
    # Set a new socket object
    socks = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    )  # listening to IPv4 ip addresses with TCP
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)  # Can only handle 100 connection
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()  # Accepting clients
            ssh_honeypot_thread = threading.Thread(
                target=client_handle, args=(client, addr, username, password)
            )  # Create a new thread
            ssh_honeypot_thread.start()

            # Start a new threading to handle multiple connections

        except Exception as error:
            print(error)


honeypot("127.0.0.1", 2223, "username", "password")
