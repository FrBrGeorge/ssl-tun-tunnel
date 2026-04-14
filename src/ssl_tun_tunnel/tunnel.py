import os
import fcntl
import struct
import socket
import ssl
import select
import argparse
import subprocess
import sys
import logging

# TUN constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tun(name='tun0'):
    """
    Creates a TUN device with the given name.
    
    Args:
        name (str): The name of the TUN interface to create.
        
    Returns:
        int: The file descriptor of the created TUN device, or None on failure.
    """
    try:
        tun = os.open('/dev/net/tun', os.O_RDWR)
    except FileNotFoundError:
        logging.error("Error: /dev/net/tun not found. Are you running on Linux?")
        return None
    except PermissionError:
        logging.error("Error: Permission denied. Try running with sudo.")
        return None

    # Set interface name
    # ifr structure: 16 bytes for name, 2 bytes for flags
    ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun

def configure_ip(name, ip_cidr):
    """
    Configures the IP address and brings up the TUN interface.
    
    Args:
        name (str): The name of the interface.
        ip_cidr (str): The IP address in CIDR notation (e.g., '192.168.255.1/24').
    """
    logging.info(f"Configuring {name} with IP {ip_cidr}...")
    try:
        subprocess.run(['ip', 'addr', 'add', ip_cidr, 'dev', name], check=True)
        subprocess.run(['ip', 'link', 'set', 'dev', name, 'up'], check=True)
    except Exception as e:
        logging.warning(f"Warning: Failed to configure IP via 'ip' command: {e}")
        logging.warning("You may need to configure it manually.")

def generate_pem(filename='server.pem'):
    """
    Generates a self-signed certificate and private key in a single .pem file.
    
    Args:
        filename (str): The name of the file to save the PEM data to.
    """
    logging.info(f"Generating self-signed PEM: {filename}...")
    try:
        # Generate a self-signed certificate and key in one file
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', 
            '-keyout', filename, '-out', filename, 
            '-days', '365', '-nodes', '-subj', '/CN=localhost'
        ], check=True)
        logging.info(f"Successfully generated {filename}")
    except Exception as e:
        logging.error(f"Error generating PEM: {e}")
        sys.exit(1)

def run_server(port, certfile, keyfile, tun_ip, log_packet_size=False):
    """
    Runs the tunnel in server mode.
    
    Args:
        port (int): The port to listen on.
        certfile (str): Path to the certificate file (or PEM containing both).
        keyfile (str): Path to the private key file (optional if certfile is a combined PEM).
        tun_ip (str): IP/CIDR for the TUN interface.
        log_packet_size (bool): Whether to log every packet size.
    """
    tun_fd = create_tun()
    if tun_fd is None: return
    configure_ip('tun0', tun_ip)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    except Exception as e:
        logging.error(f"Error loading certificates: {e}")
        return

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', port))
    server_sock.listen(1)

    logging.info(f"Server listening on port {port}...")

    while True:
        client_sock, addr = server_sock.accept()
        logging.info(f"Connection from {addr}")
        try:
            ssl_sock = context.wrap_socket(client_sock, server_side=True)
            handle_tunnel(tun_fd, ssl_sock, log_packet_size)
        except Exception as e:
            logging.error(f"Connection error: {e}")
        finally:
            client_sock.close()

def run_client(server_host, server_port, tun_ip, log_packet_size=False):
    """
    Runs the tunnel in client mode.
    
    Args:
        server_host (str): The server hostname or IP.
        server_port (int): The server port.
        tun_ip (str): IP/CIDR for the TUN interface.
        log_packet_size (bool): Whether to log every packet size.
    """
    tun_fd = create_tun()
    if tun_fd is None: return
    configure_ip('tun0', tun_ip)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(sock, server_hostname=server_host)
    
    logging.info(f"Connecting to {server_host}:{server_port}...")
    try:
        ssl_sock.connect((server_host, server_port))
        logging.info("Connected.")
        handle_tunnel(tun_fd, ssl_sock, log_packet_size)
    except Exception as e:
        logging.error(f"Connection failed: {e}")

def handle_tunnel(tun_fd, ssl_sock, log_packet_size=False):
    """
    Handles the bidirectional traffic between the TUN device and the SSL socket.
    
    Args:
        tun_fd (int): File descriptor of the TUN device.
        ssl_sock (ssl.SSLSocket): The established SSL socket.
        log_packet_size (bool): Whether to log every packet size.
    """
    ssl_sock.setblocking(0)
    
    while True:
        r, w, x = select.select([tun_fd, ssl_sock], [], [])
        
        if tun_fd in r:
            packet = os.read(tun_fd, 2048)
            if not packet: break
            if log_packet_size:
                logging.info(f"TUN -> SSL: {len(packet)} bytes")
            # Send length-prefixed packet over SSL
            # Header is 2 bytes (unsigned short, big-endian)
            ssl_sock.sendall(struct.pack('!H', len(packet)) + packet)
            
        if ssl_sock in r:
            try:
                # Read length prefix (2 bytes)
                header = ssl_sock.recv(2)
                if not header: break
                length = struct.unpack('!H', header)[0]
                
                # Read packet data
                packet = b''
                while len(packet) < length:
                    chunk = ssl_sock.recv(length - len(packet))
                    if not chunk: break
                    packet += chunk
                
                if packet:
                    if log_packet_size:
                        logging.info(f"SSL -> TUN: {len(packet)} bytes")
                    os.write(tun_fd, packet)
            except ssl.SSLWantReadError:
                continue
            except Exception as e:
                logging.error(f"Tunnel error: {e}")
                break

def main():
    parser = argparse.ArgumentParser(description='SSL TUN Tunnel')
    parser.add_argument('--mode', choices=['server', 'client'], help='Mode of operation')
    parser.add_argument('--port', type=int, default=1443, help='Port to listen on or connect to')
    parser.add_argument('--host', type=str, default='localhost', help='Server host (client mode only)')
    parser.add_argument('--tun-ip', type=str, help='IP/CIDR for tun0 (e.g. 192.168.255.1/24)')
    parser.add_argument('--cert', type=str, default='server.crt', help='Cert file or combined .pem file')
    parser.add_argument('--key', type=str, help='Key file (optional if using combined .pem)')
    parser.add_argument('--generate-pem', type=str, help='Generate a self-signed .pem file and exit')
    parser.add_argument('--log-file', type=str, help='Path to a log file')
    parser.add_argument('--log-packet-size', action='store_true', help='Log every packet size')

    args = parser.parse_args()

    # Configure logging
    log_handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        log_handlers.append(logging.FileHandler(args.log_file))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=log_handlers
    )

    if args.generate_pem:
        generate_pem(args.generate_pem)
        sys.exit(0)

    if not args.mode or not args.tun_ip:
        parser.error("--mode and --tun-ip are required unless using --generate-pem")

    if args.mode == 'server':
        run_server(args.port, args.cert, args.key, args.tun_ip, args.log_packet_size)
    else:
        run_client(args.host, args.port, args.tun_ip, args.log_packet_size)

if __name__ == "__main__":
    main()
