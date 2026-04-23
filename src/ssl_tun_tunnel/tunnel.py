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

import hashlib

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
    except Exception:
        logging.exception(f"Failed to configure IP via 'ip' command for {name}")
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
    except Exception:
        logging.exception(f"Error generating PEM: {filename}")
        sys.exit(1)

def get_cert_fingerprint(certfile):
    try:
        output = subprocess.check_output([
            'openssl', 'x509', '-in', certfile, '-noout', '-fingerprint', '-sha256'
        ], stderr=subprocess.DEVNULL).decode('utf-8')
        return output.strip().split('=')[1]
    except Exception:
        logging.error(f"Failed to get certificate fingerprint for {certfile}", exc_info=True)
        return None

def get_packet_info(packet):
    """Simple parser for basic IP protocol info."""
    if not packet or len(packet) < 20:
        return "Unknown"
    version = packet[0] >> 4
    if version == 4:
        proto = packet[9]
        proto_map = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF'}
        return f"IPv4/{proto_map.get(proto, proto)}"
    elif version == 6:
        if len(packet) < 40: return "IPv6 (Truncated)"
        proto = packet[6]
        # Simplistic next-header check
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
        return f"IPv6/{proto_map.get(proto, proto)}"
    return f"v{version}"

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
    except Exception:
        logging.exception(f"Error loading certificates from {certfile}")
        return

    fingerprint = get_cert_fingerprint(certfile)
    if fingerprint:
        logging.info(f"Server SHA256 Fingerprint: {fingerprint}")

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
        except Exception:
            logging.exception(f"Connection error from {addr}")
        finally:
            client_sock.close()

def run_client(server_host, server_port, tun_ip, log_packet_size=False, expected_fingerprint=None):
    """
    Runs the tunnel in client mode.
    
    Args:
        server_host (str): The server hostname or IP.
        server_port (int): The server port.
        tun_ip (str): IP/CIDR for the TUN interface.
        log_packet_size (bool): Whether to log every packet size.
        expected_fingerprint (str): Expected SHA256 fingerprint of the server certificate.
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
        
        if expected_fingerprint:
            der_cert = ssl_sock.getpeercert(binary_form=True)
            fingerprint = hashlib.sha256(der_cert).hexdigest().upper()
            formatted_fp = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
            
            clean_expected = expected_fingerprint.upper().replace(":", "")
            clean_actual = formatted_fp.replace(":", "")
            
            if clean_actual != clean_expected:
                logging.error("FINGERPRINT MISMATCH!")
                logging.error(f"Expected: {expected_fingerprint.upper()}")
                logging.error(f"Actual:   {formatted_fp}")
                ssl_sock.close()
                return
            logging.info("Certificate fingerprint verified.")

        logging.info("Connected.")
        handle_tunnel(tun_fd, ssl_sock, log_packet_size)
    except Exception:
        logging.exception(f"Connection failed to {server_host}:{server_port}")

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
                logging.info(f"TUN -> SSL: {len(packet)} bytes [{get_packet_info(packet)}]")
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
                        logging.info(f"SSL -> TUN: {len(packet)} bytes [{get_packet_info(packet)}]")
                    os.write(tun_fd, packet)
            except ssl.SSLWantReadError:
                continue
            except Exception:
                logging.exception("Tunnel error during socket processing")
                break
