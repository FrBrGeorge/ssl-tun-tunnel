import os
import fcntl
import struct
import socket
import ssl
import select
import subprocess
import sys
import logging
import hashlib
import time
import base64
from pathlib import Path



# TUN constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Network constants
DEFAULT_MTU = 1500
# Buffer threshold to fit within a single standard Ethernet frame after SSL/TCP overhead.
# 1500 (MTU) - 20 (IP) - 20 (TCP) - 10 (SSL/Length safety) = 1450.
TCP_MSS_FLUSH_THRESHOLD = DEFAULT_MTU - 50


def create_tun(name: str = 'tun0') -> int | None:
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


def configure_ip(name: str, ip_cidr: str) -> None:
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


def generate_pem(filename: str | Path = 'server.pem') -> None:
    """
    Generates a self-signed certificate and private key in a single .pem file.
    
    Args:
        filename (str or Path): The name of the file to save the PEM data to.
    """
    filename = Path(filename)
    logging.info(f"Generating self-signed PEM: {filename}...")
    try:
        # Generate a self-signed certificate and key in one file
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', 
            '-keyout', str(filename), '-out', str(filename), 
            '-days', '365', '-nodes', '-subj', '/CN=localhost'
        ], check=True)
        logging.info(f"Successfully generated {filename}")
    except Exception:
        logging.exception(f"Error generating PEM: {filename}")
        sys.exit(1)


def get_cert_fingerprint(certfile: str | Path, encoding: str = 'z85') -> str | None:
    try:
        output = subprocess.check_output([
            'openssl', 'x509', '-in', str(certfile), '-noout', '-fingerprint', '-sha256'
        ], stderr=subprocess.DEVNULL).decode('utf-8')
        hex_fp = output.strip().split('=')[1].replace(':', '')
        raw_fp = bytes.fromhex(hex_fp)
        if encoding == 'z85':
            return base64.z85encode(raw_fp).decode('ascii')
        return ":".join(hex_fp[i:i+2] for i in range(0, len(hex_fp), 2))
    except Exception:
        logging.error(f"Failed to get certificate fingerprint for {certfile}", exc_info=True)
        return None


def verify_fingerprint(actual_der: bytes, expected_str: str) -> tuple[bool, str]:
    actual_raw = hashlib.sha256(actual_der).digest()
    
    # Try z85 decode first, then hex
    try:
        expected_raw = base64.z85decode(expected_str)
    except Exception:
        try:
            expected_raw = bytes.fromhex(expected_str.replace(':', ''))
        except Exception:
            return False, "Invalid fingerprint format"
            
    if actual_raw == expected_raw:
        return True, ""
        
    actual_z85 = base64.z85encode(actual_raw).decode('ascii')
    actual_hex = ":".join(f"{b:02X}" for b in actual_raw)
    return False, f"Mismatched!\nActual (Z85): {actual_z85}\nActual (HEX): {actual_hex}"


def get_packet_info(packet: bytes) -> str:
    """Simple parser for basic IP protocol info."""
    if not packet or len(packet) < 20:
        return "Unknown"
    version = packet[0] >> 4
    if version == 4:
        proto = packet[9]
        tos = packet[1]
        proto_map = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF'}
        return f"IPv4/{proto_map.get(proto, proto)} ToS=0x{tos:02x}"
    elif version == 6:
        if len(packet) < 40:
            return "IPv6 (Truncated)"
        proto = packet[6]
        tc = (packet[0] & 0x0F) << 4 | (packet[1] >> 4)
        # Simplistic next-header check
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
        return f"IPv6/{proto_map.get(proto, proto)} TC=0x{tc:02x}"
    return f"v{version}"


def is_low_latency(packet: bytes, dscp_set: set[int]) -> bool:
    """Checks if the packet has a low-latency DSCP/ToS value."""
    if not dscp_set or not packet or len(packet) < 2:
        return False
    version = packet[0] >> 4
    if version == 4:
        tos = packet[1]
        return tos in dscp_set
    elif version == 6:
        tc = (packet[0] & 0x0F) << 4 | (packet[1] >> 4)
        return tc in dscp_set
    return False


def run_server(host: str, port: int, certfile: str | Path, keyfile: str | Path | None, 
               tun_ip: str | None, buffered: bool = False, flush_timeout: float = 1.0, 
               low_latency_dscp: set[int] | None = None, fill: str = 'none', 
               idle_timeout: float | None = None, reconnect_timeout: float = 0.0) -> None:
    """
    Runs the tunnel in server mode.
    
    Args:
        host (str): The address to bind to.
        port (int): The port to listen on.
        certfile (str or Path): Path to the certificate file (or PEM containing both).
        keyfile (str or Path): Path to the private key file (optional if certfile is a combined PEM).
        tun_ip (str): IP/CIDR for the TUN interface.
        buffered (bool): Enable packet buffering.
        flush_timeout (float): Buffer flush timeout in seconds.
        low_latency_dscp (set): Set of ToS/TC bytes that trigger immediate flush.
        fill (str): Random fill mode ('all', 'throughput', 'none').
        idle_timeout (float): Idle timeout in seconds to close unused connection.
        reconnect_timeout (float): Not used in server mode for the main listen loop, 
                                  but added for signature consistency.
    """
    tun_fd = create_tun()
    if tun_fd is None:
        return
    if tun_ip:
        configure_ip('tun0', tun_ip)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile) if keyfile else None)
    except Exception:
        logging.exception(f"Error loading certificates from {certfile}")
        return

    fingerprint = get_cert_fingerprint(certfile)
    if fingerprint:
        logging.info(f"Server Fingerprint (Z85): {fingerprint}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)

    logging.info(f"Server listening on {host}:{port}...")

    while True:
        client_sock, addr = server_sock.accept()
        logging.info(f"Connection from {addr}")
        try:
            ssl_sock = context.wrap_socket(client_sock, server_side=True)
            handle_tunnel(tun_fd, ssl_sock, buffered, flush_timeout, low_latency_dscp, fill, idle_timeout)
        except Exception:
            logging.exception(f"Connection error from {addr}")
        finally:
            client_sock.close()


def run_client(server_host: str, server_port: int, tun_ip: str | None, 
               expected_fingerprint: str | None = None, buffered: bool = False, 
               flush_timeout: float = 1.0, low_latency_dscp: set[int] | None = None, 
               fill: str = 'none', idle_timeout: float | None = None, 
               reconnect_timeout: float = 0.0) -> None:
    """
    Runs the tunnel in client mode.
    
    Args:
        server_host (str): The server hostname or IP.
        server_port (int): The server port.
        tun_ip (str): IP/CIDR for the TUN interface.
        expected_fingerprint (str): Expected Z85 or HEX fingerprint of the server certificate.
        buffered (bool): Enable packet buffering.
        flush_timeout (float): Buffer flush timeout in seconds.
        low_latency_dscp (set): Set of ToS/TC bytes that trigger immediate flush.
        fill (str): Random fill mode ('all', 'throughput', 'none').
        idle_timeout (float): Idle timeout in seconds to close unused connection.
        reconnect_timeout (float): Wait time before reconnecting on error. If 0, exit on error.
    """
    tun_fd = create_tun()
    if tun_fd is None:
        return
    if tun_ip:
        configure_ip('tun0', tun_ip)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(sock, server_hostname=server_host)
        
        logging.info(f"Connecting to {server_host}:{server_port}...")
        try:
            ssl_sock.connect((server_host, server_port))
            
            if expected_fingerprint:
                der_cert = ssl_sock.getpeercert(binary_form=True)
                success, error_msg = verify_fingerprint(der_cert, expected_fingerprint)
                
                if not success:
                    logging.error(f"FINGERPRINT ERROR: {error_msg}")
                    ssl_sock.close()
                    if reconnect_timeout == 0:
                        sys.exit(1)
                    logging.warning(f"Retrying in {reconnect_timeout} seconds...")
                    time.sleep(reconnect_timeout)
                    continue
                logging.info("Certificate fingerprint verified.")

            logging.info("Connected.")
            was_idle = handle_tunnel(tun_fd, ssl_sock, buffered, flush_timeout, low_latency_dscp, fill, idle_timeout)
            if not was_idle:
                if reconnect_timeout == 0:
                    logging.error("Connection closed or error occurred. Exiting.")
                    sys.exit(1)
                else:
                    logging.warning(f"Connection error or closed. Reconnecting in {reconnect_timeout} seconds...")
                    time.sleep(reconnect_timeout)
        except Exception as e:
            if reconnect_timeout == 0:
                logging.error(f"Connection failed to {server_host}:{server_port}: {e}")
                sys.exit(1)
            else:
                logging.warning(f"Connection failed to {server_host}:{server_port}. "
                                f"Reconnecting in {reconnect_timeout} seconds...")
                time.sleep(reconnect_timeout)
        finally:
            try:
                ssl_sock.close()
            except:
                pass
        
        if idle_timeout:
            logging.info(f"Idle or disconnected. Waiting for packets on tun0 before reconnecting...")
            # Wait for data on TUN device
            r, _, _ = select.select([tun_fd], [], [])
            if not r:
                continue


def handle_tunnel(tun_fd: int, ssl_sock: ssl.SSLSocket, buffered: bool = False, flush_timeout: float = 1.0, 
                  low_latency_dscp: set[int] | None = None, fill: str = 'none', 
                  idle_timeout: float | None = None) -> bool:
    """
    Handles the bidirectional traffic between the TUN device and the SSL socket.
    
    Args:
        tun_fd (int): File descriptor of the TUN device.
        ssl_sock (ssl.SSLSocket): The established SSL socket.
        buffered (bool): Enable packet buffering for TUN -> SSL.
        flush_timeout (float): Buffer flush timeout in seconds.
        low_latency_dscp (set): Set of ToS/TC bytes that trigger immediate flush.
        fill (str): Random fill mode ('all', 'throughput', 'none').
        idle_timeout (float): Idle timeout in seconds to close unused connection.
    """
    ssl_sock.setblocking(0)
    
    # Buffering state
    pkt_buffer = []
    buffer_bytes = 0
    last_flush = time.time()
    last_activity = time.time()
    
    JUNK_BIT = 0x8000

    def flush_buffer(is_low_latency_triggered=False):
        nonlocal pkt_buffer, buffer_bytes, last_flush, last_activity
        if not pkt_buffer:
            return
        
        data = b''
        bunch_info = []
        wire_bytes = 0
        for p in pkt_buffer:
            data += struct.pack('!H', len(p)) + p
            wire_bytes += len(p) + 2
            bunch_info.append(f"{len(p)}[{get_packet_info(p)}]")
        
        # Apply random fill
        do_fill = (fill == 'all') or (fill == 'throughput' and not is_low_latency_triggered)
        if do_fill:
            space_left = TCP_MSS_FLUSH_THRESHOLD - wire_bytes
            if space_left >= 2:
                junk_len = space_left - 2
                junk_data = os.urandom(junk_len)
                data += struct.pack('!H', junk_len | JUNK_BIT) + junk_data
                bunch_info.append(f"{junk_len}[JUNK]")
        
        logging.debug(f"TUN -> SSL [BUNCH]: {len(pkt_buffer)} pkts, total {len(data)} bytes on wire. "
                      f"Details: {', '.join(bunch_info)}")
            
        ssl_sock.sendall(data)
        pkt_buffer = []
        buffer_bytes = 0
        now = time.time()
        last_flush = now
        last_activity = now
    
    while True:
        now = time.time()
        sel_timeout = None
        
        if idle_timeout:
            # Calculate when the next idle timeout would happen
            time_until_idle = max(0, idle_timeout - (now - last_activity))
            sel_timeout = time_until_idle

        if buffered and pkt_buffer:
            time_until_flush = max(0, flush_timeout - (now - last_flush))
            if sel_timeout is None or time_until_flush < sel_timeout:
                sel_timeout = time_until_flush
            
        r, w, x = select.select([tun_fd, ssl_sock], [], [], sel_timeout)
        
        now = time.time()
        
        # Check idle timeout
        if idle_timeout and (now - last_activity) >= idle_timeout:
            logging.warning(f"Idle timeout ({idle_timeout}s) exceeded. Closing connection.")
            return True

        # Flush if flush_timeout or buffer large enough
        if buffered and pkt_buffer:
            if not r or buffer_bytes >= TCP_MSS_FLUSH_THRESHOLD or (now - last_flush) >= flush_timeout:
                flush_buffer()
        
        if tun_fd in r:
            try:
                packet = os.read(tun_fd, 2048)
                if not packet:
                    return False
            except Exception:
                logging.exception("Error reading from TUN device")
                return False
            
            last_activity = now
            
            if buffered:
                pkt_buffer.append(packet)
                buffer_bytes += len(packet)
                is_ll = is_low_latency(packet, low_latency_dscp)
                if buffer_bytes >= TCP_MSS_FLUSH_THRESHOLD or is_ll:
                    flush_buffer(is_ll)
            else:
                logging.debug(f"TUN -> SSL: {len(packet)} bytes [{get_packet_info(packet)}]")
                # Send length-prefixed packet over SSL
                try:
                    ssl_sock.sendall(struct.pack('!H', len(packet)) + packet)
                except Exception:
                    logging.exception("Error sending over SSL")
                    return False
            
        if ssl_sock in r:
            last_activity = now
            try:
                # We might receive multiple packets in the socket buffer
                should_break = False
                while True:
                    try:
                        header = ssl_sock.recv(2)
                    except ssl.SSLWantReadError:
                        break # Go back to select
                        
                    if not header:
                        should_break = True
                        break # EOF
                    
                    val = struct.unpack('!H', header)[0]
                    is_junk = bool(val & JUNK_BIT)
                    length = val & ~JUNK_BIT
                    
                    # Read packet data
                    packet = b''
                    while len(packet) < length:
                        chunk = ssl_sock.recv(length - len(packet))
                        if not chunk:
                            should_break = True
                            break
                        packet += chunk
                    
                    if packet and not is_junk:
                        logging.debug(f"SSL -> TUN: {len(packet)} bytes [{get_packet_info(packet)}]")
                        try:
                            os.write(tun_fd, packet)
                        except Exception:
                            logging.exception("Error writing to TUN interface")
                            return False
                    elif packet and is_junk:
                        logging.debug(f"SSL -> TUN: {len(packet)} bytes [JUNK - dropped]")
                    
                    if should_break:
                        break
                
                if should_break:
                    return False

            except ssl.SSLWantReadError:
                continue
            except Exception:
                logging.exception("Tunnel error during socket processing")
                return False
