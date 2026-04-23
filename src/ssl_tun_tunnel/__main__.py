import argparse
import sys
import logging
import toml
from pathlib import Path
from .tunnel import run_server, run_client, generate_pem

def parse_address(address_port, default_address, default_port):
    """
    Parses an address string into a tuple of (host, port).
    
    Args:
        address_port (str): The address string (e.g. 'host:port' or 'port').
        default_address (str): The default address if not specified.
        default_port (int): The default port if not specified.
        
    Returns:
        tuple: (host, port)
    """
    if not address_port:
        return default_address, default_port
    
    if ':' in address_port:
        host, port_str = address_port.split(':', 1)
        try:
            return host, int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port in address: {address_port}")
    else:
        # Check if it's just a port or just a host
        try:
            return default_address, int(address_port)
        except ValueError:
            return address_port, default_port

def main():
    # Pre-parse for config file
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('-c', '--config', type=str)
    pre_args, _ = pre_parser.parse_known_args()

    config = {}
    if pre_args.config:
        config_path = Path(pre_args.config)
        if not config_path.exists():
            print(f"Error: Config file not found: {config_path}")
            sys.exit(1)
        try:
            config = toml.load(config_path)
        except Exception as e:
            print(f"Error parsing config file: {e}")
            sys.exit(1)

    parser = argparse.ArgumentParser(
        description='SSL TUN Tunnel',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.set_defaults(**config)

    parser.add_argument('address', nargs='?', help='Server address (host:port) or listening port (port)')
    parser.add_argument('-m', '--mode', choices=['server', 'client'], default='client', help='Mode of operation')
    parser.add_argument('-c', '--config', type=str, help='Path to an optional TOML configuration file')
    parser.add_argument('-i', '--tun-ip', type=str, help='IP/CIDR for tun0 (e.g. 192.168.255.1/24)')
    parser.add_argument('--cert', type=str, default='server.pem', help='Cert file or combined .pem file')
    parser.add_argument('--key', type=str, help='Key file (optional if using combined .pem)')
    parser.add_argument('-g', '--generate', type=str, help='Generate a self-signed .pem file and exit')
    parser.add_argument('-l', '--log-file', type=str, help='Path to a log file')
    parser.add_argument('--log-packet-size', choices=['in', 'out', 'both', 'none'], default='none', help='Granular packet logging')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('-b', '--buffered', action='store_true', help='Enable packet buffering')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Buffer flush timeout in seconds')
    parser.add_argument('--low-latency-dscp', type=str, default='0x48,0xb8', help='Comma-separated ToS/TC values that trigger immediate flush')
    parser.add_argument('--fingerprint', type=str, help='Expected SHA256 fingerprint (client mode)')

    args = parser.parse_args()

    if args.generate:
        generate_pem(args.generate)
        sys.exit(0)

    # Determine defaults based on mode
    if args.mode == 'server':
        default_host = '0.0.0.0'
    else:
        if not args.address:
            parser.error("address is required in client mode")
        default_host = None # address_port is provided

    try:
        host, port = parse_address(args.address, default_host, 1443)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Determine log levels
    console_level = logging.INFO if args.verbose else logging.WARNING
    file_level = logging.DEBUG if args.verbose else logging.INFO

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console_handler)
    
    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        fh.setLevel(file_level)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(fh)

    # Parse low-latency DSCP values
    dscp_set = set()
    try:
        for val in args.low_latency_dscp.split(','):
            val = val.strip()
            if val.startswith('0x'): dscp_set.add(int(val, 16))
            else: dscp_set.add(int(val))
    except ValueError as e:
        print(f"Error: Invalid DSCP values: {e}")
        sys.exit(1)

    log_packet_size = args.log_packet_size if args.log_packet_size != 'none' else ''

    cert_path = Path(args.cert)
    if args.mode == 'server' and not cert_path.exists():
        logging.info(f"Certificate {cert_path} not found. Generating automatically...")
        generate_pem(cert_path)

    if args.mode == 'server':
        run_server(host, port, args.cert, args.key, args.tun_ip, log_packet_size, args.buffered, args.timeout, dscp_set)
    else:
        run_client(host, port, args.tun_ip, log_packet_size, args.fingerprint, args.buffered, args.timeout, dscp_set)

if __name__ == "__main__":
    main()
