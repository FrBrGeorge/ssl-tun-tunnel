import argparse
import sys
import logging
import os
import toml
from .tunnel import run_server, run_client, generate_pem

def main():
    parser = argparse.ArgumentParser(description='SSL TUN Tunnel')
    parser.add_argument('address', nargs='?', help='Server address (host:port) or listening port (port)')
    parser.add_argument('-m', '--mode', choices=['server', 'client'], help='Mode of operation (default: client)')
    parser.add_argument('-c', '--config', type=str, help='Path to an optional TOML configuration file')
    parser.add_argument('-i', '--tun-ip', type=str, help='IP/CIDR for tun0 (e.g. 192.168.255.1/24)')
    parser.add_argument('--cert', type=str, help='Cert file or combined .pem file (default: server.pem)')
    parser.add_argument('--key', type=str, help='Key file (optional if using combined .pem)')
    parser.add_argument('-g', '--generate', type=str, help='Generate a self-signed .pem file and exit')
    parser.add_argument('-l', '--log-file', type=str, help='Path to a log file')
    parser.add_argument('--log-packet-size', choices=['in', 'out', 'both', 'none'], help='Granular packet logging (default: out)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('-b', '--buffered', action='store_true', help='Enable packet buffering')
    parser.add_argument('-t', '--timeout', type=float, help='Buffer flush timeout in seconds (default: 1.0)')
    parser.add_argument('--low-latency-dscp', type=str, help='Comma-separated ToS/TC values that trigger immediate flush (default: 0x48,0xb8)')
    parser.add_argument('--fingerprint', type=str, help='Expected SHA256 fingerprint (client mode)')

    args = parser.parse_args()

    # Load config file if provided
    config = {}
    if args.config:
        if not os.path.exists(args.config):
            print(f"Error: Config file not found: {args.config}")
            sys.exit(1)
        try:
            config = toml.load(args.config)
        except Exception as e:
            print(f"Error parsing config file: {e}")
            sys.exit(1)

    # Helper to get value from args (if provided) or config or default
    def get_val(name, default=None):
        arg_val = getattr(args, name.replace('-', '_'))
        if arg_val is not None and arg_val is not False: # bool check for action='store_true'
            return arg_val
        return config.get(name.replace('-', '_'), default)

    # Determine final values
    mode = get_val('mode', 'client')
    address = get_val('address')
    tun_ip = get_val('tun_ip')
    cert = get_val('cert', 'server.pem')
    key = get_val('key')
    log_file = get_val('log_file')
    log_packet_size = get_val('log_packet_size', 'none')
    if log_packet_size == 'none': log_packet_size = ''
    verbose = get_val('verbose', False)
    buffered = get_val('buffered', False)
    timeout = get_val('timeout', 1.0)
    low_latency_dscp_str = get_val('low_latency_dscp', '0x48,0xb8')
    fingerprint = get_val('fingerprint')

    # Determine log levels
    console_level = logging.WARNING
    file_level = logging.INFO
    if verbose:
        console_level = logging.INFO
        file_level = logging.DEBUG

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console_handler)
    
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(file_level)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(fh)

    if args.generate:
        generate_pem(args.generate)
        sys.exit(0)

    if not address or not tun_ip:
        if not args.generate:
            parser.print_help()
            print("\nError: address and --tun-ip are required (or via config file)")
            sys.exit(1)

    # Parse address
    host = 'localhost'
    port = 1443
    if mode == 'server':
        try:
            port = int(address)
        except ValueError:
            print(f"Error: Server address must be a port number: {address}")
            sys.exit(1)
    else:
        if ':' in address:
            host, port_str = address.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                print(f"Error: Invalid port in address: {address}")
                sys.exit(1)
        else:
            host = address
            # use default port 1443

    # Parse low-latency DSCP values
    dscp_set = set()
    try:
        for val in low_latency_dscp_str.split(','):
            val = val.strip()
            if val.startswith('0x'): dscp_set.add(int(val, 16))
            else: dscp_set.add(int(val))
    except ValueError as e:
        print(f"Error: Invalid DSCP values: {e}")
        sys.exit(1)

    # Logic for auto-generating cert if not found
    if mode == 'server' and not os.path.exists(cert):
        logging.info(f"Certificate {cert} not found. Generating automatically...")
        generate_pem(cert)

    if mode == 'server':
        run_server(port, cert, key, tun_ip, log_packet_size, buffered, timeout, dscp_set)
    else:
        run_client(host, port, tun_ip, log_packet_size, fingerprint, buffered, timeout, dscp_set)

if __name__ == "__main__":
    main()
