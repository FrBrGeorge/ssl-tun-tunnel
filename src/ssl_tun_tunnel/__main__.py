import argparse
import sys
import logging
import toml
from pathlib import Path
from typing import Any
from .tunnel import run_server, run_client, generate_pem, get_cert_fingerprint


LEVELS_ORDERED = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]


def parse_address(address_port: str | None, default_address: str | None, default_port: int) -> tuple[str | None, int]:
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


def setup_logging(verbose_args: list[Any] | None, log_file: str | None) -> None:
    """
    Configures the logging levels and handlers.
    
    Args:
        verbose_args (list): List of verbose arguments from argparse (count or string).
        log_file (str): Path to a log file.
    """
    mapping = logging.getLevelNamesMapping()

    # Default levels: ERROR (console), WARNING (file)
    c_idx, f_idx = 1, 2
    count = 0
    explicit_levels = None

    if verbose_args:
        for arg in verbose_args:
            if isinstance(arg, str):
                # Check for -vv / -vvv style where 'v's are captured as the optional argument
                if all(c.lower() == 'v' for c in arg):
                    count += 1 + len(arg)
                else:
                    explicit_levels = arg
                    break
            elif arg is True:
                count += 1

    if explicit_levels:
        try:
            c_lvl_name, f_lvl_name = explicit_levels.split(',', 1)
            c_lvl_name, f_lvl_name = c_lvl_name.upper().strip(), f_lvl_name.upper().strip()
            if c_lvl_name not in mapping or f_lvl_name not in mapping:
                raise ValueError("Invalid level name")
            console_level = mapping[c_lvl_name]
            file_level = mapping[f_lvl_name]
        except (ValueError, IndexError):
            print(f"Error: Invalid logging levels: {explicit_levels}. Must be two valid level names separated by comma.")
            print(f"Available levels: {', '.join(LEVELS_ORDERED)}")
            sys.exit(1)
    else:
        c_idx = min(len(LEVELS_ORDERED) - 1, c_idx + count)
        f_idx = min(len(LEVELS_ORDERED) - 1, f_idx + count)
        console_level = mapping[LEVELS_ORDERED[c_idx]]
        file_level = mapping[LEVELS_ORDERED[f_idx]]

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console_handler)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(file_level)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(fh)


def main() -> None:
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
    parser.add_argument('-v', '--verbose', action='append', nargs='?', const=True, 
                        help=f'Increase output verbosity. Use multiple times (e.g. -vv) or specify levels directly '
                             f'(e.g. -v INFO,DEBUG). Available levels: {", ".join(LEVELS_ORDERED)}')
    parser.add_argument('-b', '--buffered', action='store_true', default=True, help='Enable packet buffering (on by default)')
    parser.add_argument('--no-buffering', action='store_false', dest='buffered', help='Disable packet buffering')
    parser.add_argument('--flush-timeout', type=float, default=1.0, help='Buffer flush timeout in seconds')
    parser.add_argument('--idle-timeout', type=float, help='Idle timeout in seconds to close unused connection')
    parser.add_argument('--reconnect-timeout', type=float, default=60.0, 
                        help='Wait time before reconnecting on error. If 0, exit on error.')
    parser.add_argument('--fill', choices=['all', 'throughput', 'none'], default='throughput', 
                        help='Random fill mode for flushed batches')
    parser.add_argument('--low-latency-dscp', type=str, default='0x48,0xb8', 
                        help='Comma-separated ToS/TC values that trigger immediate flush')
    parser.add_argument('-f', '--fingerprint', nargs='?', const=True, 
                        help='Expected Z85 or HEX fingerprint (client). In server mode, providing this without a '
                             'parameter prints the server fingerprint and exits.')

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

    setup_logging(args.verbose, args.log_file)

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

    cert_path = Path(args.cert)
    if args.mode == 'server' and not cert_path.exists():
        logging.info(f"Certificate {cert_path} not found. Generating automatically...")
        generate_pem(cert_path)

    # Print fingerprint and exit if requested in server mode
    if args.mode == 'server' and args.fingerprint is True:
        z85_fp = get_cert_fingerprint(cert_path, encoding='z85')
        hex_fp = get_cert_fingerprint(cert_path, encoding='hex')
        print(f"Server Fingerprint (Z85): {z85_fp}")
        print(f"Server Fingerprint (HEX): {hex_fp}")
        sys.exit(0)

    if args.mode == 'server':
        run_server(host, port, args.cert, args.key, args.tun_ip, args.buffered, args.flush_timeout, dscp_set, 
                   args.fill, args.idle_timeout, args.reconnect_timeout)
    else:
        run_client(host, port, args.tun_ip, args.fingerprint, args.buffered, args.flush_timeout, dscp_set, 
                   args.fill, args.idle_timeout, args.reconnect_timeout)

if __name__ == "__main__":
    main()
