import argparse
import sys
import logging
import os
from .tunnel import run_server, run_client, generate_pem

def main():
    parser = argparse.ArgumentParser(description='SSL TUN Tunnel')
    parser.add_argument('-m', '--mode', choices=['server', 'client'], help='Mode of operation')
    parser.add_argument('-p', '--port', type=int, default=1443, help='Port to listen on or connect to')
    parser.add_argument('-H', '--host', type=str, default='localhost', help='Server host (client mode only)')
    parser.add_argument('-i', '--tun-ip', type=str, help='IP/CIDR for tun0 (e.g. 192.168.255.1/24)')
    parser.add_argument('--cert', type=str, default='server.pem', help='Cert file or combined .pem file')
    parser.add_argument('--key', type=str, help='Key file (optional if using combined .pem)')
    parser.add_argument('-g', '--generate', type=str, help='Generate a self-signed .pem file and exit')
    parser.add_argument('-l', '--log-file', type=str, help='Path to a log file')
    parser.add_argument('--log-packet-size', action='store_true', help='Log every packet size')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('--fingerprint', type=str, help='Expected SHA256 fingerprint of the server certificate (client mode)')

    args = parser.parse_args()

    # Determine log levels
    console_level = logging.WARNING
    file_level = logging.INFO
    
    if args.verbose:
        console_level = logging.INFO
        file_level = logging.DEBUG

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG) # Allow all to pass to handlers
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(file_level)
        file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    if args.generate:
        generate_pem(args.generate)
        sys.exit(0)

    # Logic for auto-generating cert if not found
    if args.mode == 'server' and not os.path.exists(args.cert):
        logging.info(f"Certificate {args.cert} not found. Generating automatically...")
        generate_pem(args.cert)

    if not args.mode or not args.tun_ip:
        parser.error("--mode and --tun-ip are required unless using --generate")

    if args.mode == 'server':
        run_server(args.port, args.cert, args.key, args.tun_ip, args.log_packet_size)
    else:
        run_client(args.host, args.port, args.tun_ip, args.log_packet_size, args.fingerprint)

if __name__ == "__main__":
    main()
