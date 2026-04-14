# SSL TUN Tunnel

A high-performance, secure Layer 3 (IP) tunneling solution written in Python. It mimics the functionality of `socat` for creating SSL-encrypted tunnels between TUN devices.

## Features

- **Layer 3 Tunneling**: Creates virtual `tun0` interfaces to route IP traffic.
- **SSL Encryption**: All traffic between nodes is encrypted using SSL/TLS sockets.
- **Bi-directional Traffic**: Full-duplex communication for seamless networking.
- **PEM Support**: Supports combined `.pem` files for easy certificate management.
- **Auto-Generation**: Built-in utility to generate self-signed certificates.

## Installation

### Prerequisites

- **Linux**: TUN devices are a Linux kernel feature.
- **Python 3.7+**: Required for the tunnel core.
- **OpenSSL**: Required for certificate generation.

### Setup as a Python Package

You can install the tunnel directly as a package:
```bash
pip install .
```

This will install the `ssl-tun-tunnel` command-line tool.

## Usage Examples

### Command Line

**1. Generate a self-signed certificate:**
```bash
ssl-tun-tunnel --generate-pem server.pem
```

**2. Start the Server:**
```bash
sudo ssl-tun-tunnel --mode server --port 1443 --tun-ip 192.168.255.1/24 --cert server.pem
```

**3. Start the Client:**
```bash
sudo ssl-tun-tunnel --mode client --host <SERVER_IP> --port 1443 --tun-ip 192.168.255.2/24
```

## Testing

Run the Python unit tests:
```bash
python3 tests/test_tunnel.py
```

## Security Note

This tool uses self-signed certificates by default. For production environments, it is recommended to use certificates signed by a trusted Certificate Authority (CA) and enable hostname verification in the client.

## License

Apache-2.0
