# SSL TUN Tunnel

A high-performance, secure Layer 3 (IP) tunneling solution written in Python. It mimics the functionality of `socat` for creating SSL-encrypted tunnels between TUN devices.

## Features

- **Layer 3 Tunneling**: Creates virtual `tun0` interfaces to route IP traffic.
- **SSL Encryption**: All traffic between nodes is encrypted using SSL/TLS sockets.
- **Bi-directional Traffic**: Full-duplex communication for seamless networking.
- **PEM Support**: Supports combined `.pem` files for easy certificate management.
- **Auto-Generation**: Built-in utility to generate self-signed certificates.

> **Note**: Creating and configuring TUN devices requires superuser (root) privileges. You will typically need to run these commands with `sudo`.

## Installation

### Prerequisites

- **Linux**: TUN devices are a Linux kernel feature.
- **Python 3.13+**: Required for the tunnel core.
- **OpenSSL**: Required for certificate generation.

### Setup as a Python Package

You can install the tunnel directly as a package:
```bash
pip install .
```

This will install the `ssl-tun-tunnel` command-line tool.

## Usage Examples

### Command Line

The `ssl-tun-tunnel` tool now uses positional arguments for addresses and supports TOML configuration files.

**1. Generate a self-signed certificate:**
```bash
ssl-tun-tunnel -g server.pem
```

**2. Start the Server:**
```bash
# Listen on all interfaces on port 1443
ssl-tun-tunnel 1443 -m server -i 192.168.255.1/24

# Listen on a specific address only
ssl-tun-tunnel 127.0.0.1:1443 -m server -i 192.168.255.1/24
```

**3. Start the Client:**
```bash
# Connect to SERVER_IP:1443. Client mode is the default.
ssl-tun-tunnel <SERVER_IP>:1443 -i 192.168.255.2/24
```

**4. Using a configuration file:**
```bash
ssl-tun-tunnel -c config.toml
```

## Configuration

You can use a TOML file to manage settings. An example `config.toml.example` is included in the package.

```toml
mode = "client"
address = "localhost:1443"
tun_ip = "192.168.255.2/24"
buffered = true
timeout = 1.0
log_packet_size = "none"
```

## Advanced Options

- **Verbosity**: `-v` to increase logging levels for console and file. Supports multiple flags (e.g., `-vv`, `-vvv`) or explicit naming: `-v console_level,file_level` (e.g., `-v INFO,DEBUG`).
  - Available levels: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`.
  - Default: `ERROR` (console), `WARNING` (file).
- **Buffering**: Enabled by default. Use `--no-buffering` to disable.
- **Flush Timeout**: `--flush-timeout <seconds>` (Default: `1.0s`) sets the maximum delay for buffered packets.
- **Idle Timeout**: `--idle-timeout <seconds>` closes the connection if no traffic is detected. In client mode, it will reconnect only when new packets are seen on `tun0`.
- **Reconnect Timeout**: `--reconnect-timeout <seconds>` (Default: `60.0s`) specifies how long to wait before attempting to reconnect after a connection error or close. If set to `0`, the client will exit on error.
- **Priority Flush**: `--low-latency-dscp` (Default: `0x48,0xb8`) flushes buffer immediately on matching IP headers. Enabled by default when buffering is active.
- **Random Fill**: `--fill=all/throughput/none` (Default: `throughput`) to pad batches with random noise to obfuscate traffic patterns.
- **Fingerprint Verification**: `-f` / `--fingerprint <SHA256>` in client mode protects against MITM. 
- **Fingerprint Reporting**: In server mode, run `ssl-tun-tunnel -m server -f` to display the active certificate's fingerprints (Z85 and HEX) and exit.

## Clients

### Linux Client
Standard Python client for Linux machines. Requires root privileges for TUN management.

### Android Client (Non-Root)
A native Android application (located in the `android/` directory) that uses the `VpnService` API to provide a non-root tunnel. It supports:
- **Buffering & Priority Flush**: Configurable timeouts.
- **Random Fill**: Obfuscation modes.
- **Fingerprint Verification**: HEX-based verification.

Building the Android client:
The project includes a GitHub Action to automatically build the `.apk`. You can also build it locally using Gradle:
```bash
cd android
./gradlew assembleDebug
```

## Testing

Run the Python unit tests:
```bash
python3 tests/test_tunnel.py
```

## Security Note

This tool uses self-signed certificates by default. For production environments, it is recommended to use certificates signed by a trusted Certificate Authority (CA) and enable hostname verification in the client.

## License

MIT
