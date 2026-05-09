import unittest
import logging
import sys
import os
import struct
from pathlib import Path

# Ensure local src is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from unittest.mock import MagicMock, patch

from ssl_tun_tunnel.__main__ import parse_address, setup_logging
from ssl_tun_tunnel.tunnel import get_packet_info, is_low_latency, verify_fingerprint, get_cert_fingerprint

class TestUtils(unittest.TestCase):
    def test_parse_address(self):
        # host:port
        self.assertEqual(parse_address("1.2.3.4:8080", "0.0.0.0", 443), ("1.2.3.4", 8080))
        # port only
        self.assertEqual(parse_address("9090", "127.0.0.1", 443), ("127.0.0.1", 9090))
        # host only (might be interpreted as host if default_port is used)
        self.assertEqual(parse_address("example.com", "0.0.0.0", 443), ("example.com", 443))
        # empty
        self.assertEqual(parse_address(None, "0.0.0.0", 443), ("0.0.0.0", 443))
        # invalid port
        with self.assertRaises(ValueError):
            parse_address("host:invalid", "0.0.0.0", 443)

    def test_get_packet_info_ipv4(self):
        # IPv4, TCP (6), ToS 0x00
        packet = struct.pack('!BBH HH BB H 4s 4s', 
                             0x45, 0x00, 40,   # Version/IHL, ToS, Total Length
                             0, 0,             # ID, Flags/Offset
                             64, 6, 0,         # TTL, Protocol (TCP), Checksum
                             b'\x00'*4, b'\x00'*4) # Src, Dst
        info = get_packet_info(packet)
        self.assertIn("IPv4/TCP", info)
        self.assertIn("ToS=0x00", info)

    def test_get_packet_info_ipv6(self):
        # IPv6, UDP (17), TC 0x00
        # Version (6), TC (0), Flow (0) -> 0x60000000
        # Payload len (0), Next header (17), Hop limit (64)
        packet = struct.pack('!IHBB 16s 16s',
                             0x60000000, 0, 17, 64,
                             b'\x00'*16, b'\x00'*16)
        info = get_packet_info(packet)
        self.assertIn("IPv6/UDP", info)
        self.assertIn("TC=0x00", info)

    def test_is_low_latency_ipv4(self):
        packet_ll = struct.pack('!BB', 0x45, 0x48) # ToS 0x48
        packet_normal = struct.pack('!BB', 0x45, 0x00)
        dscp_set = {0x48, 0xb8}
        
        self.assertTrue(is_low_latency(packet_ll, dscp_set))
        self.assertFalse(is_low_latency(packet_normal, dscp_set))

    def test_is_low_latency_ipv6(self):
        # TC 0x48 in IPv6 Header (Traffic Class is bits 4-11)
        # 0x60 0x48 ... -> TC is 0x48
        packet_ll = struct.pack('!BB', 0x64, 0x80) # Version 6, TC high bits 0100, TC low bits 1000 -> 0x48
        packet_normal = struct.pack('!BB', 0x60, 0x00)
        dscp_set = {0x48}
        
        self.assertTrue(is_low_latency(packet_ll, dscp_set))
        self.assertFalse(is_low_latency(packet_normal, dscp_set))

    def test_verify_fingerprint(self):
        der = b"some cert der"
        import hashlib
        fp_raw = hashlib.sha256(der).digest()
        import base64
        z85_fp = base64.z85encode(fp_raw).decode('ascii')
        hex_fp = fp_raw.hex(':').upper()
        
        self.assertTrue(verify_fingerprint(der, z85_fp)[0])
        self.assertTrue(verify_fingerprint(der, hex_fp)[0])
        self.assertFalse(verify_fingerprint(der, "wrong")[0])

    @patch('subprocess.check_output')
    def test_get_cert_fingerprint(self, mock_output):
        # Mock openssl output
        mock_output.return_value = b"SHA256 Fingerprint=AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00\n"
        
        fp = get_cert_fingerprint("fake.pem", encoding='hex')
        self.assertEqual(fp, "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00")
        
        fp_z85 = get_cert_fingerprint("fake.pem", encoding='z85')
        self.assertIsNotNone(fp_z85)

    @patch('subprocess.run')
    def test_generate_pem(self, mock_run):
        from ssl_tun_tunnel.tunnel import generate_pem
        generate_pem("test.pem")
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertIn('openssl', args)
        self.assertIn('req', args)
        self.assertIn('test.pem', args)

    def test_setup_logging_basic(self):
        # Just ensure it doesn't crash
        setup_logging([True], None) # -v
        setup_logging(["DEBUG,INFO"], None) # -v DEBUG,INFO
        setup_logging(None, None)

if __name__ == '__main__':
    unittest.main()
