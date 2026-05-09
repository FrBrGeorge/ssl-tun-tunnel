import unittest
from unittest.mock import MagicMock, patch
import struct
import io
import os
import sys
import time
import itertools

# Ensure local src is in path BEFORE anything else
LIB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../src'))
if LIB_PATH not in sys.path:
    sys.path.insert(0, LIB_PATH)

# Purge any existing imports to force local ones
for mod in list(sys.modules.keys()):
    if mod.startswith('ssl_tun_tunnel'):
        del sys.modules[mod]

import ssl_tun_tunnel.tunnel as tunnel_mod
from ssl_tun_tunnel.tunnel import handle_tunnel

class TestTunnelLogic(unittest.TestCase):
    def setUp(self):
        # Common setup for mocks
        self.mock_ssl_sock = MagicMock()
        # Default pending() to 0 to avoid TypeError in tunnel.py
        self.mock_ssl_sock.pending.return_value = 0
        self.mock_tun_fd = 10

    def test_packet_framing_send(self):
        """Test that packets are correctly length-prefixed when sent."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # Mock os.read to return a small packet then empty to break loop
        with patch('os.read', side_effect=[b'HELLO', b'']):
            # Mock select.select to return tun_fd in ready list once
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([], [], []), ([], [], [])]):
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=False)
                except Exception:
                    pass
        
        # Check if sendall was called with length-prefixed packet
        expected_call = struct.pack('!H', 5) + b'HELLO'
        mock_ssl_sock.sendall.assert_any_call(expected_call)

    def test_packet_framing_receive(self):
        """Test that length-prefixed packets are correctly read and written to TUN."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # Prepare a length-prefixed packet: length 4 + 'DATA'
        packet_data = b'DATA'
        header = struct.pack('!H', len(packet_data))
        
        # Mock ssl_sock.recv to return header then data, then break loop
        mock_ssl_sock.recv.side_effect = [header + packet_data, ssl.SSLWantReadError(), b'']
        
        # Mock select.select to return ssl_sock in ready list once
        with patch('select.select', side_effect=[([mock_ssl_sock], [], []), ([], [], []), ([], [], [])]):
            with patch('os.write') as mock_write:
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=False)
                except Exception:
                    pass
                
                # Check if os.write was called with the correct data
                mock_write.assert_any_call(mock_tun_fd, b'DATA')

    def test_junk_packet_receive(self):
        """Test that junk packets (J bit set) are ignored."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # Prepare a junk packet: bit 15 is set in length
        JUNK_BIT = 0x8000
        junk_len = 10
        header = struct.pack('!H', junk_len | JUNK_BIT)
        junk_data = b'A' * junk_len
        
        mock_ssl_sock.recv.side_effect = [header + junk_data, ssl.SSLWantReadError(), b'']
        
        with patch('select.select', side_effect=[([mock_ssl_sock], [], []), ([], [], []), ([], [], [])]):
            with patch('os.write') as mock_write:
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=False)
                except Exception:
                    pass
                
                # os.write should NOT be called for junk
                self.assertFalse(mock_write.called)

    def test_random_fill_send(self):
        """Test that random fill adds junk packets to flushed batches."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # Threshold is DEFAULT_MTU - 50 = 1450
        packet = b'B' * 1000
        
        # Provide plenty of timestamps
        times = [100.0] * 10 + [110.0] * 50
        
        with patch('os.read', side_effect=[packet, b'']):
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([], [], []), ([], [], []), ([], [], [])]):
                with patch('ssl_tun_tunnel.tunnel.os.urandom', return_value=b'J'*446) as mock_urandom:
                    with patch('ssl_tun_tunnel.tunnel.time.time', side_effect=times):
                        try:
                            handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=True, fill='all', flush_timeout=1.0)
                        except Exception:
                            pass
        
        # Check if os.urandom was called
        self.assertTrue(mock_urandom.called, "os.urandom was not called")
        mock_urandom.assert_called_with(446)
        
        # Check if sendall was called with both data and junk
        JUNK_BIT = 0x8000
        expected_batch = struct.pack('!H', 1000) + packet + struct.pack('!H', 446 | JUNK_BIT) + b'J'*446
        mock_ssl_sock.sendall.assert_any_call(expected_batch)

    def test_buffering_logic(self):
        """Test that packets are buffered and flushed reasonably."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # Provide even more timestamps
        times = [100.0] * 40 + [110.0] * 40
        
        with patch('select.select', side_effect=[
            ([mock_tun_fd], [], []), # read P1
            ([mock_tun_fd], [], []), # read P2
            ([], [], []),             # timeout -> trigger flush
            ([], [], []),             # break
        ]):
            # Mock os.read to return b'' on the last call to break loop
            with patch('os.read', side_effect=[b'P1', b'P2', b'']):
                with patch('time.time', side_effect=times):
                    try:
                        handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=True, flush_timeout=1.0, fill='none')
                    except Exception:
                        pass
        
        # Check if sendall was called. It should bundle P1 and P2.
        expected_batch = struct.pack('!H', 2) + b'P1' + struct.pack('!H', 2) + b'P2'
        mock_ssl_sock.sendall.assert_any_call(expected_batch)

    def test_low_latency_flush(self):
        """Test that low-latency packets trigger immediate flush even when buffered."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # IPv4, ICMP (1), ToS 0x48 (LL)
        ll_packet = struct.pack('!BBH HH BB H 4s 4s', 
                                0x45, 0x48, 40,   # Version/IHL, ToS 0x48, Total Length
                                0, 0,             # ID, Flags/Offset
                                64, 1, 0,         # TTL, Protocol (ICMP), Checksum
                                b'\x00'*4, b'\x00'*4)
        
        # Plenty of timestamps
        times = [100.0] * 100
        
        with patch('os.read', side_effect=[ll_packet, b'']):
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([mock_tun_fd], [], []), ([], [], [])]):
                with patch('time.time', side_effect=times):
                    try:
                        handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=True, low_latency_dscp={0x48})
                    except Exception:
                        pass
        
        expected_batch = struct.pack('!H', len(ll_packet)) + ll_packet
        mock_ssl_sock.sendall.assert_any_call(expected_batch)

    def test_idle_timeout(self):
        """Test that idle timeout closes the connection."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # select.select returns nothing (timeout)
        with patch('select.select', return_value=([], [], [])):
            # Provide plenty of timestamps
            times = [100.0] * 10 + [115.0] * 100
            with patch('ssl_tun_tunnel.tunnel.time.time', side_effect=times):
                result = handle_tunnel(mock_tun_fd, mock_ssl_sock, idle_timeout=10.0)
                self.assertTrue(result) # result=True means was_idle

    def test_mtu_sized_packet(self):
        """Test that a packet exactly at MTU limit is handled correctly."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        mtu_packet = b'M' * 1500
        
        with patch('os.read', side_effect=[mtu_packet, b'']):
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([], [], []), ([], [], [])]):
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=False)
                except Exception:
                    pass
        
        expected_call = struct.pack('!H', 1500) + mtu_packet
        mock_ssl_sock.sendall.assert_any_call(expected_call)

    def test_ipv6_low_latency_flush(self):
        """Test that IPv6 Traffic Class (ToS equivalent) triggers immediate flush."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # IPv6 header: Version=6, TC=0xB8, FlowLabel=0, PayloadLength=0, NextHeader=59 (No Next), HopLimit=64
        # TC 0xB8: First 4 bits in packet[0], next 4 bits in packet[1]. 
        # TC 0xB8 is 1011 1000. 
        # packet[0] = (6 << 4) | (0xB8 >> 4) = 0x60 | 0x0B = 0x6B
        # packet[1] = (0xB8 & 0x0F) << 4 = 0x80
        ipv6_ll_packet = bytes([0x6B, 0x80]) + b'\x00' * 38
        
        times = [100.0] * 100
        with patch('os.read', side_effect=[ipv6_ll_packet, b'']):
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([], [], []), ([], [], [])]):
                with patch('time.time', side_effect=times):
                    try:
                        handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=True, low_latency_dscp={0xb8})
                    except Exception:
                        pass
        
        expected_batch = struct.pack('!H', len(ipv6_ll_packet)) + ipv6_ll_packet
        mock_ssl_sock.sendall.assert_any_call(expected_batch)

    def test_multiple_packets_in_single_ssl_recv(self):
        """Test that receiving multiple packets in a single SSL recv() works correctly."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        p1 = b'PACKET1'
        p2 = b'PACKET2'
        p3 = b'PACKET3'
        
        combined = (struct.pack('!H', len(p1)) + p1 + 
                   struct.pack('!H', len(p2)) + p2 + 
                   struct.pack('!H', len(p3)) + p3)
        
        # Mocking recv to return all at once, then break
        mock_ssl_sock.recv.side_effect = [combined, ssl.SSLWantReadError(), b'']
        
        # Mocking select
        with patch('select.select', side_effect=[([mock_ssl_sock], [], []), ([], [], []), ([], [], [])]):
            with patch('os.write') as mock_write:
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=False)
                except Exception:
                    pass
                
                # Verify all three were written
                mock_write.assert_any_call(mock_tun_fd, p1)
                mock_write.assert_any_call(mock_tun_fd, p2)
                mock_write.assert_any_call(mock_tun_fd, p3)
                self.assertEqual(mock_write.call_count, 3)

    def test_buffer_threshold_flush(self):
        """Test that the buffer flushes automatically when reaching the MSS threshold."""
        mock_tun_fd = self.mock_tun_fd
        mock_ssl_sock = self.mock_ssl_sock
        
        # Threshold is MTU - 50 = 1450
        # Packet 1: 1000 bytes
        # Packet 2: 500 bytes -> triggers flush (total 1500 > 1450)
        p1 = b'1' * 1000
        p2 = b'2' * 500
        
        times = [100.0] * 100
        with patch('os.read', side_effect=[p1, p2, b'']):
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([mock_tun_fd], [], []), ([], [], []), ([], [], [])]):
                with patch('time.time', side_effect=times):
                    try:
                        handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=True, fill='none')
                    except Exception:
                        pass
        
        # Should have captured Packet 1 and Packet 2 together
        expected_batch = struct.pack('!H', 1000) + p1 + struct.pack('!H', 500) + p2
        mock_ssl_sock.sendall.assert_any_call(expected_batch)

if __name__ == '__main__':
    unittest.main()
