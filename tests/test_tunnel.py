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
    def test_packet_framing_send(self):
        """Test that packets are correctly length-prefixed when sent."""
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        
        # Mock os.read to return a small packet then empty to break loop
        with patch('os.read', side_effect=[b'HELLO', b'']):
            # Mock select.select to return tun_fd in ready list once
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([], [], [])]):
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock)
                except StopIteration:
                    pass
                except Exception:
                    pass
        
        # Check if sendall was called with length-prefixed packet
        # length of 'HELLO' is 5. !H for 5 is \x00\x05
        expected_call = struct.pack('!H', 5) + b'HELLO'
        mock_ssl_sock.sendall.assert_any_call(expected_call)

    def test_packet_framing_receive(self):
        """Test that length-prefixed packets are correctly read and written to TUN."""
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        
        # Prepare a length-prefixed packet: length 4 + 'DATA'
        packet_data = b'DATA'
        header = struct.pack('!H', len(packet_data))
        
        # Mock ssl_sock.recv to return header then data
        mock_ssl_sock.recv.side_effect = [header, packet_data, b'']
        
        # Mock select.select to return ssl_sock in ready list once
        with patch('select.select', side_effect=[([mock_ssl_sock], [], []), ([], [], [])]):
            with patch('os.write') as mock_write:
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock)
                except Exception:
                    pass
                
                # Check if os.write was called with the correct data
                mock_write.assert_any_call(mock_tun_fd, b'DATA')

    def test_junk_packet_receive(self):
        """Test that junk packets (J bit set) are ignored."""
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        
        # Prepare a junk packet: bit 15 is set in length
        JUNK_BIT = 0x8000
        junk_len = 10
        header = struct.pack('!H', junk_len | JUNK_BIT)
        junk_data = b'A' * junk_len
        
        mock_ssl_sock.recv.side_effect = [header, junk_data, b'']
        
        with patch('select.select', side_effect=[([mock_ssl_sock], [], []), ([], [], [])]):
            with patch('os.write') as mock_write:
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock)
                except Exception:
                    pass
                
                # os.write should NOT be called for junk
                self.assertFalse(mock_write.called)

    def test_random_fill_send(self):
        """Test that random fill adds junk packets to flushed batches."""
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        
        # Threshold is DEFAULT_MTU - 50 = 1450
        packet = b'B' * 1000
        
        # Use a generator for time to avoid StopIteration
        time_gen = itertools.count(100.0, 0.1)
        # Advance time significantly for flush trigger
        def mock_time():
            val = next(time_gen)
            if val > 100.5 and val < 110.0:
                # Jump forward to trigger timeout
                # We need a way to know when we are in the second loop
                return 110.0
            return val

        with patch('os.read', side_effect=[packet, b'']):
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([], [], []), ([], [], [])]):
                with patch('ssl_tun_tunnel.tunnel.os.urandom', return_value=b'J'*446) as mock_urandom:
                    # Provide enough values
                    side_effect = [100.0, 100.1, 100.2, 110.0, 110.1, 110.2, 110.3, 110.4, 110.5, 110.6, 110.7]
                    with patch('ssl_tun_tunnel.tunnel.time.time', side_effect=side_effect):
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
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        
        # Mock os.read to return two small packets
        with patch('os.read', side_effect=[b'P1', b'P2']):
            with patch('select.select', side_effect=[
                ([mock_tun_fd], [], []), # read P1
                ([mock_tun_fd], [], []), # read P2
                ([], [], []),             # timeout -> trigger flush
                ([mock_tun_fd], [], []), # EOF or something to break
            ]):
                # Mock time.time to simulate timeout passage
                # 324, 325, 363, 378, 363, 378, 363, 378, 358, 363, 378
                times = [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 110.0, 110.0, 110.0, 110.0, 110.0, 110.0]
                with patch('time.time', side_effect=times):
                    # Mock os.read to return b'' on the last call to break loop
                    with patch('os.read', side_effect=[b'P1', b'P2', b'']):
                        try:
                            handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=True, flush_timeout=1.0)
                        except Exception:
                            pass
        
        # Check if sendall was called. It should bundle P1 and P2.
        expected_batch = struct.pack('!H', 2) + b'P1' + struct.pack('!H', 2) + b'P2'
        mock_ssl_sock.sendall.assert_any_call(expected_batch)

    def test_low_latency_flush(self):
        """Test that low-latency packets trigger immediate flush even when buffered."""
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        
        # IPv4, ICMP (1), ToS 0x48 (LL)
        ll_packet = struct.pack('!BBH HH BB H 4s 4s', 
                                0x45, 0x48, 40,   # Version/IHL, ToS 0x48, Total Length
                                0, 0,             # ID, Flags/Offset
                                64, 1, 0,         # TTL, Protocol (ICMP), Checksum
                                b'\x00'*4, b'\x00'*4)
        
        with patch('os.read', side_effect=[ll_packet, b'']):
            with patch('select.select', side_effect=[([mock_tun_fd], [], []), ([mock_tun_fd], [], []), ([], [], [])]):
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=True, low_latency_dscp={0x48})
                except Exception:
                    pass
        
        # Should have flushed immediately
        expected_batch = struct.pack('!H', len(ll_packet)) + ll_packet
        mock_ssl_sock.sendall.assert_any_call(expected_batch)

    def test_idle_timeout(self):
        """Test that idle timeout closes the connection."""
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        
        # select.select returns nothing (timeout)
        with patch('select.select', return_value=([], [], [])):
            # Provide plenty of timestamps via a long list or generator
            times = [100.0, 100.1, 100.2, 115.0, 115.1, 115.2, 115.3, 115.4, 115.5]
            with patch('ssl_tun_tunnel.tunnel.time.time', side_effect=times):
                result = handle_tunnel(mock_tun_fd, mock_ssl_sock, idle_timeout=10.0)
                self.assertTrue(result) # result=True means was_idle

if __name__ == '__main__':
    unittest.main()
