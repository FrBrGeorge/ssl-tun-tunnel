import unittest
from unittest.mock import MagicMock, patch
import struct
import os
import sys
import ssl

# Ensure local src is in path
LIB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../src'))
if LIB_PATH not in sys.path:
    sys.path.insert(0, LIB_PATH)

from ssl_tun_tunnel.tunnel import handle_tunnel

class TestFramingRobustness(unittest.TestCase):
    def test_segmented_ssl_frame(self):
        """Test that frames split across multiple SSL recv() calls are correctly assembled."""
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.pending.return_value = 0
        
        packet1 = b'PACKET1'
        header1 = struct.pack('!H', len(packet1))
        
        packet2 = b'PACKET2'
        header2 = struct.pack('!H', len(packet2))
        
        # Scenario:
        # 1. First chunk: header1 + part of packet1
        # 2. Second chunk: rest of packet1 + header2 + packet2
        chunk1 = header1 + packet1[:3]
        chunk2 = packet1[3:] + header2 + packet2
        
        # We need to make select return ssl_sock. Or even better, just rely on the loop.
        # handle_tunnel loop:
        # while True:
        #   r, w, x = select.select(...)
        #   if ssl_sock in r:
        #     while True:
        #        chunk = ssl_sock.recv(8192) -> return chunk1
        #        ... next iteration -> return chunk2
        #        ... next iteration -> raise SSLWantReadError or return empty (EOF)
        
        # We will use side_effect to simulate chunks
        mock_ssl_sock.recv.side_effect = [
            chunk1, 
            ssl.SSLWantReadError(), # Break inner while loop
            chunk2,
            ssl.SSLWantReadError(), # Break inner while loop
            b'' # EOF to break outer loop eventually
        ]
        
        # Mock select to trigger twice for ssl_sock
        with patch('select.select', side_effect=[
            ([mock_ssl_sock], [], []), # Trigger 1
            ([mock_ssl_sock], [], []), # Trigger 2
            ([], [], [])               # Break / Idle
        ]):
            with patch('os.write') as mock_write:
                # We need a way to break handle_tunnel. 
                # It breaks if chunk is null (EOF) OR if idle timeout happens.
                # In handle_tunnel, if not chunk: return False.
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=False, idle_timeout=1.0)
                except Exception as e:
                    pass
                
                # Verify that both packets were written to TUN
                mock_write.assert_any_call(mock_tun_fd, b'PACKET1')
                mock_write.assert_any_call(mock_tun_fd, b'PACKET2')
                self.assertEqual(mock_write.call_count, 2)

    def test_split_header(self):
        """Test that a frame-header split across recv() calls is handled correctly."""
        mock_tun_fd = 10
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.pending.return_value = 0
        
        packet = b'DATA'
        header = struct.pack('!H', len(packet)) # 2 bytes
        
        # Split header: 1st byte in chunk A, 2nd byte + data in chunk B
        chunk1 = header[:1]
        chunk2 = header[1:] + packet
        
        mock_ssl_sock.recv.side_effect = [
            chunk1, 
            ssl.SSLWantReadError(),
            chunk2,
            ssl.SSLWantReadError(),
            b''
        ]
        
        with patch('select.select', side_effect=[
            ([mock_ssl_sock], [], []),
            ([mock_ssl_sock], [], []),
            ([], [], [])
        ]):
            with patch('os.write') as mock_write:
                try:
                    handle_tunnel(mock_tun_fd, mock_ssl_sock, buffered=False)
                except Exception:
                    pass
                
                mock_write.assert_called_once_with(mock_tun_fd, b'DATA')

if __name__ == '__main__':
    unittest.main()
