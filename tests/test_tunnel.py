import unittest
from unittest.mock import MagicMock, patch
import struct
import io
import os

# Import functions to test
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

if __name__ == '__main__':
    unittest.main()
