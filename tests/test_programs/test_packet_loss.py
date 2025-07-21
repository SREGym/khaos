"""
Test program for packet loss fault injection.
This program sends UDP packets and demonstrates packet loss simulation.
"""

import os
import time
import socket
import struct
import sys

def create_udp_socket():
    """Create a UDP socket for testing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)  # 1 second timeout
    return sock

def send_packets(sock, host='127.0.0.1', port=12345, num_packets=20):
    """Send multiple UDP packets and track success/failure."""
    print(f"[INFO] Sending {num_packets} UDP packets to {host}:{port}")
    
    successful_sends = 0
    failed_sends = 0
    
    for i in range(num_packets):
        try:
            # Create a simple packet with sequence number
            packet_data = struct.pack('!I', i)  # 4-byte sequence number
            message = f"Packet {i}: {packet_data.hex()}".encode()
            
            # Send the packet
            bytes_sent = sock.sendto(message, (host, port))
            
            if bytes_sent > 0:
                successful_sends += 1
                print(f"[SUCCESS] Sent packet {i} ({bytes_sent} bytes)")
            else:
                failed_sends += 1
                print(f"[FAILED] Packet {i} send returned 0 bytes")
                
        except socket.error as e:
            failed_sends += 1
            print(f"[FAILED] Packet {i} send error: {e}")
        
        # Small delay between packets
        time.sleep(0.1)
    
    print(f"\n[SUMMARY] Send Results:")
    print(f"  Successful sends: {successful_sends}")
    print(f"  Failed sends: {failed_sends}")
    print(f"  Success rate: {(successful_sends/num_packets)*100:.1f}%")
    
    return successful_sends, failed_sends

def receive_packets(sock, num_packets=20):
    """Receive multiple UDP packets and track success/failure."""
    print(f"[INFO] Receiving {num_packets} UDP packets")
    
    successful_receives = 0
    failed_receives = 0
    
    for i in range(num_packets):
        try:
            # Try to receive a packet
            data, addr = sock.recvfrom(1024)
            successful_receives += 1
            print(f"[SUCCESS] Received packet {i} from {addr}: {len(data)} bytes")
            
        except socket.timeout:
            failed_receives += 1
            print(f"[TIMEOUT] Packet {i} receive timeout")
        except socket.error as e:
            failed_receives += 1
            print(f"[FAILED] Packet {i} receive error: {e}")
    
    print(f"\n[SUMMARY] Receive Results:")
    print(f"  Successful receives: {successful_receives}")
    print(f"  Failed receives: {failed_receives}")
    print(f"  Success rate: {(successful_receives/num_packets)*100:.1f}%")
    
    return successful_receives, failed_receives

def test_packet_loss_sendto():
    """Test packet loss on sendto operations."""
    print("=" * 60)
    print("TESTING PACKET LOSS ON SENDTO")
    print("=" * 60)
    
    sock = create_udp_socket()
    
    try:
        # Test normal sendto operations
        print("\n[PHASE 1] Normal sendto operations (should work)")
        send_packets(sock)

        pid = os.getpid()
        
        print("\n[PHASE 2] Sendto with packet loss fault injection")
        print(f"Run: sudo ./khaos packet_loss_sendto {pid}")
        print("Press Enter when fault is injected...")
        input()
        
        # Test sendto operations with fault injection
        send_packets(sock)
        
        print("\n[PHASE 3] Recovery test")
        print("Run: sudo ./khaos --recover packet_loss_sendto")
        print("Press Enter when fault is recovered...")
        input()
        
        # Test sendto operations after recovery
        send_packets(sock)
        
    finally:
        sock.close()

def test_packet_loss_recvfrom():
    """Test packet loss on recvfrom operations."""
    print("=" * 60)
    print("TESTING PACKET LOSS ON RECVFROM")
    print("=" * 60)
    
    # Create a server socket to receive packets
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(('127.0.0.1', 12346))
    server_sock.settimeout(1.0)
    
    # Create a client socket to send packets
    client_sock = create_udp_socket()
    
    try:
        print("\n[PHASE 1] Normal recvfrom operations (should work)")
        print("Sending packets to trigger receives...")
        
        # Send some packets to trigger receives
        for i in range(20):
            client_sock.sendto(f"Test packet {i}".encode(), ('127.0.0.1', 12346))
            time.sleep(0.1)
        
        # Try to receive packets
        receive_packets(server_sock, 20)

        pid = os.getpid()
        
        print("\n[PHASE 2] Recvfrom with packet loss fault injection")
        print(f"Run: sudo ./khaos packet_loss_recvfrom {pid}")
        print("Press Enter when fault is injected...")
        input()
        
        # Send more packets to trigger receives with fault
        for i in range(20):
            client_sock.sendto(f"Test packet {i}".encode(), ('127.0.0.1', 12346))
            time.sleep(0.1)
        
        # Try to receive packets with fault injection
        receive_packets(server_sock, 20)
        
        print("\n[PHASE 3] Recovery test")
        print("Run: sudo ./khaos --recover packet_loss_recvfrom")
        print("Press Enter when fault is recovered...")
        input()
        
        # Send more packets to trigger receives after recovery
        for i in range(20):
            client_sock.sendto(f"Test packet {i}".encode(), ('127.0.0.1', 12346))
            time.sleep(0.1)
        
        # Try to receive packets after recovery
        receive_packets(server_sock, 20)
        
    finally:
        server_sock.close()
        client_sock.close()

def main():
    """Main test function."""
    print("Packet Loss Fault Injection Test")
    print("=" * 40)
    
    if len(sys.argv) > 1:
        test_type = sys.argv[1]
        if test_type == "sendto":
            test_packet_loss_sendto()
        elif test_type == "recvfrom":
            test_packet_loss_recvfrom()
        else:
            print(f"Unknown test type: {test_type}")
            print("Usage: python3 test_packet_loss.py [sendto|recvfrom]")
    else:
        # Run both tests
        test_packet_loss_sendto()
        print("\n" + "=" * 60)
        test_packet_loss_recvfrom()

if __name__ == "__main__":
    main() 