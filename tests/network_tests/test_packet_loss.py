import os
import time
import socket
import struct
import sys

def create_udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    return sock

def send_packets(sock, host='127.0.0.1', port=12345, num_packets=20):
    print(f"[INFO] Sending {num_packets} UDP packets to {host}:{port}")
    
    successful_sends = 0
    failed_sends = 0
    
    for i in range(num_packets):
        try:
            packet_data = struct.pack('!I', i)
            message = f"Packet {i}: {packet_data.hex()}".encode()
            
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
        
        time.sleep(0.1)
    
    print(f"\n[SUMMARY] Send Results:")
    print(f"  Successful sends: {successful_sends}")
    print(f"  Failed sends: {failed_sends}")
    print(f"  Success rate: {(successful_sends/num_packets)*100:.1f}%")
    
    return successful_sends, failed_sends

def receive_packets(sock, num_packets=20):
    print(f"[INFO] Receiving {num_packets} UDP packets")
    
    successful_receives = 0
    failed_receives = 0
    
    for i in range(num_packets):
        try:
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
    print("=" * 60)
    print("TESTING PACKET LOSS ON SENDTO")
    print("=" * 60)
    
    sock = create_udp_socket()
    
    try:
        print("\n[PHASE 1] Normal sendto operations (should work)")
        send_packets(sock)

        pid = os.getpid()
        
        print("\n[PHASE 2] Sendto with packet loss fault injection")
        print(f"Run: sudo ./khaos packet_loss_sendto {pid} [drop_rate] (default: 30)")
        print("Press Enter when fault is injected...")
        input()
        
        send_packets(sock)
        
        print("\n[PHASE 3] Recovery test")
        print("Run: sudo ./khaos --recover packet_loss_sendto")
        print("Press Enter when fault is recovered...")
        input()
        
        send_packets(sock)
        
    finally:
        sock.close()

def test_packet_loss_recvfrom():
    print("=" * 60)
    print("TESTING PACKET LOSS ON RECVFROM")
    print("=" * 60)
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(('127.0.0.1', 12346))
    server_sock.settimeout(1.0)
    
    client_sock = create_udp_socket()
    
    try:
        print("\n[PHASE 1] Normal recvfrom operations (should work)")
        print("Sending packets to trigger receives...")
        
        for i in range(20):
            client_sock.sendto(f"Test packet {i}".encode(), ('127.0.0.1', 12346))
            time.sleep(0.1)
        
        receive_packets(server_sock, 20)

        pid = os.getpid()
        
        print("\n[PHASE 2] Recvfrom with packet loss fault injection")
        print(f"Run: sudo ./khaos packet_loss_recvfrom {pid} [drop_rate] (default: 30)")
        print("Press Enter when fault is injected...")
        input()
        
        for i in range(20):
            client_sock.sendto(f"Test packet {i}".encode(), ('127.0.0.1', 12346))
            time.sleep(0.1)
        
        receive_packets(server_sock, 20)
        
        print("\n[PHASE 3] Recovery test")
        print("Run: sudo ./khaos --recover packet_loss_recvfrom")
        print("Press Enter when fault is recovered...")
        input()
        
        for i in range(20):
            client_sock.sendto(f"Test packet {i}".encode(), ('127.0.0.1', 12346))
            time.sleep(0.1)
        
        receive_packets(server_sock, 20)
        
    finally:
        server_sock.close()
        client_sock.close()

def main():
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
        test_packet_loss_sendto()
        print("\n" + "=" * 60)
        test_packet_loss_recvfrom()

if __name__ == "__main__":
    main() 