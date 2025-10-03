#!/usr/bin/env python3
import struct
import socket
import json
import datetime
from collections import defaultdict
import time

class NetworkMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.suspicious_ips = []
        self.packet_count = 0
        self.connection_attempts = defaultdict(list)
        
    def get_mac_addr(self, bytes_addr):
        """Convert bytes MAC address to readable format"""
        bytes_str = map("{:02x}".format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def get_ipv4(self, addr):
        """Convert bytes IP to string"""
        return '.'.join(map(str, addr))

    def parse_frame(self, frame):
        """Parse Ethernet frame"""
        eth_len = 14
        eth_header = frame[:eth_len]
        eth_data = frame[eth_len:]
        dest_mac, src_mac, proto_field1, proto_field2 = struct.unpack('!6s6scc', eth_header)
        
        dest_mac = self.get_mac_addr(dest_mac)
        src_mac = self.get_mac_addr(src_mac)

        proto1 = ''.join(map(str, proto_field1))
        proto2 = ''.join(map(str, proto_field2))
        proto = proto1 + proto2
        
        if proto == '80':
            ip_proto = 'IPv4'
        elif proto == '86':
            ip_proto = 'ARP'
        elif proto == '86DD':
            ip_proto = 'IPv6'
        else:
            ip_proto = proto
            
        return eth_data, ip_proto, src_mac, dest_mac

    def parse_packet(self, packet):
        """Parse IP packet"""
        first_byte = packet[0]
        ip_version = first_byte >> 4
        ip_header_length = (first_byte & 15) * 4

        ttl, proto, src, dest = struct.unpack('!8xBB2x4s4s', packet[:20])
        src_ip = self.get_ipv4(src)
        dest_ip = self.get_ipv4(dest)

        if proto == 1:
            transport_proto = 'ICMP'
        elif proto == 6:
            transport_proto = 'TCP'
        elif proto == 17:
            transport_proto = 'UDP'
        else:
            transport_proto = f'Unknown({proto})'

        return packet[ip_header_length:], transport_proto, src_ip, dest_ip, ttl

    def parse_TCP(self, data):
        """Parse TCP segment"""
        src_port, dest_port, seq, ack, offset_flags = struct.unpack('!HHLLH', data[:14])
        tcp_header_length = (offset_flags >> 12) * 4

        # Extract flags
        flag_urg = (offset_flags & 32) >> 5
        flag_ack = (offset_flags & 16) >> 4
        flag_psh = (offset_flags & 8) >> 3
        flag_rst = (offset_flags & 4) >> 2
        flag_syn = (offset_flags & 2) >> 1
        flag_fin = offset_flags & 1

        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'flags': {
                'syn': flag_syn,
                'ack': flag_ack,
                'fin': flag_fin,
                'rst': flag_rst
            },
            'header_length': tcp_header_length
        }

    def is_suspicious(self, src_ip, dest_port, transport_proto, tcp_data=None):
        """Detect suspicious patterns"""
        alerts = []
        
        # Port scanning detection
        if transport_proto == 'TCP' and tcp_data and tcp_data['flags']['syn']:
            current_time = time.time()
            
            # Clean old entries
            self.connection_attempts[src_ip] = [
                t for t in self.connection_attempts[src_ip]
                if current_time - t < 60  # 60 second window
            ]
            
            # Add new attempt
            self.connection_attempts[src_ip].append(current_time)
            
            # Check if threshold exceeded (10 attempts in 60 seconds)
            if len(self.connection_attempts[src_ip]) > 10:
                alerts.append(f"Port scan detected from {src_ip}")
        
        # Suspicious port detection
        suspicious_ports = [22, 23, 3389, 1433, 3306]  # SSH, Telnet, RDP, SQL
        if dest_port in suspicious_ports and transport_proto == 'TCP':
            alerts.append(f"Suspicious connection to port {dest_port} from {src_ip}")
            
        return alerts

    def log_alert(self, alert_data):
        """Log suspicious activity to JSON file"""
        log_entry = {
            'timestamp': str(datetime.datetime.now()),
            'alert': alert_data,
            'packet_num': self.packet_count
        }
        
        try:
            with open('../logs/alerts.json', 'a', encoding='utf-8') as f:
                json.dump(log_entry, f, ensure_ascii=False)
                f.write('\n')
            print(f"ALERT: {alert_data}")
        except Exception as e:
            print(f"Error writing alert: {e}")

    def start_monitoring(self):
        """Start packet capture"""
        print(f"Starting network monitoring...")
        
        try:
            # Create raw socket
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            while True:
                # Receive Ethernet frame
                payload, addr = conn.recvfrom(65535)
                self.packet_count += 1
                
                try:
                    # Parse frames
                    ip_packet, ip_protocol, src_mac, dest_mac = self.parse_frame(payload)
                    
                    if ip_protocol == 'IPv4':
                        # Parse IP packet
                        transport_packet, transport_proto, src_ip, dest_ip, ttl = self.parse_packet(ip_packet)
                        
                        # Parse TCP if applicable
                        tcp_data = None
                        dest_port = None
                        
                        if transport_proto == 'TCP':
                            tcp_data = self.parse_TCP(transport_packet)
                            dest_port = tcp_data['dest_port']
                            
                            # Check for suspicious activity
                            alerts = self.is_suspicious(src_ip, dest_port, transport_proto, tcp_data)
                            for alert in alerts:
                                self.log_alert(alert)
                                
                        # Log every 100 packets for debugging
                        if self.packet_count % 100 == 0:
                            print(f"📦 Packets processed: {self.packet_count}")
                            
                except Exception as e:
                    # Continue monitoring even if one packet fails
                    continue
                    
        except PermissionError:
            print("ERROR: Permission denied. Run with sudo!")
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        except Exception as e:
            print(f"ERROR: {e}")

def main():
    """Main function"""
    print("HomeSOC Network Monitor")
    print("=" * 30)
    
    monitor = NetworkMonitor()
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
