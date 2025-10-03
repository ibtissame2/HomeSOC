#!/usr/bin/env python3
from scapy.all import *
import json
import datetime
from collections import defaultdict
import time
import sys

class EnhancedNetworkMonitor:
    def __init__(self):
        self.suspicious_ips = []
        self.packet_count = 0
        self.connection_attempts = defaultdict(list)
        self.dns_queries = defaultdict(list)
        self.start_time = time.time()
    
    def find_working_interface(self):
        """Trouve une interface qui fonctionne"""
        interfaces = get_if_list()
        
        print("Interfaces disponibles:")
        for iface in interfaces:
            print(f"  - {iface}")
        
        # Préférer enp0s8 car c'est l'interface par défaut (voir ip route)
        preferred = ['enp0s8', 'enp0s3']  # enp0s8 est l'interface par défaut
        
        for iface in preferred:
            if iface in interfaces:
                print(f"Trying preferred interface: {iface}")
                try:
                    sniff(iface=iface, count=1, timeout=2)
                    print(f"Interface {iface} is working")
                    return iface
                except Exception as e:
                    print(f"Interface {iface} failed: {e}")
                    continue
        
        # Essayer toutes les interfaces
        for iface in interfaces:
            if iface != 'lo':
                print(f"Trying interface: {iface}")
                try:
                    sniff(iface=iface, count=1, timeout=2)
                    print(f"Interface {iface} is working")
                    return iface
                except:
                    continue
        
        return None
    
    def packet_callback(self, packet):
        """Callback function for Scapy sniffing"""
        self.packet_count += 1
        
        # Afficher un résumé du paquet
        if self.packet_count % 50 == 0:
            elapsed = time.time() - self.start_time
            print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Packets: {self.packet_count} | Rate: {self.packet_count/elapsed:.1f} pkt/s")
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            # Afficher les paquets intéressants
            if packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(DNS):
                self.print_packet_summary(packet)
            
            # Détection de scans de ports TCP
            if packet.haslayer(TCP):
                self.detect_port_scan(src_ip, packet[TCP])
            
            # Détection de tunnels DNS
            if packet.haslayer(DNSQR):
                self.detect_dns_tunnel(src_ip, packet[DNSQR])
            
            # Détection ICMP suspect (ping floods)
            if packet.haslayer(ICMP):
                self.detect_icmp_flood(src_ip)
    
    def print_packet_summary(self, packet):
        """Affiche un résumé du paquet"""
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if packet.haslayer(TCP):
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    print(f"TCP  {src_ip}:{sport} -> {dst_ip}:{dport} [{flags}]")
                
                elif packet.haslayer(UDP):
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    print(f"UDP  {src_ip}:{sport} -> {dst_ip}:{dport}")
                
                elif packet.haslayer(DNSQR):
                    query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    print(f"DNS  {src_ip} -> {dst_ip} : {query[:50]}")
                
                elif packet.haslayer(ICMP):
                    print(f"ICMP {src_ip} -> {dst_ip}")
                    
        except Exception as e:
            # Ignorer les erreurs d'affichage
            pass
    
    def detect_port_scan(self, src_ip, tcp_layer):
        """Détection de scans de ports"""
        if hasattr(tcp_layer, 'flags') and tcp_layer.flags == 'S':  # SYN seulement
            current_time = time.time()
            dst_port = tcp_layer.dport
            
            # Nettoyage des anciennes entrées
            self.connection_attempts[src_ip] = [
                (t, port) for t, port in self.connection_attempts[src_ip] 
                if current_time - t < 60
            ]
            
            # Ajout de la nouvelle tentative
            self.connection_attempts[src_ip].append((current_time, dst_port))
            
            # Vérifier le nombre de ports différents
            unique_ports = len(set(port for _, port in self.connection_attempts[src_ip]))
            
            if unique_ports > 10:
                alert = f"PORT_SCAN from {src_ip} - {unique_ports} different ports in 60s"
                self.log_alert(alert)
    
    def detect_dns_tunnel(self, src_ip, dns_layer):
        """Détection de tunnels DNS"""
        if hasattr(dns_layer, 'qname'):
            try:
                domain = dns_layer.qname.decode('utf-8', errors='ignore')
                
                # Détection basée sur la longueur du domaine
                if len(domain) > 100:
                    alert = f"DNS_TUNNEL_SUSPECT from {src_ip} - Domain length: {len(domain)}"
                    self.log_alert(alert)
                
                # Détection de domaines étranges
                if any(suspicious in domain.lower() for suspicious in 
                       ['.ddns.net', '.duckdns.org', '.no-ip.org', '.myftp.org']):
                    alert = f"DYNAMIC_DNS_QUERY from {src_ip} - {domain[:50]}"
                    self.log_alert(alert)
                
                # Surveillance de la fréquence
                current_time = time.time()
                self.dns_queries[src_ip].append(current_time)
                
                # Nettoyage des anciennes requêtes
                self.dns_queries[src_ip] = [
                    t for t in self.dns_queries[src_ip] 
                    if current_time - t < 10
                ]
                
                # Trop de requêtes DNS
                if len(self.dns_queries[src_ip]) > 30:
                    alert = f"DNS_FLOOD from {src_ip} - {len(self.dns_queries[src_ip])} queries in 10s"
                    self.log_alert(alert)
                    
            except Exception as e:
                pass
    
    def detect_icmp_flood(self, src_ip):
        """Détection de flood ICMP"""
        current_time = time.time()
        
        # Similaire aux autres détections, mais pour ICMP
        # Implémentation simplifiée
        pass
    
    def log_alert(self, alert_data):
        """Log les alertes en JSON"""
        log_entry = {
            'timestamp': str(datetime.datetime.now()),
            'alert': alert_data,
            'packet_num': self.packet_count
        }
        
        try:
            # Créer le dossier logs s'il n'existe pas
            import os
            os.makedirs('/home/ubuntu/HomeSOC/logs', exist_ok=True)
            
            with open('/home/ubuntu/HomeSOC/logs/alerts.json', 'a') as f:
                json.dump(log_entry, f)
                f.write('\n')
            print(f"ALERT: {alert_data}")
        except Exception as e:
            print(f"Error writing alert: {e}")
    
    def start_monitoring(self):
        """Démarre la surveillance"""
        print("Finding network interface...")
        
        interface = self.find_working_interface()
        
        if interface is None:
            print("ERROR: No working interface found!")
            sys.exit(1)
        
        print(f"Starting monitoring on interface: {interface}")
        print(" Monitoring started. Press Ctrl+C to stop.")
        print("=" * 60)
        
        try:
            # Commencer la capture
            sniff(iface=interface, prn=self.packet_callback, store=False)
            
        except KeyboardInterrupt:
            print(f"Monitoring stopped. Total packets processed: {self.packet_count}")
        except Exception as e:
            print(f"Monitoring error: {e}")

def main():
    """Fonction principale"""
    print(" Enhanced Network Monitor with Scapy")
    print("=" * 50)
    
    # Vérifier les privilèges
    import os
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges!")
        print("Please run with: sudo python3 packet_sniffer.py")
        sys.exit(1)
    
    # Vérifier que Scapy est installé
    try:
        import scapy
    except ImportError:
        print("ERROR: Scapy is not installed!")
        print("Install with: sudo pip3 install scapy")
        sys.exit(1)
    
    monitor = EnhancedNetworkMonitor()
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
