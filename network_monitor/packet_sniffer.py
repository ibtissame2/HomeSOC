#!/usr/bin/env python3  
"""
HomeSOC - Enhanced Network Monitor
GitHub: https://github.com/ibtissame2/HomeSOC
A sophisticated network intrusion detection system using Scapy.
"""

from scapy.all import *
import json
import datetime
from collections import defaultdict
import time
import sys
import os
import netifaces

class EnhancedNetworkMonitor:
    def __init__(self):
        self.suspicious_ips = []
        self.packet_count = 0
        self.connection_attempts = defaultdict(list)
        self.dns_queries = defaultdict(list)
        self.icmp_requests = defaultdict(list)
        self.start_time = time.time()
        self.alert_count = 0
        self.last_stats_time = time.time()
    
    def find_working_interface(self):
        """Trouve et force l'interface avec le réseau 192.168.2.x"""
        interfaces = get_if_list()
        
        print("Interfaces disponibles:")
        for iface in interfaces:
            print(f"  - {iface}")
        
        # FORCER l'interface enp0s3 qui a l'IP 192.168.2.14
        target_interface = 'enp0s3'
        
        if target_interface in interfaces:
            print(f"FORCED interface: {target_interface} (192.168.2.14)")
            return target_interface
        
        return None
    
    def packet_callback(self, packet):
        """Callback function for Scapy sniffing"""
        self.packet_count += 1
        
        # Afficher les statistiques toutes les 20 paquets
        current_time = time.time()
        if current_time - self.last_stats_time >= 5:  # Toutes les 5 secondes
            elapsed = current_time - self.start_time
            rate = self.packet_count / elapsed if elapsed > 0 else 0
            print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Packets: {self.packet_count} | Rate: {rate:.1f} pkt/s | Alerts: {self.alert_count}")
            self.last_stats_time = current_time
        
        # ANALYSER TOUS LES PAQUETS SANS FILTRE
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # AFFICHER TOUTES LES PAQUETS TCP SYN (comme nmap)
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                flags = tcp.flags
                
                # AFFICHER TOUTES LES CONNEXIONS TCP
                prefix = "LOCAL" if src_ip.startswith('192.168.2.') or dst_ip.startswith('192.168.2.') else "EXTERN"
                print(f"{prefix} TCP  {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport} [{flags}]")
                
                # DITECTION DE SCANS DE PORTS
                if flags == 'S':  # SYN packet (nmap scan)
                    self.detect_port_scan(src_ip, tcp)
            
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                prefix = "LOCAL" if src_ip.startswith('192.168.2.') or dst_ip.startswith('192.168.2.') else "EXTERN"
                print(f"{prefix} UDP  {src_ip}:{udp.sport} -> {dst_ip}:{udp.dport}")
            
            elif packet.haslayer(ICMP):
                prefix = "LOCAL" if src_ip.startswith('192.168.2.') or dst_ip.startswith('192.168.2.') else "EXTERN"
                print(f"{prefix} ICMP {src_ip} -> {dst_ip}")
                self.detect_icmp_flood(src_ip)
            
            elif packet.haslayer(DNSQR):
                try:
                    query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    prefix = "LOCAL" if src_ip.startswith('192.168.2.') or dst_ip.startswith('192.168.2.') else "EXTERN"
                    print(f"{prefix} DNS  {src_ip} -> {dst_ip} : {query[:50]}")
                    self.detect_dns_tunnel(src_ip, packet[DNSQR])
                except:
                    pass
    
    def detect_port_scan(self, src_ip, tcp_layer):
        """Detection de scans de ports avec ameliorations"""
        current_time = time.time()
        dst_port = tcp_layer.dport
    
        # Nettoyage des anciennes entrees (fenetre de 30 secondes)
        self.connection_attempts[src_ip] = [
            (t, port) for t, port in self.connection_attempts[src_ip] 
            if current_time - t < 30  # Changement de 60 a 30 secondes
        ]
    
        # Ajout de la nouvelle tentative
        self.connection_attempts[src_ip].append((current_time, dst_port))
    
        # Verifier le nombre de ports differents
        unique_ports = len(set(port for _, port in self.connection_attempts[src_ip]))
    
        # Rendre la detection plus sensible
        if unique_ports >= 3:  # Changement de 5 a 3 ports
            alert = f"ALERT: PORT_SCAN from {src_ip} - {unique_ports} different ports in 30s"
            self.log_alert(alert)
        
            # Afficher les ports scannes pour confirmation
            ports_scanned = list(set(port for _, port in self.connection_attempts[src_ip]))
            print(f"SCANNED PORTS: {ports_scanned}")
        
            # Optionnel: Vider les tentatives apres detection
            self.connection_attempts[src_ip] = []
   
    def detect_dns_tunnel(self, src_ip, dns_layer):
        """Détection de tunnels DNS"""
        if hasattr(dns_layer, 'qname'):
            try:
                domain = dns_layer.qname.decode('utf-8', errors='ignore')
                
                # Détection basée sur la longueur du domaine
                if len(domain) > 100:
                    alert = f"DNS_TUNNEL_SUSPECT from {src_ip} - Domain length: {len(domain)}"
                    self.log_alert(alert)
                
            except Exception:
                pass
    
    def detect_icmp_flood(self, src_ip):
        """Détection de flood ICMP (Ping floods)"""
        current_time = time.time()
        
        # Ajouter la requête ICMP actuelle
        self.icmp_requests[src_ip].append(current_time)
        
        # Nettoyage des anciennes requêtes (fenêtre de 5 secondes)
        self.icmp_requests[src_ip] = [
            t for t in self.icmp_requests[src_ip]
            if current_time - t < 5
        ]
        
        # Détection de flood ICMP : 20 requêtes en 5 secondes
        if len(self.icmp_requests[src_ip]) > 20:
            alert = f"ICMP_FLOOD from {src_ip} - {len(self.icmp_requests[src_ip])} requests in 5s"
            self.log_alert(alert)
    
    def log_alert(self, alert_data):
        """Log les alertes en JSON avec compteur"""
        self.alert_count += 1
        
        log_entry = {
            'timestamp': str(datetime.datetime.now()),
            'alert': alert_data,
            'packet_num': self.packet_count,
            'alert_id': self.alert_count
        }
        
        try:
            # Créer le dossier logs s'il n'existe pas
            log_dir = '/home/ubuntu/HomeSOC/logs'
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, 'alerts.json')
            
            with open(log_file, 'a') as f:
                json.dump(log_entry, f)
                f.write('\n')
            
            # Afficher l'alerte avec un formatage spécial
            print(f"*** ALERT #{self.alert_count}: {alert_data} ***")
            
        except Exception as e:
            print(f"Error writing alert: {e}")
    
    def start_monitoring(self):
        """Démarre la surveillance réseau"""
        print("Finding network interface...")
        
        interface = self.find_working_interface()
        
        if interface is None:
            print("ERROR: No working interface found!")
            sys.exit(1)
        
        print(f">>> Starting monitoring on interface: {interface}")
        print(">>> Waiting for nmap scans from 192.168.2.10...")
        print("Monitoring started. Press Ctrl+C to stop.")
        print("=" * 60)
        
        try:
            # Commencer la capture avec gestion d'erreurs
            sniff(iface=interface, prn=self.packet_callback, store=False)
            
        except KeyboardInterrupt:
            print(f"\nMonitoring stopped by user.")
            print(f"Total packets processed: {self.packet_count}")
            print(f"Total alerts generated: {self.alert_count}")
        except PermissionError:
            print("Permission denied! Run with sudo.")
            sys.exit(1)
        except Exception as e:
            print(f"Monitoring error: {e}")
            sys.exit(1)

def display_banner():
    """Affiche la bannière du projet"""
    banner = """
    ==============================================
            HomeSOC Network Monitor           
           GitHub: HomeSOC-Project            
      Advanced Intrusion Detection System     
    ==============================================
    """
    print(banner)

def main():
    """Fonction principale"""
    display_banner()
    
    # Vérifier les privilèges root
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
    
    # Démarrer le monitoring
    monitor = EnhancedNetworkMonitor()
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
