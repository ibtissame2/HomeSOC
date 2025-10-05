#!/usr/bin/env python3
import socket
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.open_ports = []
        # Ports communs à scanner
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443,
            445, 993, 995, 3306, 3389, 5432, 8080, 8443
        ]
        
        # Définir le chemin absolu pour les logs
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.logs_dir = os.path.join(self.project_root, 'logs')

    def scan_port(self, port):
        """Scan un port unique"""
        try:
            # Créer un socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Timeout de 1 seconde
            
            # Tenter la connexion
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:  # Port ouvert
                service = self.identify_service(port)
                port_info = {
                    'port': port,
                    'service': service,
                    'status': 'OPEN'
                }
                self.open_ports.append(port_info)
                print(f"[+] Port {port} est OUVERT - {service}")
            
            sock.close()
            
        except Exception as e:
            pass  # Ignorer les erreurs pour continuer le scan

    def identify_service(self, port):
        """Identifie le service basé sur le port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')

    def scan_all_ports(self):
        """Scan tous les ports communs en utilisant le threading"""
        print(f"[*] Démarrage du scan sur {self.target_ip}...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Lancer le scan de tous les ports en parallèle
            executor.map(self.scan_port, self.common_ports)
        
        print(f"[*] Scan terminé. {len(self.open_ports)} ports ouverts trouvés.")
        return self.open_ports

    def generate_report(self):
        """Génère un rapport du scan"""
        # S'assurer que le dossier logs existe
        os.makedirs(self.logs_dir, exist_ok=True)
        
        report = {
            'target': self.target_ip,
            'scan_time': str(datetime.now()),
            'open_ports': self.open_ports,
            'total_open': len(self.open_ports)
        }
        
        # Sauvegarder le rapport JSON
        report_path = os.path.join(self.logs_dir, 'scan_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"[+] Rapport sauvegardé dans '{report_path}'")
        return report

# Test du scanner
if __name__ == "__main__":
    # Scanner localhost pour tester
    scanner = PortScanner('127.0.0.1')
    results = scanner.scan_all_ports()
    scanner.generate_report()
