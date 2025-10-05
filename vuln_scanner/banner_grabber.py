#!/usr/bin/env python3
import socket
import os

class BannerGrabber:
    def __init__(self, target_ip, port):
        self.target_ip = target_ip
        self.port = port

    def grab_banner(self):
        """Récupère la bannière du service"""
        try:
            # Créer une connexion socket
            sock = socket.socket()
            sock.settimeout(3)  # Timeout de 3 secondes
            sock.connect((self.target_ip, self.port))
            
            banner = ""
            
            # Envoyer une requête HTTP pour les serveurs web
            if self.port in [80, 443, 8080, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Pour SSH, FTP, SMTP - juste recevoir la bannière
            elif self.port in [21, 22, 25, 53]:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.close()
            
            return self.analyze_banner(banner) if banner else None

        except Exception as e:
            print(f"[-] Erreur sur {self.target_ip}:{self.port} - {e}")
            return None

    def analyze_banner(self, banner):
        """Analyse la bannière pour détecter des vulnérabilités"""
        vulnerabilities = []
        
        # Vérifier les versions obsolètes d'Apache
        if 'Apache/2.2' in banner or 'Apache/2.4.1' in banner:
            vulnerabilities.append({
                'type': 'Logiciel Obsolète',
                'severity': 'HAUTE',
                'description': 'Version Apache ancienne et potentiellement vulnérable'
            })
        
        # Vérifier les versions obsolètes de nginx
        if 'nginx/1.0' in banner or 'nginx/1.2' in banner:
            vulnerabilities.append({
                'type': 'Logiciel Obsolète', 
                'severity': 'HAUTE',
                'description': 'Version nginx ancienne'
            })
        
        # Détection d'exposition d'informations
        if 'Server:' in banner or 'X-Powered-By:' in banner:
            vulnerabilities.append({
                'type': 'Exposition d\'Informations',
                'severity': 'FAIBLE', 
                'description': 'Le serveur expose des informations de version'
            })
        
        # Détection de services avec versions spécifiques
        if 'OpenSSH_5.' in banner or 'OpenSSH_6.' in banner:
            vulnerabilities.append({
                'type': 'SSH Ancien',
                'severity': 'MOYENNE',
                'description': 'Version OpenSSH ancienne'
            })

        return {
            'banner': banner[:500],  # Limiter la taille
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities)
        }

# Test du banner grabber
if __name__ == "__main__":
    # Tester sur les ports ouverts trouvés
    ports_to_test = [22, 53, 80, 8080]
    
    for port in ports_to_test:
        print(f"\n[*] Test du port {port}...")
        grabber = BannerGrabber('127.0.0.1', port)
        result = grabber.grab_banner()
        
        if result:
            print(f"[+] Bannière récupérée sur le port {port}")
            print(f"    Extrait: {result['banner'][:100]}...")
            print(f"    Vulnérabilités détectées: {result['vulnerability_count']}")
            for vuln in result['vulnerabilities']:
                print(f"      - {vuln['type']} ({vuln['severity']}): {vuln['description']}")
        else:
            print(f"[-] Aucune bannière récupérée sur le port {port}")
