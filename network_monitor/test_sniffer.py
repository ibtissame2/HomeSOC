#!/usr/bin/env python3
from scapy.all import *
import json
import datetime

def packet_callback(packet):
    if IP in packet:
        print(f"Packet: {packet[IP].src} -> {packet[IP].dst} Proto: {packet[IP].proto}")
        
        # Détection basique SYN
        if TCP in packet and packet[TCP].flags == 'S':
            alert = {
                'timestamp': str(datetime.datetime.now()),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'alert': 'SYN_SCAN_DETECTED'
            }
            print(f"ALERTE SYN: {alert}")
            with open('logs/alerts.json', 'a') as f:
                f.write(json.dumps(alert) + '\n')

print("Démarrage du sniffer de test...")
sniff(iface="enp0s3", prn=packet_callback, count=50)
