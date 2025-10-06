#!/usr/bin/env python3
import threading
import time
import sys
import os

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from network_monitor.packet_sniffer import EnhancedNetworkMonitor as NetworkMonitor
    from vuln_scanner.port_scanner import PortScanner
    from elasticsearch import Elasticsearch
    print("[SUCCESS] All imports successful")
except ImportError as e:
    print(f"[ERROR] Import error: {e}")
    sys.exit(1)

class HomeSOC:
    def __init__(self):
        try:
            self.es = Elasticsearch(['http://localhost:9200'])
            self.network_monitor = NetworkMonitor()
            self.is_running = False
            print("[SUCCESS] HomeSOC initialized successfully")
        except Exception as e:
            print(f"[ERROR] Initialization error: {e}")
            raise

    def start_monitoring(self):
        """Start network monitoring in background"""
        print("Starting network monitoring...")
        monitor_thread = threading.Thread(
            target=self.network_monitor.start_monitoring
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        print("[SUCCESS] Network monitoring started in background")

    def run_vulnerability_scan(self, target):
        """Run vulnerability scan"""
        print(f"Starting vulnerability scan for {target}")
        scanner = PortScanner(target)
        results = scanner.scan_all_ports()
        self.send_to_elasticsearch(results)

    def send_to_elasticsearch(self, data):
        """Send data to Elasticsearch"""
        try:
            self.es.index(index='homesoc-scans', body=data)
            print("[SUCCESS] Data sent to Elasticsearch")
        except Exception as e:
            print(f"[ERROR] Error sending to Elasticsearch: {e}")

    def start(self):
        """Start the entire HomeSOC system"""
        print("Starting HomeSOC System...")
        self.is_running = True
        self.start_monitoring()
        print("HomeSOC is running. Press Ctrl+C to stop.")

        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down HomeSOC...")
            self.is_running = False

if __name__ == "__main__":
    try:
        soc = HomeSOC()
        soc.start()
    except Exception as e:
        print(f"Failed to start HomeSOC: {e}")
