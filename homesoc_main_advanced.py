#!/usr/bin/env python3
import threading
import time
import schedule
import sys
import os
from datetime import datetime

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

class HomeSOCAdvanced:
    def __init__(self):
        try:
            self.es = Elasticsearch(['http://localhost:9200'])
            self.network_monitor = NetworkMonitor()
            self.is_running = False
            self.scan_targets = ['192.168.2.1', '192.168.2.10', '192.168.2.14', '192.168.2.100']
            print("[SUCCESS] HomeSOC Advanced initialized successfully")
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
        """Run vulnerability scan on specific target"""
        print(f"Starting vulnerability scan for {target}")
        try:
            scanner = PortScanner(target)
            results = scanner.scan_all_ports()
            self.send_to_elasticsearch(results, 'vulnerability-scan')
            print(f"[SUCCESS] Vulnerability scan completed for {target}")
            return results
        except Exception as e:
            print(f"[ERROR] Scan failed for {target}: {e}")
            return None

    def run_comprehensive_scan(self):
        """Run comprehensive scan on all targets"""
        print("Starting comprehensive vulnerability scan...")
        scan_results = []
        
        for target in self.scan_targets:
            result = self.run_vulnerability_scan(target)
            if result:
                scan_results.append(result)
            time.sleep(2)  # Pause entre les scans
        
        print(f"[SUCCESS] Comprehensive scan completed: {len(scan_results)} targets scanned")
        return scan_results

    def send_to_elasticsearch(self, data, scan_type='network-alert'):
        """Send data to Elasticsearch with proper indexing"""
        try:
            if scan_type == 'vulnerability-scan':
                index_name = 'homesoc-vuln-scans'
            else:
                index_name = 'homesoc-alerts'
            
            # Add metadata
            data['scan_type'] = scan_type
            data['timestamp'] = datetime.now().isoformat()
            data['system'] = 'HomeSOC'
            
            self.es.index(index=index_name, body=data)
            print(f"[SUCCESS] Data sent to Elasticsearch index: {index_name}")
        except Exception as e:
            print(f"[ERROR] Error sending to Elasticsearch: {e}")

    def setup_scheduled_scans(self):
        """Setup automated scheduled scans"""
        # Scan complet tous les jours à 2h du matin
        schedule.every().day.at("02:00").do(self.run_comprehensive_scan)
        
        # Scan rapide toutes les 6 heures
        schedule.every(6).hours.do(lambda: self.run_vulnerability_scan('192.168.2.1'))
        
        print("[SUCCESS] Scheduled scans configured")

    def start_scheduler(self):
        """Start the schedule runner in background"""
        def run_scheduler():
            while self.is_running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        scheduler_thread = threading.Thread(target=run_scheduler)
        scheduler_thread.daemon = True
        scheduler_thread.start()
        print("[SUCCESS] Scheduler started in background")

    def start(self):
        """Start the entire HomeSOC Advanced system"""
        print("=== HomeSOC Advanced System Starting ===")
        self.is_running = True
        
        # Start all components
        self.start_monitoring()
        self.setup_scheduled_scans()
        self.start_scheduler()
        
        # Run initial scan
        print("Running initial vulnerability scan...")
        self.run_comprehensive_scan()
        
        print("=== HomeSOC Advanced is fully operational ===")
        print("Press Ctrl+C to stop the system.")
        print("Available commands:")
        print("  - Network monitoring: ACTIVE")
        print("  - Vulnerability scanning: ACTIVE") 
        print("  - Scheduled scans: ACTIVE")
        print("  - Kibana dashboard: http://localhost:5601")

        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n=== HomeSOC Advanced System Shutting Down ===")
            self.is_running = False

if __name__ == "__main__":
    try:
        # Install schedule package if not available
        try:
            import schedule
        except ImportError:
            print("Installing schedule package...")
            os.system("pip3 install schedule")
            import schedule
        
        soc = HomeSOCAdvanced()
        soc.start()
    except Exception as e:
        print(f"Failed to start HomeSOC Advanced: {e}")
