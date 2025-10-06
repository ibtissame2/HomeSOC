# 🛡️ HomeSOC - Home Security Operations Center

![HomeSOC Architecture](docs/images/architecture.png)

## 📋 Overview
HomeSOC is an integrated security monitoring system that simulates a real Security Operations Center environment. This project demonstrates practical cybersecurity skills including network monitoring, vulnerability assessment, and SIEM implementation.

## 🚀 Features
- **Real-time Network Monitoring** with packet analysis
- **Port Scanning Detection** and intrusion detection
- **Vulnerability Scanner** with banner grabbing
- **SIEM Dashboard** using ELK Stack (Elasticsearch, Logstash, Kibana)
- **Centralized Alerting System** with JSON logging
- **Dockerized Deployment** for easy setup

## 🛠️ Technologies Used
- **Python 3.8+** with Scapy, Pandas, Requests
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Docker & Docker Compose**
- **Ubuntu Linux** environment
- **Git** for version control

## 📁 Project Structure
HomeSOC/
├── network_monitor/ # Packet sniffing and intrusion detection
├── vuln_scanner/ # Port scanning and vulnerability assessment
├── siem/ # ELK Stack configuration
├── logs/ # Generated alerts and reports
├── docs/ # Documentation and architecture
└── screenshots/ # Dashboard screenshots

## ⚡ Quick Start

### Prerequisites
- Ubuntu 20.04+ or similar Linux distribution
- Python 3.8+
- Docker and Docker Compose
- 8GB RAM minimum (16GB recommended)

### Installation
```bash
# Clone the repository
git clone https://github.com/IbtissameHsini/HomeSOC.git
cd HomeSOC

# Install Python dependencies
pip3 install scapy pandas requests elasticsearch flask

# Start the ELK Stack
cd siem
docker-compose up -d

# Run the network monitor
cd ../network_monitor
sudo python3 packet_sniffer.py

# Test the vulnerability scanner
cd ../vuln_scanner
python3 port_scanner.py
🔧 Components
Network Traffic Monitor
Real-time packet capture using Scapy

Port scan detection with threshold analysis

DNS tunneling detection

JSON alert logging

Vulnerability Scanner
Multi-threaded port scanning

Service identification via banner grabbing

Basic vulnerability detection

Comprehensive reporting

SIEM Dashboard
Centralized log aggregation

Real-time alert visualization

Geographic threat mapping

Custom Kibana dashboards

📈 Results
293+ security alerts processed and visualized

Real-time detection of network attacks

Comprehensive vulnerability assessment reports

Professional SOC dashboard operational

🎯 Skills Demonstrated
Advanced Python programming

Network security and packet analysis

SIEM system administration

Docker containerization

Cybersecurity threat detection

Data visualization with Kibana

🤝 Contributing
Feel free to fork this project and submit pull requests for any improvements.

📄 License
This project is open source and available under the MIT License.

👤 Author
Ibtissame HSINI

LinkedIn: Ibtissame HSINI

GitHub: @IbtissameHsini

### **Étape 3 : CRÉER LES AUTRES FICHIERS ESSENTIELS**

**requirements.txt :**
```bash
cat > requirements.txt << 'EOF'
scapy==2.4.5
pandas==1.5.3
requests==2.28.2
elasticsearch==8.5.0
flask==2.2.3
python-nmap==0.7.1
