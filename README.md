# 🛡️ Task 1 — Local Network Port Discovery & Risk Analysis

## 🎯 Objective
The goal of this task was to **scan my local network for open ports**, understand which services are running, capture network packets during the scan, and perform a basic risk analysis.  

This helps in identifying **security exposures** and learning how attackers might discover and exploit open services.

## 🛠 Tools Used
- **Nmap** → for scanning hosts and discovering open ports  
- **Wireshark** → for packet capture and analysis  
- **GitHub** → to organize results, findings, and screenshots  

## 📂 Repository Structure
├── scan/
│ └── task1_scan.txt # Raw Nmap scan results
├── findings/
│ ├── findings.csv # Table of hosts, ports, services, severity
│ └── risk_analysis.md # Risk analysis explanation & severity ratings
├── packet capture/
│ └── wireshark_handshake.md # Steps + screenshot of packet capture
├── screenshots/
│ └── wireshark_handshake.png # Screenshot of SYN/SYN-ACK from Wireshark
| └── ports.png #common running ports
└── README.md # This main report

**Command run:**  
  nmap -sS -T4 192.168.20.218/24 -oN scans/open-port-scanning_scan.txt
Packet Capture
During a focused scan of one host (192.168.20.10), I captured packets with Wireshark:
nmap -sS -p 22,80 192.168.20.10


📸 Screenshot (Wireshark SYN/SYN-ACK handshake):


➡️ Steps and explanation in capture/open-port-scanning_scan.md

➡️ Optional .pcap file: capture/open-port-scanning_packet capture.pcap

Risk Analysis
I rated the severity of findings as Low, Medium, or High based on:
Service sensitivity (SSH, SMB = higher risk than HTTP)
Exposure (accessible to whole network?)
Vulnerabilities (e.g., SMBv1 known exploits)
Authentication/encryption status
Full guide: risk_analysis.txt




#How to Reproduce
-Install Nmap and Wireshark.
-Run a scan:
nmap -sS -T4 192.168.20.219/24 -oN scans/task1_scan.txt
-Capture packets in Wireshark with filter:
ip.addr == <target_ip>
-Save outputs in scans/, findings/, and captures/ folders.
-Add screenshots in screenshots/ and update Markdown files.

#Recommendations
-Close or block unnecessary ports
-Update/patch outdated services
-Use key-based authentication for SSH
-Disable SMBv1 and use secure file-sharing protocols
-Restrict admin interfaces (HTTP/HTTPS) to trusted hosts
