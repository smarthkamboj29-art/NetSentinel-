NetSentinel — Network Packet Analyzer & NIDS

A Rust-based network packet analyzer and lightweight Network Intrusion Detection System (NIDS) designed to capture live network traffic, inspect TCP, UDP, and ICMP packets, detect suspicious traffic patterns, and generate traffic statistics and CSV logs.

Overview

NetSentinel captures live traffic from an active network interface and analyzes IPv4 packets at the protocol level.

The analyzer supports selective monitoring of:

TCP
UDP
ICMP
All supported protocols

During packet capture, NetSentinel tracks traffic statistics, analyzes packet behavior, detects suspicious patterns, displays alerts in the terminal, and records captured traffic in a CSV file.

Features
Protocol Filtering

At startup, NetSentinel allows the user to select:

1. TCP
2. UDP
3. ICMP
4. ALL

This allows focused analysis of a specific protocol or monitoring of all supported protocols.

TCP Traffic Analysis

The TCP analyzer:

Parses TCP packets
Displays source and destination addresses and ports
Identifies packet direction as incoming or outgoing
Inspects TCP flags including SYN, ACK, FIN, and RST
Tracks repeated connections
Detects possible SYN scans
Detects possible SYN floods
Tracks SYN and RST activity
UDP Traffic Analysis

The UDP analyzer:

Parses UDP packets
Displays source and destination addresses and ports
Identifies traffic direction
Tracks unique destination ports over a time window
Detects possible UDP scanning activity
ICMP Traffic Analysis

The ICMP analyzer:

Parses ICMP packets
Displays source and destination addresses
Displays ICMP packet type
Tracks packet frequency within a time window
Detects possible ICMP flooding
Suspicious Activity Detection

NetSentinel applies simple threshold-based detection logic for potentially suspicious traffic patterns, including:

Possible SYN scans
Possible UDP scans
Possible SYN floods
Possible ICMP floods
Repeated network connections
Suspicious SYN/RST patterns

Detection is performed using short time windows and packet/connection thresholds.

Traffic Logging

Captured traffic is written to:

traffic.csv

The CSV file stores:

protocol, source, destination, bytes

This provides a structured record of observed network traffic for later analysis.

Traffic Statistics

After packet capture is stopped, NetSentinel displays:

Total packets
Total bytes
TCP packets
UDP packets
ICMP packets

It also displays all generated security alerts.

Graceful Shutdown

Packet capture can be stopped using:

Ctrl + C

NetSentinel uses an atomic running flag and a Ctrl+C handler to stop the capture loop cleanly and then display the final alerts and traffic statistics.

Detection Logic

The current implementation uses threshold-based rules over short time windows.

Examples include:

10+ unique destination ports within 10 seconds
→ Possible SYN/UDP scan
100+ SYN packets within 10 seconds
→ Possible SYN flood
100+ ICMP packets within 10 seconds
→ Possible ICMP flood
Connection count > 10
→ Repeated connection alert

The thresholds are implemented in the current detection logic and are intended as basic indicators rather than full intrusion detection signatures.

Architecture
Network Interface
        ↓
Live Packet Capture
        ↓
Ethernet Parsing
        ↓
IPv4 Parsing
        ↓
Protocol Filtering
   ┌────┼────┐
   ↓    ↓    ↓
 TCP   UDP  ICMP
   ↓    ↓    ↓
 Analysis & Detection
        ↓
 Alerts + CSV Logging
        ↓
 Final Statistics
Technologies Used
Rust
pnet
TCP/IP networking
Packet capture and parsing
HashMap / HashSet based state tracking
CSV logging
Atomic state management
Running the Project

Clone the repository:

git clone https://github.com/smarthkamboj29-art/NetSentinel-.git
cd NetSentinel-

Build the project:

cargo build

Run the analyzer:

cargo run

The application will ask you to select the protocol you want to analyze.

Depending on the system and network interface configuration, packet capture may require elevated privileges.

Project Structure
NetSentinel/
├── Cargo.toml
├── Cargo.lock
├── .gitignore
├── traffic.csv
└── src/
    └── main.rs
Learning Objectives

This project was developed to build practical understanding of:

Live network packet capture
Ethernet and IPv4 packet parsing
TCP, UDP, and ICMP protocols
TCP flag analysis
Network traffic direction
Stateful traffic tracking
Basic intrusion detection logic
Threshold-based anomaly detection
CSV-based traffic logging
Rust systems programming
Graceful application shutdown
Disclaimer

NetSentinel is intended for educational purposes, network monitoring, and authorized security testing only. Use it only on networks and systems for which you have permission to capture or analyze traffic.
