# NAFAT - Network Authentication Feasibility Assessment Tool

## Overview
NAFAT is an interactive CLI-based security assessment tool designed for penetration testers and network security analysts. It evaluates the feasibility and time required for wordlist and brute-force attacks against target services. By measuring network latency (RTT) via TCP sockets and integrating protocol overheads, NAFAT provides dynamic time estimates and generates structured report files.

## Features & User Stories

As a Security Analyst / Penetration Tester, I should be able to:
1. **Probe Target Ports:** Check if a service port is active and retrieve its Service Banner using raw TCP Sockets.
2. **Measure Live Latency:** Measure real-time RTT (Round Trip Time) during TCP Handshakes for accurate speed estimation.
3. **Assess Attack Feasibility:**
   - **Wordlist Attacks:** Estimate execution time based on wordlist line count.
   - **Pure Brute-Force Attacks:** Calculate total search space and estimated time based on character set complexity.
4. **Export Assessment Reports:** Automatically generate structured text and JSON reports saved directly under the `reports/` directory.

## Project Structure
The project is organized into modular Python files:
- `main.py`: Interactive CLI entry point with loop validations and clean exit handling.
- `scanner.py`: Socket probing, RTT measurement, and banner grabbing.
- `calculator.py`: Mathematical calculations for password space and time estimation.
- `report.py`: Formatting and exporting assessment results to disk.
- `config.py`: Centralized constants, timeout settings, and protocol overheads.

## Usage & Commands

1. **Run the tool:**
   ```bash
   python main.py