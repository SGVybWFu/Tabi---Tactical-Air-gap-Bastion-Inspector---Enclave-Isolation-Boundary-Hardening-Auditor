<p align="center">
  <img src="TABILogo.ico" alt="TABI Logo" width="160">
</p>

<h1 align="center">TABI — Tactical Air-gap & Bastion Inspector</h1>

<p align="center">
  <strong>Zero-Dependency Enclave Isolation & Boundary Hardening Auditor</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Release-v1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Python-3.7+-yellow?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Security-Air--Gap%20Hardened-red?style=flat-square" alt="Security">
</p>

<p align="center">
  
> *Dual-platform (Windows 7–11 & Linux) | Zero External Dependencies | Military & High-Assurance Enclaves*

</p>

## **🎯 Target Environments & Operational Context**

TABI was engineered to audit endpoints deployed in strictly compartmentalized, high-security enclaves where policy enforcement must be verified directly at the host and physical layer:

* **Defense Sector & Defense Contractors:** Isolated engineering terminals, laboratory workstations, and tactical jump-boxes operating within controlled or classified enclaves.  
* **Tactical Operations Centers (TOC) & Tactical Transceivers:** Verification of field terminals, mission planning laptops, and tactical communication systems (e.g., Falcon series tactical transceivers). In tactical networks, serial DATA ports (RS-232 / MIL-STD-188-114 / UART converters) can act as physical out-of-band (OOB) RF egress channels bypassing host firewalls.  
* **Critical National Infrastructure (CNI / ICS / SCADA):** Engineering workstations (EWS), human-machine interfaces (HMI), and operational technology bastions segregated from enterprise IT.  
* **Privileged Access Workstations (PAWs / Tier-0 Bastions):** Hardened administration consoles enforcing strict single-homing, ingress elimination, and physical exfiltration countermeasures aligned with **DISA STIG** and **CIS Benchmark** guidelines.  
* **Legacy Field Hardware & Ruggedized Terminals (Windows 7+ & Linux):** Compatible with ruggedized tactical laptops (e.g., Panasonic Toughbook CF-19 / CF-31 running Windows 7 SP1 / Embedded Standard 7\) through modern Windows 11 and Enterprise Linux distributions.

## **📋 Overview**

**TABI** is a dual-platform (Linux & Windows 7–11), zero-dependency Python utility designed to audit whether a system adheres to strict air-gap, bastion host, and perimeter isolation standards.

In partitioned operational networks, misconfigurations frequently undermine perimeter defenses:

* Dormant or rogue Wi-Fi/Bluetooth adapters bridge isolated subnets into wireless space.  
* Serial / COM data ports connected to modems or transceivers open out-of-band RF egress links.  
* Multi-homed network cards create bridging hazards between secure and untrusted networks.  
* Kernel packet forwarding turns an administration host into an unauthorized transit router.  
* Permissive firewall rules allow egress command-and-control (C2) channels and data exfiltration.  
* Exposed listening sockets (0.0.0.0) facilitate lateral movement across isolated boundaries.  
* Unlocked USB mass storage drivers allow weaponized hardware injection (BadUSB) or physical exfiltration.

TABI automates the validation of these attack vectors without requiring third-party libraries, compilers, or internet connectivity.

## **✨ Key Features**

* **Strict Zero-Dependency Architecture:** Runs out-of-the-box on standard Python 3 installations. No external packages (pip install) needed—critical for offline enclaves.  
* **Dual-Platform Engine (Win7 through Win11 & Linux):** Native audit logic for **Linux** (kernel sysfs, /proc, procfs networking) and **Windows** (Registry APIs, PowerShell NDIS/WMI fallback for PowerShell 2.0 on Windows 7, Winsock error codes).  
* **Hardware & RF Interface Inspection:** Multi-layer detection of wireless adapters across modern NDIS (Get-NetAdapter), legacy WMI (Win32\_NetworkAdapter), and netsh.  
* **Serial & Out-of-Band Bridge Auditing:** Identifies active RS-232, UART, and USB-serial peripheral links capable of serving as out-of-band communication vectors.  
* **Physical Exfiltration Hardening:** Audits USB mass storage driver state (Windows USBSTOR registry keys and Linux kernel storage modules).  
* **Network & Ingress Auditing:** Identifies unauthorized wildcard (0.0.0.0 / \[::\]) listeners and multi-homed IP assignments.  
* **Active Egress & DNS Leak Probing:** Tests egress firewall policies against user-defined destinations and detects unisolated DNS query forwarding.  
* **Interactive Setup Wizard:** Built-in guided CLI wizard for interactive execution, with full headless CLI flag support for scripting and automated pipelines.  
* **Dual-Language Reporting:** Full runtime localization and report generation in **English** and **Polish**.  
* **Dual Output Formats:** Generates SIEM-ready structured JSON alongside clean, formatted plaintext audit logs with execution timestamps (tabi\_report\_YYYY-MM-DD\_HH-MM-SS.txt).

## **🔍 Audit Capabilities**

| Check Category | Linux Implementation | Windows Implementation (Win7 \- Win11) | Security Rationale |
| :---- | :---- | :---- | :---- |
| **Multi-Homing** | getaddrinfo \+ routing-table evaluation | Routing-table evaluation & local IP enumeration | Prevents accidental bridging between isolated zones |
| **Wireless / RF Isolation** | /sys/class/net wireless flags & /sys/class/rfkill | NDIS (Get-NetAdapter), WMI (Win32\_NetworkAdapter), netsh | Eliminates wireless backdoors and out-of-band air-gap bypasses |
| **Serial / Hardware Bridges** | /sys/bus/usb-serial, /dev/serial/by-id, /dev/ttyACM\* | Registry key HARDWARE\\DEVICEMAP\\SERIALCOMM | Detects covert serial/modem links bypassing network firewalls |
| **Kernel Forwarding** | /proc/sys/net/ipv4/ip\_forward | Registry key IPEnableRouter in Tcpip\\Parameters | Stops the host from acting as a transit router |
| **USB Storage Lockdown** | Kernel module inspection (usb\_storage, uas in /proc/modules) | Registry key Start in Services\\USBSTOR | Mitigates physical exfiltration and BadUSB injection vectors |
| **Ingress Exposure** | Procfs socket parsing (/proc/net/tcp, /proc/net/udp) | netstat \-ano listening socket enumeration | Prevents lateral movement via wildcard 0.0.0.0 bindings |
| **DNS Query Leakage** | Domain resolution probe against honeypot FQDN | Domain resolution probe against honeypot FQDN | Validates that enclave DNS queries do not escape to public resolvers |
| **Egress Filtering** | TCP SYN probes with socket errno decoding | TCP SYN probes with Winsock error decoding (10035, etc.) | Verifies outbound firewall drop rules (C2 mitigation) |

## **🚀 Installation & Usage**

### **Prerequisites**

* Python 3.7+ installed (for Windows 7, Python 3.8.10 is recommended; or use standalone TABI Tactical Air-gap & Bastion Inspector.exe).  
* Standard administrative privileges recommended for complete hardware and registry inspection.

### **Running TABI Interactively**

Simply run the script without arguments to launch the interactive configuration wizard:

\# On Linux  
python3 tabi.py

\# On Windows (Command Prompt or PowerShell)  
py tabi.py  
\# Or if using compiled standalone executable:  
.\\TABI Tactical Air-gap & Bastion Inspector.exe

The interactive wizard will guide you through language selection, audit profile selection (Standard Bastion vs. Strict Air-gap), and probe scope.

### **Command-Line Arguments (Automated / Headless Mode)**

TABI supports comprehensive CLI flags for automated pipelines, security assessments, and scheduled tasks:

usage: tabi \[-h\] \[--lang {en,pl}\] \[--profile {bastion,airgap}\] \[--quick\]  
            \[--targets TARGETS \[TARGETS ...\]\] \[--ports PORTS \[PORTS ...\]\]  
            \[--timeout TIMEOUT\] \[--output OUTPUT\] \[--txt-output TXT\_OUTPUT\]  
            \[--dns-check DNS\_CHECK\] \[--version\]

TABI: Tactical Air-gap & Bastion Inspector \- Host Isolation & Egress Auditor.

options:  
  \-h, \--help            show this help message and exit  
  \--lang, \-l {en,pl}    Interface & report language ('en' or 'pl').  
  \--profile {bastion,airgap}  
                        Policy profile (default: bastion).  
  \--quick, \-q           Stealth mode: audit local host only without outbound packets.  
  \--targets TARGETS \[TARGETS ...\]  
                        Egress probe destination IPs (default: 1.1.1.1 8.8.8.8 192.168.1.1).  
  \--ports PORTS \[PORTS ...\]  
                        TCP ports for outbound probes (default: 53 80 443 22 123).  
  \--timeout TIMEOUT     Socket timeout in seconds (default: 1.5).  
  \--output, \-o OUTPUT   Output file path for JSON report.  
  \--txt-output, \-t TXT\_OUTPUT  
                        Output file path for human-readable TXT log.  
  \--dns-check DNS\_CHECK Probe domain for DNS leak test.  
  \--version, \-v         show program's version number and exit

## **💡 Usage Examples**

### **1\. Fast, Passive Local Audit (No Network Probes)**

Audit only the local machine's configuration, hardware, USB, and listening ports without emitting any network traffic:

python3 tabi.py \--quick

### **2\. Strict Air-Gap Assessment in Polish**

Enforce zero tolerance for external IP interfaces and output all logs in Polish:

python3 tabi.py \--profile airgap \--lang pl

### **3\. Custom Egress Verification with Explicit Output Paths**

Test firewall rules against specific IP ranges and export reports to designated locations:

python3 tabi.py \--targets 10.0.0.1 192.168.10.5 \--ports 80 443 8080 \-o report.json \-t report.txt

## **📄 License**

This project is licensed under the MIT License — see the [LICENSE](http://docs.google.com/LICENSE) file for details.
