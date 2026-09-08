# **Changelog**

All notable changes to the **TABI** (Tactical Air-gap & Bastion Inspector) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),

and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## **\[1.1.0\] \- 2026-09-08**

### **Added**

* **INCONCLUSIVE Status Classification:** Introduced an ambiguous audit outcome category alongside PASS, WARN, and FAIL to eliminate false confidence in border security tests.  
* **Detailed Socket Error Code Decoder (\_explain\_socket\_error):** Cross-platform mapping of POSIX and Winsock network errno codes (e.g., WSAEWOULDBLOCK, WSAETIMEDOUT, WSAECONNREFUSED, WSAEHOSTUNREACH, ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH).  
* **Cryptographic Report Integrity Verification:** Automatic SHA-256 calculation for both structured JSON and plain-text TXT reports upon generation. The digest is embedded directly into the report metadata and displayed in console summaries.  
* **Enhanced Visual CLI Status Labels:** Color-coded INCONCLUSIVE tag (magenta) and separate counters in CLI and report summaries.

### **Changed**

* **Egress Evaluation Logic Overhaul:**  
  * PASS is now awarded **strictly** when packets are silently dropped without acknowledgment (ETIMEDOUT, WSAETIMEDOUT, WSAEWOULDBLOCK, EAGAIN), proving an active silent DROP firewall rule.  
  * Active rejections (ECONNREFUSED / 10061 / 111\) are classified as INCONCLUSIVE, recognizing that a TCP RST can originate either from a firewall REJECT rule or an external host on an unblocked perimeter.  
  * Unreachable routing errors (EHOSTUNREACH, ENETUNREACH, 10065, 10051\) are flagged as INCONCLUSIVE since missing routes or physical disconnections do not prove firewall policy enforcement.  
* **DNS Leak Test Realism:** Domain resolution failures (socket.gaierror / NXDOMAIN) are no longer reported as PASS. They are classified as INCONCLUSIVE with explicit security guidance indicating that domain non-existence does not prove the outbound query was blocked by network controls.  
* **Audit Table & Rationale Refinement:** Updated technical terminology from ambiguous raw packet claims to precise TCP socket probing and perimeter rule evaluation.

## **\[1.0.0\] \- 2026-09-07**

### **Added**

* Initial public release of TABI.  
* Zero-dependency inspection engine compatible with Windows 7–11 and Linux.  
* Multi-homing network boundary auditing via RFC 5737 route discovery.  
* RF transceiver inspection (Linux sysfs/rfkill, Windows NDIS/WMI/netsh).  
* Serial, COM, and UART out-of-band communication link detection.  
* Kernel packet forwarding checks (ip\_forward, Windows IPEnableRouter).  
* USB mass storage driver lockdown checks (USBSTOR, usb\_storage/uas).  
* Listening socket analysis (0.0.0.0 wildcard exposure).  
* Outbound TCP egress probes and basic DNS honeypot query resolution.  
* Interactive CLI setup wizard with dual-language support (English & Polish).  
* Automated reporting in JSON and TXT formats.