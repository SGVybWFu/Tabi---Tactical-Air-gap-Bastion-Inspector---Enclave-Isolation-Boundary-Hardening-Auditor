#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TABI - Tactical Air-gap & Bastion Inspector (v1.1)
Author: SGVybWFu
GitHub: https://github.com/SGVybWFu/tabi

Audits network boundaries, RF hardware, removable media locks,
serial/COM out-of-band bridges, listening sockets, and egress filtering.
Zero external dependencies. Compatible with Linux & Windows (7/8/10/11).
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys

VERSION = "1.1"
IS_WIN = platform.system() == "Windows"

# Detect legacy Windows (Windows 7 / 8 / Server 2008 R2)
IS_WIN_LEGACY = False
if IS_WIN:
    try:
        IS_WIN_LEGACY = sys.getwindowsversion().major < 10
    except Exception:
        IS_WIN_LEGACY = False

    # Try enabling VT100 virtual terminal processing on Windows 10+
    if not IS_WIN_LEGACY:
        try:
            os.system("")
        except Exception:
            pass

# ANSI color definitions
CLR_RESET   = "\033[0m"
CLR_BOLD    = "\033[1m"
CLR_DIM     = "\033[2m"
CLR_RED     = "\033[91m"
CLR_GREEN   = "\033[92m"
CLR_WARN    = "\033[93m"
CLR_CYAN    = "\033[96m"
CLR_MAGENTA = "\033[95m"

def paint(text: str, color_code: str) -> str:
    # Strip ANSI escape codes on legacy Windows 7 consoles to avoid rendering raw artifacts
    if IS_WIN_LEGACY:
        return text
    return f"{color_code}{text}{CLR_RESET}"

def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)

def calculate_sha256(filepath: str) -> str:
    """Computes SHA-256 hash of an artifact for supply chain integrity."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest().upper()
    except Exception:
        return ""

BANNER = r"""
                       ---                       -==                      
                    -+**##+-=                 --+++++--                   
                   =+***#%%#=-=             ==#%%%%#*+==                  
                 +=*+=+####@%*==+===  ==+==+*%@%#*##+=*==                 
                +=*%++#%@%%@@%*===========*#%@@%#%%#*=+*==                
               +=*%*=*%@@@@#******+**+***#****%@@@@%*=+%#=                
               =-+#*+*%@@@#***############*#***#@@@%*=+%%#+               
              --=+**#%@@#**+++*####%%%#####**+**##@%#++*#+=               
             ---+***#%#**++++++***#%%%###**++++****#%%#*#*++              
             ==+**##*++**+++==+++*######*++===++++***#%%##*+              
             +=+#*+==+******+*++==+###*+=++==++++++****%%#***             
            +++===+++****#%%%#**=--+**+--=+*###***++*+***+++*             
             +==+*#*==-=+*%@@@@*===+***=-=#@@@%#**+++++***#**             
             ++=++--==----=*@@@@@%*+++*%@@@@@#*=---===+**####             
             *+*+=-----=---+##%*=--====--+###*=--=--=-==+***#             
             *#*----===----===-::-=++=-----=+=---===-=-==*****            
             *+++--====-------:-=#@@@@@#=------=-=+==---++###             
            #*+=---======+===-=*+@@@@@@@++*======-====--=+##**            
            ***++--======++*==+**#@@@@@#***+=*++====--===+****            
            *%**=++====+++**#+*##%@@@@@%###**#+==+++=-=+=*####            
             #%##**=+*+==+++#%%%@@@@@@@@@%%@@#===*+==+++###%%             
             %@@@@%***+++++++*%@@@####*%@@@%*+===+++==**#@@@              
           ###%%@%%@@#*#**+****#%%%@@@@%%#*+=++++*+**#*@@@@@##%           
         %#%#%@@@@%@@@@%%#%***++###%%%##****#*+**###@@@@%%@@@%@%          
         @%@%@@%#%%%@@@@@@@%#*+#*%#%%%#*#**+*%%#@@@%%%@@#%@@@@@@@         
          @@@@@%%@@@@@@@%%@@@%#%@@%%%%%#%%##*%@@@#@@##%@%%@@@@@@          
           @@@@@@@@@@@@@%##%%%%%@@@@%%@@@@@%%%%%@#%%@#@%%%@@@@            
             @@@@@@%@@@@%%%@@%%%%@@@@@@@@@%%%@%%@@%%%@@@@@@@@             
               @@@@@@@@%%%@@@%%%@%+%+#*#@@%%%@%@@@@@@@@@@@@               
                 @@@@@@@%%@@@@@%@@###*##@@%%@@%@@@@@@@@@@                 
                    @@@@@@@@@@@@@@@@@@@@@@%%%@@@@@@@@@                    
                        @@@@@@@@%%%%%%%%%%%@@@@@@@                        
                             @@@@@@@@@@@@@@@@                             
"""

TEXTS = {
    "en": {
        "title": f"TABI - Tactical Air-gap & Bastion Inspector (v{VERSION})",
        "sub": "Enclave Isolation & Boundary Hardening Auditor",
        "step_iface": "[*] Auditing network interfaces and multi-homing...",
        "step_rf": "[*] Checking wireless / RF transceivers...",
        "step_serial": "[*] Auditing serial / COM / UART out-of-band interfaces...",
        "step_hard": "[*] Auditing kernel flags and removable media controls...",
        "step_sock": "[*] Checking listening sockets and ingress exposure...",
        "step_dns": "[*] Testing DNS query leakage...",
        "step_egress": "[*] Testing outbound egress filtering...",
        "step_skip": "[*] Quick mode enabled: skipping outbound network probes.",
        "test_mh": "Multi-Homing Boundary Check",
        "test_rf": "Wireless & RF Isolation",
        "test_serial": "Serial & Out-of-Band Hardware Bridges (RS-232/UART)",
        "test_fwd": "Kernel Packet Forwarding",
        "test_usb": "Removable Media Lockdown",
        "test_sock": "Listening Sockets (Ingress Exposure)",
        "test_egress": "Egress Filtering (Outbound TCP Probes)",
        "test_dns": "DNS Resolution Boundary Check",
        "mh_fail": "Multiple non-loopback IP addresses found: {ips}. Risk of traffic bridging between zones.",
        "mh_pass_one": "Single active interface identified: {ip}.",
        "mh_pass_zero": "No external IPs assigned (isolated loopback-only host).",
        "exp_mh_fail": "Multi-homing connects distinct networks, letting an attacker bypass physical perimeters.",
        "exp_mh_pass": "Interface layout conforms to single-boundary bastion or isolated enclave rules.",
        "rf_win_none": "No active wireless/Wi-Fi adapters found.",
        "rf_win_hit": "Active wireless hardware detected: {name}!",
        "rf_notsup": "RF inspection not implemented for {sys}.",
        "rf_lin_hit": "Active wireless interfaces or unblocked RF hardware detected: {details}!",
        "rf_lin_none": "No active wireless NICs or unblocked RF transmitters found.",
        "exp_rf_fail": "Radio hardware provides an out-of-band channel, bypassing perimeter firewalls.",
        "exp_rf_pass": "Radio interfaces disabled, preserving electromagnetic boundary isolation.",
        "serial_warn": "Active serial/COM hardware bridges detected:\n{items}",
        "serial_pass": "No active serial or COM hardware bridges detected.",
        "exp_serial_warn": "Active serial links (RS-232, tactical transceivers, UART adapters) enable out-of-band data egress bypassing network firewalls.",
        "exp_serial_pass": "Serial peripheral perimeter clear; no active hardware communication channels detected.",
        "fwd_win_on": "IPv4 routing is active in registry (IPEnableRouter=1). Host bridges packets!",
        "fwd_win_off": "IPv4 packet routing is disabled in registry (IPEnableRouter=0).",
        "fwd_lin_on": "IPv4 packet forwarding enabled in sysctl (net.ipv4.ip_forward=1).",
        "fwd_lin_off": "IPv4 forwarding disabled in kernel.",
        "exp_fwd_fail": "Enabled forwarding routes untrusted transit traffic between network segments.",
        "exp_fwd_pass": "Transit routing disabled; host drops forwarded packets.",
        "usb_win_lock": "USB mass storage driver disabled in registry (USBSTOR Start=4).",
        "usb_win_warn": "USB mass storage driver is enabled (USBSTOR Start={val}). Risk of physical exfil or BadUSB mass storage mount.",
        "usb_lin_warn": "Removable storage kernel modules currently loaded: {drivers}.",
        "usb_lin_pass": "No USB mass storage kernel modules loaded.",
        "exp_usb_warn": "Active USB storage drivers allow data exfiltration and physical mount attacks (note: non-storage USB attacks like HID BadUSB require separate OS device control).",
        "exp_usb_pass": "Removable storage disabled at driver level, mitigating unauthorized USB mass storage mounting.",
        "sock_warn": "Services bound to wildcard or external IPs:\n{items}",
        "sock_pass": "No unauthorized listeners bound to wildcard 0.0.0.0 addresses.",
        "exp_sock_warn": "Wildcard 0.0.0.0 listeners accept connections from any interface unless blocked by active host firewall rules.",
        "exp_sock_pass": "No unhardened ingress listeners exposed to external networks.",
        "egress_fail": "Outbound TCP connection established to {host}:{port}. Egress policy violated!",
        "egress_pass": "Connection to {host}:{port} dropped silently (code: {code} - {reason}). Firewall DROP rule verified.",
        "egress_ambiguous": "Connection to {host}:{port} rejected ({reason}). Inconclusive: TCP RST could originate from firewall REJECT or target host with permissive egress.",
        "egress_unreach": "Target {host}:{port} unreachable ({reason}). Inconclusive: Route missing or network disconnected; does not verify firewall policy.",
        "egress_dns_err": "Target {host} could not be resolved (unresolvable destination).",
        "exp_egress_fail": "Permissive egress allows command-and-control beacons, reverse shells, or data exfiltration.",
        "exp_egress_pass": "Firewall successfully dropped outbound probe without acknowledgment (silent DROP rule confirmed).",
        "exp_egress_inconclusive": "Network error or active rejection does not guarantee perimeter firewall enforcement. Manual firewall rule inspection required.",
        "dns_warn": "Probe domain '{domain}' resolved to {ip}. External DNS resolution confirmed!",
        "dns_inconclusive": "Probe domain '{domain}' did not resolve (NXDOMAIN/gaierror). Note: NXDOMAIN does not prove query encapsulation or firewall blocking; upstream resolvers may have processed the query.",
        "exp_dns_warn": "Resolution confirms internal queries traverse to external/untrusted resolvers.",
        "exp_dns_inconclusive": "NXDOMAIN only confirms the domain does not exist; traffic capture is necessary to ensure DNS packets never exit the boundary.",
        "summary_title": "AUDIT RESULTS SUMMARY",
        "stats": "TOTALS: PASS: {p} | WARN: {w} | FAIL: {f} | INCONCLUSIVE: {inc}",
        "hint": "💡 Review audit log with: {cmd} {path}",
        "sec_label": "Security Context:",
        "integrity_label": "Audit Integrity Seal (Session SHA-256):",
        "exit_prompt": "\n🏁 Press [ENTER] to exit..."
    },
    "pl": {
        "title": f"TABI - Taktyczny Inspektor Bastionów i Stref Air-gap (v{VERSION})",
        "sub": "Audytor izolacji enklawy i szczelności reguł brzegowych",
        "step_iface": "[*] Weryfikacja interfejsów sieciowych i ryzyka multi-homingu...",
        "step_rf": "[*] Inspekcja modułów radiowych (Wi-Fi / Bluetooth)...",
        "step_serial": "[*] Audyt portów szeregowych COM/TTY (RS-232/UART/Modemy)...",
        "step_hard": "[*] Audyt parametrów jądra i blokady nośników USB...",
        "step_sock": "[*] Analiza nasłuchujących gniazd sieciowych (Ingress)...",
        "step_dns": "[*] Weryfikacja izolacji zapytań DNS...",
        "step_egress": "[*] Testowanie filtracji ruchu wyjściowego (Egress)...",
        "step_skip": "[*] Tryb szybki: pomijanie aktywnych sond sieciowych.",
        "test_mh": "Audyt multi-homingu (wielu kart)",
        "test_rf": "Izolacja interfejsów radiowych (RF/Wi-Fi)",
        "test_serial": "Porty szeregowe i mostki sprzętowe (RS-232/UART/COM)",
        "test_fwd": "Trasowanie pakietów w jądrze (IP Forwarding)",
        "test_usb": "Blokada pamięci masowych USB",
        "test_sock": "Ekspozycja portów nasłuchujących (Ingress)",
        "test_egress": "Filtracja ruchu wychodzącego (Sondy TCP Egress)",
        "test_dns": "Izolacja zapytań DNS",
        "mh_fail": "Wykryto wiele zewnętrznych adresów IP: {ips}. Ryzyko mostkowania ruchu między strefami!",
        "mh_pass_one": "Zidentyfikowano pojedynczy interfejs podstawowy: {ip}.",
        "mh_pass_zero": "Brak zewnętrznych adresów IP. Maszyna działa w trybie pełnej izolacji / pętli zwrotnej.",
        "exp_mh_fail": "Obecność wielu kart pozwala ominąć zaporę fizyczną i przerzucać pakiety między sieciami.",
        "exp_mh_pass": "Liczba interfejsów zgodna z polityką pojedynczej strefy lub bastionu.",
        "rf_win_none": "Brak aktywnych kart bezprzewodowych Wi-Fi.",
        "rf_win_hit": "Wykryto aktywny adapter bezprzewodowy: {name}! Zagrożenie obejścia air-gapu.",
        "rf_notsup": "Brak obsługi audytu RF dla platformy {sys}.",
        "rf_lin_hit": "Wykryto aktywne nadajniki bezprzewodowe: {details}!",
        "rf_lin_none": "Brak aktywnych kart Wi-Fi lub odblokowanych nadajników radiowych.",
        "exp_rf_fail": "Nadajniki radiowe pozwalają na komunikację poza pasmem i ominięcie zapory sieciowej.",
        "exp_rf_pass": "Interfejsy radiowe wyłączone, zachowana szczelność elektromagnetyczna enklawy.",
        "serial_warn": "Wykryto aktywne porty szeregowe COM/TTY:\n{items}",
        "serial_pass": "Brak aktywnych mostków szeregowych COM/RS-232.",
        "exp_serial_warn": "Porty szeregowe (RS-232, radiostacje taktyczne, konwertery UART) stanowią fizyczny kanał transmisji poza pasmem (OOB), omijając zapory.",
        "exp_serial_pass": "Brak aktywnych urządzeń szeregowych; fizyczny obwód stacji pozostaje szczelny.",
        "fwd_win_on": "Trasowanie IPv4 włączone w rejestrze (IPEnableRouter=1). Host mostkuje pakiety!",
        "fwd_win_off": "Trasowanie pakietów IPv4 jest wyłączone (IPEnableRouter=0).",
        "fwd_lin_on": "Trasowanie IPv4 aktywne w jądrze (net.ipv4.ip_forward=1). Host trasuje obcy ruch!",
        "fwd_lin_off": "Trasowanie pakietów wyłączone w jądrze.",
        "exp_fwd_fail": "Włączony routing przekształca maszynę w router przekazujący pakiety między strefami.",
        "exp_fwd_pass": "Ruch tranzytowy jest odrzucany przez system.",
        "usb_win_lock": "Obsługa pamięci masowych USB zablokowana w rejestrze (USBSTOR Start=4).",
        "usb_win_warn": "Obsługa pamięci USB włączona (USBSTOR Start={val}). Ryzyko podłączenia pamięci flash (uwaga: urządzenia inne niż storage, np. HID BadUSB, wymagają odrębnej kontroli).",
        "usb_lin_warn": "Załadowano moduły pamięci masowej USB ({drivers}). Polityka nośników nieutwardzona.",
        "usb_lin_pass": "Sterowniki pamięci masowej USB nie są załadowane w jądrze.",
        "exp_usb_warn": "Aktywne moduły pamięci masowej USB umożliwiają montowanie nośników i kradzież danych.",
        "exp_usb_pass": "Porty pamięci masowej USB zablokowane na poziomie sterownika (ochrona przed nośnikami wymiennymi).",
        "sock_warn": "Usługi nasłuchujące na adresach 0.0.0.0 lub zewnętrznych:\n{items}",
        "sock_pass": "Brak nieautoryzowanych usług nasłuchujących na interfejsach 0.0.0.0.",
        "exp_sock_warn": "Gniazda nasłuchujące na 0.0.0.0 są dostępne z każdego interfejsu, chyba że blokuje je lokalny firewall.",
        "exp_sock_pass": "Brak niebezpiecznych gniazd sieciowych wystawionych na ruch z zewnątrz.",
        "egress_fail": "Nawiązano połączenie TCP z {host}:{port}. Naruszenie reguł zapory!",
        "egress_pass": "Połączenie z {host}:{port} zrzucone po cichu (kod: {code} - {reason}). Potwierdzono regułę DROP na zaporze.",
        "egress_ambiguous": "Połączenie z {host}:{port} odrzucone ({reason}). Wynik niejednoznaczny: TCP RST może pochodzić z reguły REJECT na zaporze LUB od zdalnego serwera przy braku blokady wyjścia!",
        "egress_unreach": "Cel {host}:{port} nieosiągalny ({reason}). Wynik niejednoznaczny: brak trasy w systemie; nie dowodzi to działania zapory sieciowej.",
        "egress_dns_err": "Cel {host} nie został rozwiązany (brak rekordu w sieci).",
        "exp_egress_fail": "Otwarte wyjście pozwala na nawiązanie powłoki zwrotnej (reverse shell) i łączność z C2.",
        "exp_egress_pass": "Zapora sieciowa prawidłowo odrzuca ruch wychodzący (pakiet SYN porzucony po cichu).",
        "exp_egress_inconclusive": "Błąd sieciowy lub aktywne odrzucenie RST nie dają gwarancji działania zapory brzegowej. Wymagana ręczna weryfikacja reguł.",
        "dns_warn": "Sonda DNS rozwiązała domenę '{domain}' na adres {ip}. Potwierdzony wyciek zapytań poza sieć!",
        "dns_inconclusive": "Domena testowa '{domain}' nie została rozwiązana (NXDOMAIN/gaierror). Uwaga: brak rekordu NXDOMAIN nie dowodzi blokady pakietów; zapytanie mogło opuścić sieć i dotrzeć do resolvera nadrzędnego.",
        "exp_dns_warn": "Pomyślna rezolucja dowodzi, że zapytania DNS wyciekają do publicznych/zewnętrznych resolverów.",
        "exp_dns_inconclusive": "NXDOMAIN informuje wyłącznie o braku rekordu w bazie; pełna weryfikacja szczelności wymaga przechwytywania ruchu pcap.",
        "summary_title": "PODSUMOWANIE AUDYTU BEZPIECZEŃSTWA",
        "stats": "WYNIKI: PASS: {p} | WARN: {w} | FAIL: {f} | INCONCLUSIVE: {inc}",
        "hint": "💡 Przejrzyj log audytu poleceniem: {cmd} {path}",
        "sec_label": "Znaczenie bezpieczeństwa:",
        "integrity_label": "Pieczęć Integralności Audytu (Session SHA-256):",
        "exit_prompt": "\n🏁 Naciśnij [ENTER], aby zamknąć to okno..."
    }
}

class TabiAuditor:
    def __init__(self, targets, ports, timeout=1.5, lang="en", profile="bastion"):
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.lang = lang if lang in TEXTS else "en"
        self.profile = profile
        self.i18n = TEXTS[self.lang]
        self.findings = []

    def record(self, test, status, severity, details, explanation=""):
        self.findings.append({
            "test": test,
            "status": status,
            "severity": severity,
            "details": details,
            "explanation": explanation
        })

    def check_interfaces(self):
        print(paint(self.i18n["step_iface"], CLR_CYAN))
        ips = []

        try:
            for entry in socket.getaddrinfo(socket.gethostname(), None):
                ip = entry[4][0]
                if not ip.startswith("127.") and ip != "::1" and ip not in ips:
                    ips.append(ip)
        except Exception:
            pass

        # Trick routing table via TEST-NET-1 (RFC 5737) without emitting traffic
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("192.0.2.1", 80))
            best_ip = sock.getsockname()[0]
            sock.close()
            if not best_ip.startswith("127.") and best_ip not in ips:
                ips.append(best_ip)
        except Exception:
            pass

        name = self.i18n["test_mh"]
        if len(ips) > 1:
            self.record(name, "FAIL", "CRITICAL", self.i18n["mh_fail"].format(ips=ips), self.i18n["exp_mh_fail"])
        elif len(ips) == 1:
            if self.profile == "airgap":
                self.record(name, "WARN", "MEDIUM", f"{self.i18n['mh_pass_one'].format(ip=ips[0])} [Strict airgap expects 0]", self.i18n["exp_mh_fail"])
            else:
                self.record(name, "PASS", "LOW", self.i18n["mh_pass_one"].format(ip=ips[0]), self.i18n["exp_mh_pass"])
        else:
            self.record(name, "PASS", "INFO", self.i18n["mh_pass_zero"], self.i18n["exp_mh_pass"])

    def check_rf(self):
        print(paint(self.i18n["step_rf"], CLR_CYAN))
        name = self.i18n["test_rf"]

        if IS_WIN:
            cards = []

            # 1. Primary inspection for modern Windows (8/10/11) via PowerShell NDIS module
            try:
                ps_script = (
                    "Get-NetAdapter | Where-Object { "
                    "$_.PhysicalMediaType -match '802.11|Wireless|Native 802.11' -or "
                    "$_.InterfaceDescription -match 'Wireless|Wi-Fi|802.11|WLAN' -or "
                    "$_.Name -match 'Wi-Fi|Wireless' "
                    "} | Select-Object -ExpandProperty InterfaceDescription"
                )
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True, timeout=4)
                cards = [line.strip() for line in res.stdout.splitlines() if line.strip() and not line.strip().startswith("Get-NetAdapter :")]
            except Exception:
                pass

            # 2. Resilient fallback for Windows 7 (PowerShell 2.0 uses Win32_NetworkAdapter WMI)
            if not cards:
                try:
                    wmi_script = (
                        "Get-WmiObject Win32_NetworkAdapter | Where-Object { "
                        "$_.AdapterType -match 'Wireless' -or "
                        "$_.Name -match 'Wireless|Wi-Fi|802.11|WLAN' -or "
                        "$_.Description -match 'Wireless|Wi-Fi|802.11|WLAN' "
                        "} | Select-Object -ExpandProperty Name"
                    )
                    res = subprocess.run(["powershell", "-NoProfile", "-Command", wmi_script], capture_output=True, text=True, timeout=4)
                    cards = [line.strip() for line in res.stdout.splitlines() if line.strip()]
                except Exception:
                    pass

            # 3. Third-layer fallback: netsh wlan
            if not cards:
                try:
                    res = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=3)
                    stdout = res.stdout
                    has_tokens = any(k in stdout for k in ("State", "Stan", "SSID", "GUID", "Radio", "Description", "Opis"))
                    is_missing = any(k in stdout for k in ("no wireless interface", "Brak bezprzewodowego", "nie jest uruchomiona", "is not running"))
                    if has_tokens and not is_missing:
                        cards.append("WLAN Interface (netsh)")
                except Exception:
                    pass

            if cards:
                clean_cards = sorted(list(set(cards)))
                self.record(name, "FAIL", "CRITICAL", self.i18n["rf_win_hit"].format(name=", ".join(clean_cards)), self.i18n["exp_rf_fail"])
            else:
                self.record(name, "PASS", "LOW", self.i18n["rf_win_none"], self.i18n["exp_rf_pass"])
            return

        if platform.system() != "Linux":
            self.record(name, "INFO", "LOW", self.i18n["rf_notsup"].format(sys=platform.system()), self.i18n["exp_rf_pass"])
            return

        wireless_devs = []
        if os.path.isdir("/sys/class/net"):
            try:
                for iface in os.listdir("/sys/class/net"):
                    is_wireless = os.path.exists(f"/sys/class/net/{iface}/wireless") or iface.startswith(("wlan", "wlp", "wifi"))
                    if is_wireless:
                        operstate = "unknown"
                        p = f"/sys/class/net/{iface}/operstate"
                        if os.path.isfile(p):
                            with open(p, "r") as f:
                                operstate = f.read().strip()
                        wireless_devs.append(f"{iface} ({operstate})")
            except Exception:
                pass

        rfkill_unblocked = []
        if os.path.isdir("/sys/class/rfkill"):
            try:
                for dev in os.listdir("/sys/class/rfkill"):
                    p_type = f"/sys/class/rfkill/{dev}/type"
                    p_soft = f"/sys/class/rfkill/{dev}/soft"
                    if os.path.isfile(p_type) and os.path.isfile(p_soft):
                        with open(p_type, "r") as f:
                            dev_t = f.read().strip()
                        with open(p_soft, "r") as f:
                            soft_blocked = f.read().strip() == "1"
                        if not soft_blocked:
                            rfkill_unblocked.append(f"{dev_t} (active)")
            except Exception:
                pass

        if wireless_devs or rfkill_unblocked:
            summary = []
            if wireless_devs:
                summary.append(f"interfaces: {', '.join(wireless_devs)}")
            if rfkill_unblocked:
                summary.append(f"transceivers: {', '.join(rfkill_unblocked)}")
            self.record(name, "FAIL", "CRITICAL", self.i18n["rf_lin_hit"].format(details="; ".join(summary)), self.i18n["exp_rf_fail"])
        else:
            self.record(name, "PASS", "LOW", self.i18n["rf_lin_none"], self.i18n["exp_rf_pass"])

    def check_serial_ports(self):
        """Audits RS-232 / UART / USB-serial peripheral bridges (out-of-band egress channels)."""
        print(paint(self.i18n["step_serial"], CLR_CYAN))
        name = self.i18n["test_serial"]
        ports = []

        if IS_WIN:
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\SERIALCOMM") as k:
                    idx = 0
                    while True:
                        try:
                            val_name, port_val, _ = winreg.EnumValue(k, idx)
                            ports.append(f"{port_val} ({val_name.split(chr(92))[-1]})")
                            idx += 1
                        except OSError:
                            break
            except Exception:
                pass

        elif platform.system() == "Linux":
            if os.path.isdir("/sys/bus/usb-serial/devices"):
                try:
                    for dev in os.listdir("/sys/bus/usb-serial/devices"):
                        ports.append(f"/dev/{dev} (USB-Serial)")
                except Exception:
                    pass

            if os.path.isdir("/dev/serial/by-id"):
                try:
                    for dev in os.listdir("/dev/serial/by-id"):
                        ports.append(f"/dev/serial/by-id/{dev}")
                except Exception:
                    pass

            if os.path.isdir("/dev"):
                try:
                    for dev in os.listdir("/dev"):
                        if dev.startswith("ttyACM"):
                            ports.append(f"/dev/{dev} (ACM modem/data link)")
                except Exception:
                    pass

        if ports:
            clean_list = sorted(list(set(ports)))
            formatted = "\n".join(f"      - {p}" for p in clean_list)
            self.record(name, "WARN", "MEDIUM", self.i18n["serial_warn"].format(items=formatted), self.i18n["exp_serial_warn"])
        else:
            self.record(name, "PASS", "LOW", self.i18n["serial_pass"], self.i18n["exp_serial_pass"])

    def check_system_hardening(self):
        print(paint(self.i18n["step_hard"], CLR_CYAN))
        lbl_fwd = self.i18n["test_fwd"]
        lbl_usb = self.i18n["test_usb"]

        if IS_WIN:
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as k:
                    val, _ = winreg.QueryValueEx(k, "IPEnableRouter")
                    if val == 1:
                        self.record(lbl_fwd, "FAIL", "CRITICAL", self.i18n["fwd_win_on"], self.i18n["exp_fwd_fail"])
                    else:
                        self.record(lbl_fwd, "PASS", "LOW", self.i18n["fwd_win_off"], self.i18n["exp_fwd_pass"])
            except Exception:
                pass

            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR") as k:
                    start_val, _ = winreg.QueryValueEx(k, "Start")
                    if start_val == 4:
                        self.record(lbl_usb, "PASS", "LOW", self.i18n["usb_win_lock"], self.i18n["exp_usb_pass"])
                    else:
                        self.record(lbl_usb, "WARN", "MEDIUM", self.i18n["usb_win_warn"].format(val=start_val), self.i18n["exp_usb_warn"])
            except Exception:
                pass
            return

        if platform.system() != "Linux":
            return

        if os.path.isfile("/proc/sys/net/ipv4/ip_forward"):
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    enabled = f.read().strip() == "1"
                if enabled:
                    self.record(lbl_fwd, "FAIL", "CRITICAL", self.i18n["fwd_lin_on"], self.i18n["exp_fwd_fail"])
                else:
                    self.record(lbl_fwd, "PASS", "LOW", self.i18n["fwd_lin_off"], self.i18n["exp_fwd_pass"])
            except Exception:
                pass

        if os.path.isfile("/proc/modules"):
            try:
                with open("/proc/modules", "r") as f:
                    mods = f.read()
                active = [m for m in ("usb_storage", "uas") if re.search(rf"\b{m}\b", mods)]
                if active:
                    self.record(lbl_usb, "WARN", "MEDIUM", self.i18n["usb_lin_warn"].format(drivers=", ".join(active)), self.i18n["exp_usb_warn"])
                else:
                    self.record(lbl_usb, "PASS", "LOW", self.i18n["usb_lin_pass"], self.i18n["exp_usb_pass"])
            except Exception:
                pass

    def check_listening_sockets(self):
        print(paint(self.i18n["step_sock"], CLR_CYAN))
        name = self.i18n["test_sock"]
        listeners = []

        if IS_WIN:
            try:
                res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5)
                for line in res.stdout.splitlines():
                    tokens = line.strip().split()
                    if not tokens:
                        continue
                    proto = tokens[0].upper()
                    if proto == "TCP" and len(tokens) >= 4 and tokens[3] == "LISTENING":
                        addr = tokens[1]
                        if addr.startswith("0.0.0.0:") or (not addr.startswith("127.0.0.1:") and not addr.startswith("[::1]")):
                            listeners.append(f"TCP {addr}")
                    elif proto == "UDP" and len(tokens) >= 2:
                        addr = tokens[1]
                        if addr.startswith("0.0.0.0:") or (not addr.startswith("127.0.0.1:") and not addr.startswith("[::1]")):
                            listeners.append(f"UDP {addr}")
            except Exception:
                pass

        elif platform.system() == "Linux":
            def parse_procfs(proto, filename):
                path = f"/proc/net/{filename}"
                if not os.path.isfile(path):
                    return
                try:
                    with open(path, "r") as f:
                        lines = f.readlines()[1:]
                    for row in lines:
                        parts = row.strip().split()
                        if len(parts) < 4:
                            continue
                        # 0A = TCP_LISTEN
                        if proto == "TCP" and parts[3] != "0A":
                            continue
                        hex_ip, hex_port = parts[1].split(":")
                        port = int(hex_port, 16)
                        if len(hex_ip) == 8:
                            octets = [str(int(hex_ip[i:i+2], 16)) for i in (6, 4, 2, 0)]
                            ip_addr = ".".join(octets)
                            if ip_addr == "0.0.0.0":
                                listeners.append(f"{proto} 0.0.0.0:{port}")
                            elif not ip_addr.startswith("127."):
                                listeners.append(f"{proto} {ip_addr}:{port}")
                except Exception:
                    pass

            parse_procfs("TCP", "tcp")
            parse_procfs("UDP", "udp")

        if listeners:
            clean_list = sorted(list(set(listeners)))
            formatted = "\n".join(f"      - {item}" for item in clean_list)
            self.record(name, "WARN", "HIGH", self.i18n["sock_warn"].format(items=formatted), self.i18n["exp_sock_warn"])
        else:
            self.record(name, "PASS", "LOW", self.i18n["sock_pass"], self.i18n["exp_sock_pass"])

    def check_dns(self, probe_domain="corp-perimeter-leak-probe.local"):
        """
        Tests DNS query leakage.
        Resolving to IP = Confirmed Leak (FAIL).
        NXDOMAIN/gaierror = INCONCLUSIVE (domain non-existence does not prove queries were blocked by firewall).
        """
        print(paint(self.i18n["step_dns"], CLR_CYAN))
        name = self.i18n["test_dns"]
        try:
            ip = socket.gethostbyname(probe_domain)
            self.record(name, "FAIL", "HIGH", self.i18n["dns_warn"].format(domain=probe_domain, ip=ip), self.i18n["exp_dns_warn"])
        except socket.gaierror:
            self.record(name, "INCONCLUSIVE", "INFO", self.i18n["dns_inconclusive"].format(domain=probe_domain), self.i18n["exp_dns_inconclusive"])

    def _explain_socket_error(self, code):
        reasons = {
            10035: "WSAEWOULDBLOCK / Packet silently dropped by firewall or gateway timeout",
            10060: "WSAETIMEDOUT / Connection timed out waiting for SYN-ACK",
            10061: "WSAECONNREFUSED / Connection actively refused (TCP RST returned)",
            10065: "WSAEHOSTUNREACH / No route to host or unreachable network segment",
            10051: "WSAENETUNREACH / Network is unreachable",
            11:    "EAGAIN / Operation would block (SYN probe dropped)",
            110:   "ETIMEDOUT / Connection timed out (firewall drop rule)",
            111:   "ECONNREFUSED / Target port closed or rejected by firewall rule (TCP RST)",
            113:   "EHOSTUNREACH / No route to destination host"
        }
        if self.lang == "pl":
            reasons_pl = {
                10035: "WSAEWOULDBLOCK / Pakiet SYN porzucony po cichu (DROP) przez zaporę lub timeout",
                10060: "WSAETIMEDOUT / Przekroczono limit czasu oczekiwania na pakiet SYN-ACK (DROP)",
                10061: "WSAECONNREFUSED / Połączenie odrzucone pakietem TCP RST",
                10065: "WSAEHOSTUNREACH / Brak trasy do hosta docelowego",
                10051: "WSAENETUNREACH / Sieć docelowa jest nieosiągalna",
                11:    "EAGAIN / Operacja zablokowana (pakiet SYN zignorowany przez zaporę DROP)",
                110:   "ETIMEDOUT / Przekroczono limit czasu (reguła DROP na zaporze)",
                111:   "ECONNREFUSED / Port zamknięty lub odrzucony przez regułę REJECT (TCP RST)",
                113:   "EHOSTUNREACH / Brak ścieżki routingu do hosta docelowego"
            }
            return reasons_pl.get(code, f"Errno {code}")
        return reasons.get(code, f"Errno {code}")

    def check_egress(self):
        """
        Differentiates verified DROP (PASS), active connection (FAIL),
        TCP RST rejection (INCONCLUSIVE), and routing errors (INCONCLUSIVE).
        """
        print(paint(self.i18n["step_egress"], CLR_CYAN))
        name = self.i18n["test_egress"]

        for host in self.targets:
            for port in self.ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                try:
                    res = s.connect_ex((host, port))
                    reason = self._explain_socket_error(res)

                    if res == 0:
                        # Direct connection successful -> severe egress policy violation
                        self.record(name, "FAIL", "HIGH", self.i18n["egress_fail"].format(host=host, port=port), self.i18n["exp_egress_fail"])

                    elif res in (10035, 10060, 11, 110):
                        # Timeout / WouldBlock -> Verified silent DROP rule on firewall
                        self.record(name, "PASS", "INFO", self.i18n["egress_pass"].format(host=host, port=port, code=res, reason=reason), self.i18n["exp_egress_pass"])

                    elif res in (10061, 111):
                        # ECONNREFUSED -> Ambiguous: RST might be sent by local REJECT rule OR by external host!
                        self.record(name, "INCONCLUSIVE", "MEDIUM", self.i18n["egress_ambiguous"].format(host=host, port=port, reason=reason), self.i18n["exp_egress_inconclusive"])

                    elif res in (10065, 10051, 113):
                        # Unreachable route / disconnected interface -> cannot verify firewall rule
                        self.record(name, "INCONCLUSIVE", "INFO", self.i18n["egress_unreach"].format(host=host, port=port, reason=reason), self.i18n["exp_egress_inconclusive"])

                    else:
                        self.record(name, "INCONCLUSIVE", "INFO", f"{host}:{port} - {reason}", self.i18n["exp_egress_inconclusive"])

                except socket.gaierror:
                    self.record(name, "INCONCLUSIVE", "INFO", self.i18n["egress_dns_err"].format(host=host), self.i18n["exp_egress_inconclusive"])
                except Exception as err:
                    self.record(name, "INCONCLUSIVE", "INFO", f"{host}:{port} dropped: {err}", self.i18n["exp_egress_inconclusive"])
                finally:
                    s.close()

    def build_report(self, json_path=None):
        findings_json = json.dumps(self.findings, sort_keys=True)
        timestamp_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_fingerprint = f"{platform.node()}:{timestamp_utc}:{findings_json}"
        session_sha256 = hashlib.sha256(session_fingerprint.encode("utf-8")).hexdigest().upper()

        p_count = sum(1 for f in self.findings if f["status"] == "PASS")
        w_count = sum(1 for f in self.findings if f["status"] == "WARN")
        f_count = sum(1 for f in self.findings if f["status"] == "FAIL")
        inc_count = sum(1 for f in self.findings if f["status"] == "INCONCLUSIVE")

        # 1. Korpus danych audytowych
        payload = {
            "tool": f"TABI v{VERSION}",
            "author": "SGVybWFu",
            "locale": self.lang,
            "profile": self.profile,
            "timestamp_utc": timestamp_utc,
            "session_sha256": session_sha256,
            "system_info": {
                "system": platform.system(),
                "release": platform.release(),
                "hostname": platform.node(),
                "arch": platform.machine(),
                "legacy_win": IS_WIN_LEGACY
            },
            "findings": self.findings,
            "summary": {
                "pass": p_count,
                "warn": w_count,
                "fail": f_count,
                "inconclusive": inc_count
            },
            "audit_integrity_seal": {
                "algorithm": "SHA-256",
                "session_sha256": session_sha256,
                "status": "SEALED"
            }
        }

        if json_path:
            try:
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)

                # Tworzymy oficjalny plik sumy kontrolnej .json.sha256 dla weryfikacji w SIEM / sha256sum
                real_file_hash = calculate_sha256(json_path)
                sha_file_path = f"{json_path}.sha256"
                with open(sha_file_path, "w", encoding="utf-8") as f:
                    f.write(f"{real_file_hash}  {os.path.basename(json_path)}\n")
            except Exception as ex:
                print(f"[-] Failed writing JSON log: {ex}")

        return payload

def export_txt_report(report, txt_path, lang="en"):
    i18n = TEXTS.get(lang, TEXTS["en"])
    lines = []
    lines.append("=" * 76)
    lines.append(f"       {i18n['title']} - AUDIT LOG")
    lines.append("=" * 76)
    lines.append(f"Host:         {report['system_info']['hostname']}")
    lines.append(f"OS:           {report['system_info']['system']} {report['system_info']['release']} ({report['system_info']['arch']})")
    lines.append(f"Profile:      {report.get('profile', 'bastion').upper()}")
    lines.append(f"Timestamp:    {report['timestamp_utc']}")
    lines.append(f"Session Seal: {report.get('session_sha256', 'N/A')}")
    lines.append("-" * 76)
    lines.append("")

    p_count = sum(1 for f in report["findings"] if f["status"] == "PASS")
    w_count = sum(1 for f in report["findings"] if f["status"] == "WARN")
    f_count = sum(1 for f in report["findings"] if f["status"] == "FAIL")
    inc_count = sum(1 for f in report["findings"] if f["status"] == "INCONCLUSIVE")

    lines.append("FINDINGS:")
    lines.append("")

    for i, item in enumerate(report["findings"], 1):
        lines.append(f"{i:02d}. [{item['status']:<12}] ({item['severity']:<8}) - {item['test']}")
        for sub in item["details"].split("\n"):
            lines.append(f"    {sub}")
        if item.get("explanation"):
            lines.append(f"    Context: {item['explanation']}")
        lines.append("")

    lines.append("=" * 76)
    lines.append(i18n["stats"].format(p=p_count, w=w_count, f=f_count, inc=inc_count))
    lines.append("-" * 76)
    lines.append(f"🔒 {i18n['integrity_label']}")
    lines.append(f"   {report.get('session_sha256', 'N/A')}")
    lines.append("=" * 76)
    lines.append("")

    raw_text = "\n".join(strip_ansi(line) for line in lines)

    try:
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(raw_text)
    except Exception as ex:
        print(f"[-] Failed writing text log: {ex}")

    # Tworzymy oficjalny plik sumy kontrolnej .txt.sha256 (standard sha256sum / CertUtil)
    try:
        real_file_hash = calculate_sha256(txt_path)
        sha_file_path = f"{txt_path}.sha256"
        with open(sha_file_path, "w", encoding="utf-8") as f:
            f.write(f"{real_file_hash}  {os.path.basename(txt_path)}\n")
    except Exception:
        pass


def render_cli_summary(report, lang="en", txt_path=None, json_path=None, txt_sha=None, json_sha=None):
    i18n = TEXTS.get(lang, TEXTS["en"])
    print(f"\n{CLR_CYAN}{'=' * 76}{CLR_RESET}")
    print(f"{CLR_BOLD}           {i18n['summary_title']}{CLR_RESET}")
    print(f"{CLR_CYAN}{'=' * 76}{CLR_RESET}")
    print(f"{CLR_DIM}Host:{CLR_RESET} {CLR_BOLD}{report['system_info']['hostname']}{CLR_RESET} | {CLR_DIM}OS:{CLR_RESET} {report['system_info']['system']} | {CLR_DIM}Profile:{CLR_RESET} {CLR_CYAN}{report.get('profile', 'bastion').upper()}{CLR_RESET}")
    print(f"{CLR_DIM}Time:{CLR_RESET} {report['timestamp_utc']}\n")

    for i, item in enumerate(report["findings"], 1):
        st = item["status"]
        if st == "PASS":
            c_status = CLR_GREEN
        elif st == "WARN":
            c_status = CLR_WARN
        elif st == "FAIL":
            c_status = CLR_RED
        else:
            c_status = CLR_MAGENTA
        tag_status = f"{c_status}{CLR_BOLD}[{st:<12}]{CLR_RESET}"

        sev = item["severity"]
        c_sev = CLR_RED if sev in ("CRITICAL", "HIGH") else (CLR_WARN if sev == "MEDIUM" else CLR_CYAN)
        tag_sev = f"{c_sev}({sev}){CLR_RESET}"

        print(f"{CLR_BOLD}{i:02d}.{CLR_RESET} {tag_status} {tag_sev:<16} - {CLR_BOLD}{item['test']}{CLR_RESET}")
        for sub in item["details"].split("\n"):
            print(f"    {sub}")
        if item.get("explanation"):
            print(f"    {CLR_DIM}💡 {i18n['sec_label']}{CLR_RESET} {CLR_CYAN}{item['explanation']}{CLR_RESET}")
        print()

    p_count = sum(1 for f in report["findings"] if f["status"] == "PASS")
    w_count = sum(1 for f in report["findings"] if f["status"] == "WARN")
    f_count = sum(1 for f in report["findings"] if f["status"] == "FAIL")
    inc_count = sum(1 for f in report["findings"] if f["status"] == "INCONCLUSIVE")

    print(f"{CLR_CYAN}{'-' * 76}{CLR_RESET}")
    print(
        f"{CLR_BOLD}SUMMARY:{CLR_RESET} "
        f"{paint(f'PASS: {p_count}', CLR_GREEN)} | "
        f"{paint(f'WARN: {w_count}', CLR_WARN)} | "
        f"{paint(f'FAIL: {f_count}', CLR_RED)} | "
        f"{paint(f'INCONCLUSIVE: {inc_count}', CLR_MAGENTA)}"
    )
    print(f"{CLR_CYAN}{'-' * 76}{CLR_RESET}")

    # Cryptographic Audit Integrity Seals (Always calculated & printed in the summary)
    session_hash = report.get("session_sha256", "N/A")
    print(f"{CLR_BOLD}🔒 {i18n['integrity_label']}{CLR_RESET}")
    print(f"   {paint(session_hash, CLR_CYAN)}")

    if txt_path and txt_sha:
        lbl = "📄 Log tekstowy (TXT):" if lang == "pl" else "📄 Text Report (TXT):"
        print(f"{CLR_DIM}{lbl}{CLR_RESET} {txt_path}\n   SHA-256: {paint(txt_sha, CLR_GREEN)}")

    if json_path and json_sha:
        lbl = "📦 Raport SIEM (JSON):" if lang == "pl" else "📦 SIEM Report (JSON):"
        print(f"{CLR_DIM}{lbl}{CLR_RESET} {json_path}\n   SHA-256: {paint(json_sha, CLR_GREEN)}")

    print(f"{CLR_CYAN}{'=' * 76}{CLR_RESET}\n")

def run_interactive_wizard():
    print("-" * 70)
    print("        TABI - INTERACTIVE SETUP / KREATOR KONFIGURACJI")
    print("-" * 70)

    print("[1] Select Language / Wybierz język:")
    print("    [1] English (Default)")
    print("    [2] Polski")
    choice = input("    Choice / Wybór [1/2, default 1]: ").strip()
    selected_lang = "pl" if choice == "2" else "en"

    if selected_lang == "pl":
        print("\n[2] Wybierz profil polityki:")
        print("    [1] Bastion (Domyślny - toleruje 1 fizyczną kartę)")
        print("    [2] Air-gap (Ścisła izolacja - 0 kart zewnętrznych)")
        p_choice = input("    Wybór [1/2, domyślnie 1]: ").strip()
    else:
        print("\n[2] Select Policy Profile:")
        print("    [1] Bastion (Default - single primary NIC tolerated)")
        print("    [2] Strict Air-gap (Zero external NIC tolerance)")
        p_choice = input("    Choice [1/2, default 1]: ").strip()
    selected_profile = "airgap" if p_choice == "2" else "bastion"

    if selected_lang == "pl":
        print("\n[3] Zakres inspekcji:")
        print("    [1] Pełny audyt (Lokalny + testy wyjścia Egress/DNS)")
        print("    [2] Szybki / Pasywny (--quick, tylko audyt lokalnego hosta)")
        m_choice = input("    Wybór [1/2, domyślnie 1]: ").strip()
    else:
        print("\n[3] Execution Scope:")
        print("    [1] Full Audit (Local host + outbound probes)")
        print("    [2] Quick / Stealth (--quick, passive local host only)")
        m_choice = input("    Choice [1/2, default 1]: ").strip()
    selected_quick = (m_choice == "2")

    prompt = (
        "\n🚀 Naciśnij [ENTER], aby rozpocząć audyt (lub 'q' aby wyjść): "
        if selected_lang == "pl" else
        "\n🚀 Press [ENTER] to start audit (or 'q' to abort): "
    )
    ans = input(prompt).strip().lower()
    if ans in ("q", "quit", "exit"):
        sys.exit(0)

    print("\n" + "=" * 70 + "\n")
    return selected_lang, selected_profile, selected_quick

def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="tabi",
        description=f"TABI: Tactical Air-gap & Bastion Inspector (v{VERSION}) - Enclave Isolation & Boundary Hardening Auditor.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--lang", "-l", choices=["en", "pl"], default="en", help="Interface & report language ('en' or 'pl').")
    parser.add_argument("--profile", choices=["bastion", "airgap"], default="bastion", help="Policy profile (default: bastion).")
    parser.add_argument("--quick", "-q", action="store_true", help="Stealth: audit local host only without outbound packets.")
    parser.add_argument("--targets", nargs="+", default=["1.1.1.1", "8.8.8.8", "192.168.1.1"], help="Egress probe destination IPs.")
    parser.add_argument("--ports", nargs="+", type=int, default=[53, 80, 443, 22, 123], help="TCP ports for outbound probes.")
    parser.add_argument("--timeout", type=float, default=1.5, help="Socket timeout in seconds (default: 1.5).")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output path for JSON report.")
    parser.add_argument("--txt-output", "-t", type=str, default=None, help="Output path for human-readable TXT log.")
    parser.add_argument("--dns-check", type=str, default="corp-perimeter-leak-probe.local", help="Probe domain for DNS leak test.")
    parser.add_argument("--version", "-v", action="version", version=f"TABI v{VERSION}")
    return parser


def main():
    parser = parse_arguments()
    is_interactive = (len(sys.argv) == 1)

    if is_interactive:
        print(BANNER)
        print("=" * 70)
        print(f"     TABI - Tactical Air-gap & Bastion Inspector (v{VERSION})")
        print("     Enclave Isolation & Boundary Hardening Auditor")
        print("=" * 70 + "\n")

        lang, profile, quick = run_interactive_wizard()
        targets = ["1.1.1.1", "8.8.8.8", "192.168.1.1"]
        ports = [53, 80, 443, 22, 123]
        timeout = 1.5
        dns_target = "corp-perimeter-leak-probe.local"
        json_out = None
        txt_out = None
    else:
        args = parser.parse_args()
        lang = args.lang
        profile = args.profile
        quick = args.quick
        targets = args.targets
        ports = args.ports
        timeout = args.timeout
        dns_target = args.dns_check
        json_out = args.output
        txt_out = args.txt_output

        print(BANNER)
        print("=" * 70)
        print(f"     {TEXTS[lang]['title']}")
        print(f"     {TEXTS[lang]['sub']}")
        print("=" * 70 + "\n")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    final_json = json_out if json_out else f"tabi_report_{timestamp}.json"
    final_txt = txt_out if txt_out else f"tabi_report_{timestamp}.txt"

    auditor = TabiAuditor(targets=targets, ports=ports, timeout=timeout, lang=lang, profile=profile)

    # Local host boundary & hardening checks
    auditor.check_interfaces()
    auditor.check_rf()
    auditor.check_serial_ports()
    auditor.check_system_hardening()
    auditor.check_listening_sockets()

    # Outbound probes
    if quick:
        print(TEXTS[lang]["step_skip"])
    else:
        auditor.check_dns(probe_domain=dns_target)
        auditor.check_egress()

    # Always generate and cryptographically seal JSON and TXT reports
    report = auditor.build_report(json_path=final_json)
    json_sha = report.get("artifact_sha256", calculate_sha256(final_json))

    export_txt_report(report, txt_path=final_txt, lang=lang)
    txt_sha = calculate_sha256(final_txt)

    # Render summary with cryptographic seals visible right above the exit prompt
    render_cli_summary(
        report,
        lang=lang,
        txt_path=final_txt,
        json_path=final_json,
        txt_sha=txt_sha,
        json_sha=json_sha
    )

    cmd = "type" if IS_WIN else "cat"
    print(f"{TEXTS[lang]['hint'].format(cmd=cmd, path=final_txt)}\n")

    # Keep terminal open if double-clicked / run interactively
    if is_interactive:
        try:
            input(TEXTS[lang]["exit_prompt"])
        except (KeyboardInterrupt, EOFError):
            pass


if __name__ == "__main__":
    main()