#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TABI - Tactical Air-gap & Bastion Inspector (v1.0)
Author: SGVybWFu
GitHub: https://github.com/SGVybWFu/tabi

Audits network boundaries, RF hardware, removable media locks,
serial/COM out-of-band bridges, listening sockets, and egress filtering.
Zero external dependencies. Compatible with Linux & Windows (7/8/10/11).
"""

import argparse
import datetime
import json
import os
import platform
import re
import socket
import subprocess
import sys

VERSION = "1.0"
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
CLR_RESET = "\033[0m"
CLR_BOLD  = "\033[1m"
CLR_DIM   = "\033[2m"
CLR_RED   = "\033[91m"
CLR_GREEN = "\033[92m"
CLR_WARN  = "\033[93m"
CLR_CYAN  = "\033[96m"

def paint(text: str, color_code: str) -> str:
    # Strip ANSI escape codes on legacy Windows 7 consoles to avoid rendering raw artifacts
    if IS_WIN_LEGACY:
        return text
    return f"{color_code}{text}{CLR_RESET}"

def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)

BANNER = r"""
               ..=*+.
              .*..:.+.===---::+#=::
              :#..:.:+..... .-.-:.+.
              .#. ....      .-... =.
              .#+:.           .:*.#.
              =..               .=*
            .+=    ..#+.   -#:.   :..
           ..%         .  ...     .@.
        .--..#:        :@@%-      .%.
      .::    .=.   .@...:=...#..  .@.
    .*..   .-:..    +@%+%@%#=.   .%.
   .*:   .:+. .:    .-@*...=   .-+:
  .--.  .-...  .:=.   .:*#*...-..:*
  .:=. .=. :..=   :*#=-..-+%*:...*.
  ..-.=:  .-..=+       ......   .*.
   .-..   .=...#.              .%*:
     =    ......%:             *:*-
    .%          .*=           +-.*:
    -*     .     .:=        .*...*.
    ++     =       ..       .....#.
    ++     +.                   .*.
    -*     -%                   .=.
    .+     .@:        ...      .#-
    .*      :*       .+-       .@.
    .%     :.%.      =-.       --
     +.  .:+.#.     .:--.      *.
     -#  .%..:    .%...-..    .*.
     .@. :- .#    +-  .%=:    ==.
     .#- =- .%   .%@. --=-.   +:
      .- *: .%.  .#@: +.=-.   +.
      :-.+: .#.  -#@..%.=+.  .*.
      +-... .#.  ++@.:@.=#   .+
     .@:.%  .#.  +.= .%.-%. .+=
     -#.=+. .#-  =.@..%..%. .%.
    .# .=.  .#=  +.@: =-.%. .#.
    =..-#.   -+  +.@. .. %. .%.
    -=.:+    .+  +:@-.:+--. .:.
             .:  +*.=:-=:.. .#:..
             =-  =#     .%: .*=..
            .%.  :.     .%.  :+
            .*.: :*..    .:.  +:.
            .:=#.=-..     +:.=.*-.
               ..         .=-+:-*.
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
        "test_egress": "Egress Filtering",
        "test_dns": "DNS Resolution Isolation",
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
        "usb_win_warn": "USB mass storage driver is enabled (USBSTOR Start={val}). Risk of physical exfil or BadUSB.",
        "usb_lin_warn": "Removable storage kernel modules currently loaded: {drivers}.",
        "usb_lin_pass": "No USB mass storage kernel modules loaded.",
        "exp_usb_warn": "Active USB drivers allow data exfiltration and weaponized hardware injection.",
        "exp_usb_pass": "Removable storage disabled at driver level, mitigating physical USB attacks.",
        "sock_warn": "Services bound to wildcard or external IPs:\n{items}",
        "sock_pass": "No unauthorized listeners bound to wildcard 0.0.0.0 addresses.",
        "exp_sock_warn": "Wildcard 0.0.0.0 listeners expose services on all interfaces, facilitating lateral movement.",
        "exp_sock_pass": "No unhardened ingress listeners exposed to external networks.",
        "egress_fail": "Unrestricted outbound connection established to {host}:{port}. Egress policy violated!",
        "egress_pass": "Connection to {host}:{port} blocked (code: {code} - {reason}). Egress boundary intact.",
        "egress_dns_err": "Target {host} could not be resolved (DNS isolation intact).",
        "egress_err": "Connection to {host}:{port} dropped: {err}",
        "exp_egress_fail": "Permissive egress allows command-and-control beacons, reverse shells, or data exfiltration.",
        "exp_egress_pass": "Firewall or security group successfully blocks outbound traffic (SYN packets dropped or rejected).",
        "dns_warn": "Probe domain '{domain}' resolved to {ip}. External DNS leak detected!",
        "dns_pass": "Probe domain '{domain}' did not resolve (expected inside isolated enclaves).",
        "exp_dns_warn": "Resolution confirms internal queries traverse to public/untrusted resolvers.",
        "exp_dns_pass": "Resolver boundary intact; external lookups fail as designed.",
        "summary_title": "AUDIT RESULTS SUMMARY",
        "summary_json": "[+] JSON report saved to {path}",
        "summary_txt": "[+] Text log saved to {path}",
        "stats": "TOTALS: PASS: {p} | WARN: {w} | FAIL: {f}",
        "hint": "💡 Review audit log with: {cmd} {path}",
        "sec_label": "Security Context:",
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
        "step_dns": "[*] Weryfikacja wycieków zapytań DNS poza obwód...",
        "step_egress": "[*] Testowanie filtracji ruchu wyjściowego (Egress)...",
        "step_skip": "[*] Tryb szybki: pomijanie aktywnych sond sieciowych.",
        "test_mh": "Audyt multi-homingu (wielu kart)",
        "test_rf": "Izolacja interfejsów radiowych (RF/Wi-Fi)",
        "test_serial": "Porty szeregowe i mostki sprzętowe (RS-232/UART/COM)",
        "test_fwd": "Trasowanie pakietów w jądrze (IP Forwarding)",
        "test_usb": "Blokada pamięci masowych USB",
        "test_sock": "Ekspozycja portów nasłuchujących (Ingress)",
        "test_egress": "Filtracja ruchu wychodzącego (Egress)",
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
        "usb_win_warn": "Obsługa pamięci USB włączona (USBSTOR Start={val}). Aktywny wektor fizyczny.",
        "usb_lin_warn": "Załadowano moduły pamięci masowej USB ({drivers}). Polityka nośników nieutwardzona.",
        "usb_lin_pass": "Sterowniki pamięci masowej USB nie są załadowane w jądrze.",
        "exp_usb_warn": "Aktywne porty USB umożliwiają kradzież danych oraz ataki sprzętowe (BadUSB).",
        "exp_usb_pass": "Porty pamięci USB zablokowane na poziomie sterownika (ochrona przed nośnikami fizycznymi).",
        "sock_warn": "Usługi nasłuchujące na adresach 0.0.0.0 lub zewnętrznych:\n{items}",
        "sock_pass": "Brak nieautoryzowanych usług nasłuchujących na interfejsach 0.0.0.0.",
        "exp_sock_warn": "Gniazda nasłuchujące na 0.0.0.0 są dostępne z każdego interfejsu, ułatwiając ruch boczny.",
        "exp_sock_pass": "Brak niebezpiecznych gniazd sieciowych wystawionych na ruch z zewnątrz.",
        "egress_fail": "Nawiązano nieautoryzowane połączenie wyjściowe z {host}:{port}. Naruszenie reguł zapory!",
        "egress_pass": "Połączenie z {host}:{port} zostało zablokowane (kod: {code} - {reason}). Szczelność obwodu zachowana.",
        "egress_dns_err": "Cel {host} nie został rozwiązany (izolacja DNS działa prawidłowo).",
        "egress_err": "Połączenie z {host}:{port} odrzucone: {err}",
        "exp_egress_fail": "Otwarte wyjście pozwala na nawiązanie powłoki zwrotnej (reverse shell) i łączność z C2.",
        "exp_egress_pass": "Zapora sieciowa prawidłowo odrzuca ruch wychodzący (pakiety SYN są cicho porzucane lub blokowane).",
        "dns_warn": "Sonda DNS rozwiązała domenę '{domain}' na adres {ip}. Wyciek zapytań poza sieć!",
        "dns_pass": "Domena testowa '{domain}' nie została rozwiązana (zgodnie z założeniem izolacji).",
        "exp_dns_warn": "Pomyślna rezolucja dowodzi, że zapytania DNS wyciekają do publicznych resolverów.",
        "exp_dns_pass": "Brak wycieków; zapytania DNS nie opuszczają zamkniętej strefy.",
        "summary_title": "PODSUMOWANIE AUDYTU BEZPIECZEŃSTWA",
        "summary_json": "[+] Zapisano raport JSON: {path}",
        "summary_txt": "[+] Zapisano raport tekstowy: {path}",
        "stats": "WYNIKI: PASS: {p} | WARN: {w} | FAIL: {f}",
        "hint": "💡 Review audit log with: {cmd} {path}",
        "sec_label": "Znaczenie bezpieczeństwa:",
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
            # Query Windows Registry for active COM ports mapping (compatible with Win7 through Win11)
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
            # Check sysfs for active USB-to-serial or ACM modem bridges
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
        print(paint(self.i18n["step_dns"], CLR_CYAN))
        name = self.i18n["test_dns"]
        try:
            ip = socket.gethostbyname(probe_domain)
            self.record(name, "WARN", "MEDIUM", self.i18n["dns_warn"].format(domain=probe_domain, ip=ip), self.i18n["exp_dns_warn"])
        except socket.gaierror:
            self.record(name, "PASS", "INFO", self.i18n["dns_pass"].format(domain=probe_domain), self.i18n["exp_dns_pass"])

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
                10060: "WSAETIMEDOUT / Przekroczono limit czasu oczekiwania na pakiet SYN-ACK",
                10061: "WSAECONNREFUSED / Połączenie aktywnie odrzucone (zwrócono TCP RST)",
                10065: "WSAEHOSTUNREACH / Brak trasy do hosta lub segment sieci niedostępny",
                10051: "WSAENETUNREACH / Sieć docelowa jest nieosiągalna",
                11:    "EAGAIN / Operacja zablokowana (pakiet SYN zignorowany przez zaporę)",
                110:   "ETIMEDOUT / Przekroczono limit czasu (reguła DROP na zaporze)",
                111:   "ECONNREFUSED / Port zamknięty lub odrzucony przez regułę firewall (TCP RST)",
                113:   "EHOSTUNREACH / Brak ścieżki routingu do hosta docelowego"
            }
            return reasons_pl.get(code, f"Errno {code}")
        return reasons.get(code, f"Errno {code}")

    def check_egress(self):
        print(paint(self.i18n["step_egress"], CLR_CYAN))
        name = self.i18n["test_egress"]

        for host in self.targets:
            for port in self.ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                try:
                    res = s.connect_ex((host, port))
                    if res == 0:
                        self.record(name, "FAIL", "HIGH", self.i18n["egress_fail"].format(host=host, port=port), self.i18n["exp_egress_fail"])
                    else:
                        reason = self._explain_socket_error(res)
                        self.record(name, "PASS", "INFO", self.i18n["egress_pass"].format(host=host, port=port, code=res, reason=reason), self.i18n["exp_egress_pass"])
                except socket.gaierror:
                    self.record(name, "PASS", "INFO", self.i18n["egress_dns_err"].format(host=host), self.i18n["exp_egress_pass"])
                except Exception as err:
                    self.record(name, "PASS", "INFO", self.i18n["egress_err"].format(host=host, port=port, err=err), self.i18n["exp_egress_pass"])
                finally:
                    s.close()

    def build_report(self, json_path=None):
        payload = {
            "tool": f"TABI v{VERSION}",
            "author": "SGVybWFu",
            "locale": self.lang,
            "profile": self.profile,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "system_info": {
                "system": platform.system(),
                "release": platform.release(),
                "hostname": platform.node(),
                "arch": platform.machine(),
                "legacy_win": IS_WIN_LEGACY
            },
            "findings": self.findings
        }
        if json_path:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            print(paint(self.i18n["summary_json"].format(path=json_path), CLR_GREEN))
        return payload

def export_txt_report(report, txt_path, lang="en"):
    i18n = TEXTS.get(lang, TEXTS["en"])
    lines = []
    lines.append("=" * 76)
    lines.append(f"       {i18n['title']} - AUDIT LOG")
    lines.append("=" * 76)
    lines.append(f"Host:      {report['system_info']['hostname']}")
    lines.append(f"OS:        {report['system_info']['system']} {report['system_info']['release']} ({report['system_info']['arch']})")
    lines.append(f"Profile:   {report.get('profile', 'bastion').upper()}")
    lines.append(f"Timestamp: {report['timestamp_utc']}")
    lines.append("-" * 76)
    lines.append("")

    p_count = sum(1 for f in report["findings"] if f["status"] == "PASS")
    w_count = sum(1 for f in report["findings"] if f["status"] == "WARN")
    f_count = sum(1 for f in report["findings"] if f["status"] == "FAIL")

    lines.append("FINDINGS:")
    lines.append("")

    for i, item in enumerate(report["findings"], 1):
        lines.append(f"{i:02d}. [{item['status']:<4}] ({item['severity']:<8}) - {item['test']}")
        for sub in item["details"].split("\n"):
            lines.append(f"    {sub}")
        if item.get("explanation"):
            lines.append(f"    Context: {item['explanation']}")
        lines.append("")

    lines.append("=" * 76)
    lines.append(i18n["stats"].format(p=p_count, w=w_count, f=f_count))
    lines.append("=" * 76)

    try:
        raw_text = "\n".join(strip_ansi(line) for line in lines)
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(raw_text + "\n")
        print(paint(i18n["summary_txt"].format(path=txt_path), CLR_GREEN))
    except Exception as ex:
        print(f"[-] Failed writing text log: {ex}")


def render_cli_summary(report, lang="en"):
    i18n = TEXTS.get(lang, TEXTS["en"])
    print(f"\n{CLR_CYAN}{'=' * 76}{CLR_RESET}")
    print(f"{CLR_BOLD}           {i18n['summary_title']}{CLR_RESET}")
    print(f"{CLR_CYAN}{'=' * 76}{CLR_RESET}")
    print(f"{CLR_DIM}Host:{CLR_RESET} {CLR_BOLD}{report['system_info']['hostname']}{CLR_RESET} | {CLR_DIM}OS:{CLR_RESET} {report['system_info']['system']} | {CLR_DIM}Profile:{CLR_RESET} {CLR_CYAN}{report.get('profile', 'bastion').upper()}{CLR_RESET}")
    print(f"{CLR_DIM}Time:{CLR_RESET} {report['timestamp_utc']}\n")

    for i, item in enumerate(report["findings"], 1):
        st = item["status"]
        c_status = CLR_GREEN if st == "PASS" else (CLR_WARN if st == "WARN" else CLR_RED)
        tag_status = f"{c_status}{CLR_BOLD}[{st}]{CLR_RESET}"

        sev = item["severity"]
        c_sev = CLR_RED if sev in ("CRITICAL", "HIGH") else (CLR_WARN if sev == "MEDIUM" else CLR_CYAN)
        tag_sev = f"{c_sev}({sev}){CLR_RESET}"

        print(f"{CLR_BOLD}{i:02d}.{CLR_RESET} {tag_status} {tag_sev:<18} - {CLR_BOLD}{item['test']}{CLR_RESET}")
        for sub in item["details"].split("\n"):
            print(f"    {sub}")
        if item.get("explanation"):
            print(f"    {CLR_DIM}💡 {i18n['sec_label']}{CLR_RESET} {CLR_CYAN}{item['explanation']}{CLR_RESET}")
        print()

    p_count = sum(1 for f in report["findings"] if f["status"] == "PASS")
    w_count = sum(1 for f in report["findings"] if f["status"] == "WARN")
    f_count = sum(1 for f in report["findings"] if f["status"] == "FAIL")

    print(f"{CLR_CYAN}{'-' * 76}{CLR_RESET}")
    print(f"{CLR_BOLD}SUMMARY:{CLR_RESET} {paint(f'PASS: {p_count}', CLR_GREEN)} | {paint(f'WARN: {w_count}', CLR_WARN)} | {paint(f'FAIL: {f_count}', CLR_RED)}")
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
        description="TABI: Tactical Air-gap & Bastion Inspector (v1.0) - Enclave Isolation & Boundary Hardening Auditor.",
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

    report = auditor.build_report(json_path=final_json)
    if final_txt:
        export_txt_report(report, txt_path=final_txt, lang=lang)
    render_cli_summary(report, lang=lang)

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
