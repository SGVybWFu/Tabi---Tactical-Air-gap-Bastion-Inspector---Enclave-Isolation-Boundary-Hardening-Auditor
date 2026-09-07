# **TABI — Taktyczny Inspektor Bastionów i Stref Air-gap (v1.0)**

> **Audytor Izolacji Enklawy i Szczelności Reguł Brzegowych**

> *Zero Zależności Zewnętrznych (Zero-Dependency) | Kompatybilny z Windows 7–11 oraz Linux | Sektor Obronny i Środowiska Podwyższonego Rygoru*

## **🎯 Środowiska Docelowe i Kontekst Operacyjny**

TABI został zaprojektowany do weryfikacji stacji roboczych i serwerów w środowiskach o najwyższym reżimie bezpieczeństwa teleinformatycznego, gdzie zgodność z polityką musi być badana bezpośrednio na poziomie jądra systemu oraz warstwy sprzętowej:

* **Sektor Obronny i Przemysł Zbrojeniowy:** Stacje dostępowe, laboratoria badawczo-rozwojowe oraz terminale przetwarzające dane wrażliwe w strefach zamkniętych.  
* **Taktyczne Centra Operacyjne (TOC) i Łączność Radiowa:** Weryfikacja stacji polowych i laptopów dowodzenia współpracujących z taktycznymi systemami łączności (np. Falcon). Złącza DATA (porty szeregowe RS-232 / MIL-STD-188-114 / konwertery UART) stanowią fizyczny kanał transmisji radiowej poza pasmem (OOB), który w strefie Air-gap może posłużyć do nieautoryzowanego ominięcia zapory sieciowej.  
* **Infrastruktura Krytyczna (CNI / OT / SCADA):** Stacje inżynierskie (EWS), panele HMI oraz bastiony technologiczne odseparowane fizycznie od korporacyjnej sieci IT.  
* **Stacje Robocze o Podwyższonym Rygorze (PAW / Tier-0 Bastions):** Weryfikacja zgodności konfiguracji stacji z rygorystycznymi wytycznymi hardeningu (m.in. standardy **DISA STIG** oraz **CIS Benchmarks** w zakresie blokady nośników wymiennych, eliminacji kart bezprzewodowych oraz szczelności zapory sieciowej).  
* **Terminal Polowy i Sprzęt Klasy Rugged (Windows 7 SP1 do Windows 11):** Kompatybilność wsteczna z laptopami pancernymi (np. Panasonic Toughbook CF-19 / CF-31 z systemem Windows 7 Embedded), często spotykanymi w polowych punktach łączności i wozach dowodzenia.

## **📋 Wprowadzenie**

**TABI** to dwuplatformowe (Linux i Windows 7–11), całkowicie niezależne od zewnętrznych bibliotek narzędzie audytorskie w języku Python. Służy do automatycznej weryfikacji, czy badany system spełnia rygorystyczne wymogi fizycznej i logicznej izolacji od sieci obcych.

W izolowanych środowiskach operacyjnych drobne błędy konfiguracyjne często niweczą bezpieczeństwo całego obwodu:

* Aktywne adaptery Wi-Fi/Bluetooth tworzą bezprzewodowy pomost omijający zaporę fizyczną.  
* Aktywne porty szeregowe (COM/RS-232) podłączone do radiostacji lub modemów stanowią ukryte kanały transmisji poza pasmem (OOB).  
* Obecność wielu kart sieciowych naraz (multi-homing) grozi mostkowaniem ruchu między strefami.  
* Włączone trasowanie pakietów w jądrze (IP Forwarding) zamienia stację w nieautoryzowany router tranzytowy.  
* Zbyt pobłażliwe reguły zapory sieciowej umożliwiają nawiązanie połączeń zwrotnych (C2 / reverse shell) i kradzież danych.  
* Otwarte gniazda nasłuchujące na adresach 0.0.0.0 umożliwiają wrogim węzłom ruch boczny (*lateral movement*).  
* Włączona obsługa nośników pamięci masowej USB otwiera wektor ataku fizycznego (BadUSB, exfiltracja danych).

TABI automatyzuje wykrywanie powyższych podatności bez potrzeby instalowania jakichkolwiek pakietów, kompilatorów czy dostępu do Internetu.

## **✨ Główne Możliwości**

* **Rygorystyczna Architektura Zero-Dependency:** Działa na czystej instalacji Pythona 3 bez instalowania bibliotek zewnętrznych (pip install). Niezbędne w odciętych środowiskach.  
* **Pełna Kompatybilność Linux oraz Windows (7 / 8 / 10 / 11):** Autonomiczna logika dla systemów **Linux** (analiza /sys, /proc, procfs) oraz **Windows** (rejestr systemowy winreg, trójwarstwowa detekcja Wi-Fi NDIS/WMI/netsh z obsługą PowerShell 2.0 na Win7, natywne kody błędów Winsock).  
* **Inspekcja Urządzeń Radiowych (RF):** Wykrywa aktywne interfejsy Wi-Fi i nadajniki Bluetooth mogące posłużyć do ominięcia strefy Air-gap.  
* **Audyt Portów Szeregowych i Mostków Sprzętowych:** Identyfikuje aktywne łącza RS-232, UART i adaptery USB-Serial stanowiące potencjalny wektor wyjścia poza pasmem (OOB).  
* **Weryfikacja Blokady Nośników USB:** Bada stan sterowników pamięci masowej USB (klucz rejestru USBSTOR na Windowsie, moduły usb\_storage/uas na Linuksie).  
* **Audyt Usług Nasłuchujących i Multi-Homingu:** Sprawdza obecność niebezpiecznych usług powiązanych z 0.0.0.0 oraz bada ryzyko mostkowania ruchu między podsieciami.  
* **Aktywne Badanie Reguł Wyjścia (Egress) i Wycieków DNS:** Sprawdza skuteczność blokowania ruchu wyjściowego przez zaporę sieciową oraz wykrywa nieszczelności zapytań DNS.  
* **Interaktywny Kreator Konfiguracji (Wizard):** Intuicyjne menu startowe pozwalające na natychmiastowe uruchomienie testu bez znajomości flag konsolowych.  
* **Dwujęzyczne Raportowanie:** Pełna obsługa języka **angielskiego** oraz **polskiego** w konsoli i w plikach wynikowych.  
* **Podwójny Format Raportów:** Automatyczny zapis ustrukturyzowanego pliku JSON (do analizy w SIEM) oraz przejrzystego pliku tekstowego z unikalnym znacznikiem czasu (tabi\_report\_YYYY-MM-DD\_HH-MM-SS.txt).

## **🔍 Zakres Inspekcji Technicznej**

| Badany Wektor | Implementacja Linux | Implementacja Windows (Win7 \- Win11) | Znaczenie Bezpieczeństwa |
| :---- | :---- | :---- | :---- |
| **Multi-Homing** | getaddrinfo \+ analiza tablicy routingu | Analiza tablicy routingu i enumeracja adresów IP | Zapobiega mostkowaniu ruchu między odrębnymi strefami sieci |
| **Izolacja Radiowa (RF)** | Flagi wireless w /sys/class/net i /sys/class/rfkill | NDIS (Get-NetAdapter), WMI (Win32\_NetworkAdapter dla Win7), netsh | Eliminuje bezprzewodowe tylne furtki poza kontrolą zapory sieciowej |
| **Mostki Szeregowe (COM)** | /sys/bus/usb-serial, /dev/serial/by-id, /dev/ttyACM\* | Klucz rejestru HARDWARE\\DEVICEMAP\\SERIALCOMM | Wykrywa fizyczne kanały transmisji szeregowej/radiowej omijające zaporę sieciową |
| **Trasowanie w Jądrze** | Flaga /proc/sys/net/ipv4/ip\_forward | Wartość IPEnableRouter w rejestrze Tcpip\\Parameters | Uniemożliwia stacji pełnienie roli routera tranzytowego |
| **Blokada Pamięci USB** | Weryfikacja modułów jądra (usb\_storage, uas w /proc/modules) | Wartość Start w kluczu Services\\USBSTOR | Ochrona przed kradzieżą danych i atakami sprzętowymi (BadUSB) |
| **Porty Nasłuchujące** | Parsowanie struktur /proc/net/tcp oraz /proc/net/udp | Analiza gniazd nasłuchujących z netstat \-ano | Blokuje możliwość nieautoryzowanego ruchu bocznego |
| **Izolacja Zapytań DNS** | Próba rezolucji testowej domeny wewnętrznej | Próba rezolucji testowej domeny wewnętrznej | Potwierdza, że wewnętrzne zapytania nie wyciekają do obcych resolverów |
| **Filtracja Ruchu Wyjściowego** | Próby TCP SYN z interpretacją błędów gniazd | Próby TCP SYN z analizą kodów Winsock (10035, etc.) | Weryfikuje szczelność reguł DROP na zaporze sieciowej |

## **🚀 Uruchomienie i Użycie**

### **Wymagania**

* Zainstalowany Python 3.7+ (dla Windows 7 zalecany Python 3.8.10 lub gotowy plik binarny TABI Tactical Air-gap & Bastion Inspector.exe).  
* Uprawnienia administratora w celu pełnej inspekcji rejestru i podsystemów sprzętowych.

### **Uruchomienie w Trybie Interaktywnym**

Uruchomienie skryptu bez żadnych parametrów uruchamia interaktywny kreator konfiguracji:

\# Na systemie Linux  
python3 tabi.py

\# Na systemie Windows (PowerShell lub CMD)  
py tabi.py  
\# Lub jeśli używasz skompilowanego pliku:  
.\\TABI Tactical Air-gap & Bastion Inspector.exe

Kreator pozwoli w prosty sposób wybrać język interfejsu (angielski/polski), profil polityki (Bastion lub ścisły Air-gap) oraz tryb skanowania.

### **Tryb wsadowy / Flagi konsolowe (Headless)**

Narzędzie obsługuje pełen zestaw argumentów wiersza poleceń do zastosowań automatycznych i skryptowych:

\# Szybki, cichy audyt wyłącznie lokalnego hosta (bez wysyłania pakietów w sieć):  
py tabi.py \--quick

\# Audyt w języku polskim z profilem ścisłej izolacji (Air-gap):  
python3 tabi.py \--profile airgap \--lang pl

\# Własne cele i porty do testu wyjścia wraz ze wskazaniem plików raportów:  
py tabi.py \--targets 10.0.0.1 192.168.1.1 \--ports 80 443 \-o wynik.json \-t wynik.txt

## **📄 Licencja**

Projekt jest dystrybuowany na warunkach otwartoźródłowej licencji **MIT** — szczegóły w pliku [LICENSE](http://docs.google.com/LICENSE).