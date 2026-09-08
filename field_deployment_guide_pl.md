# **TABI — Wdrażanie w Środowiskach Polowych i Odciętych (Air-Gap Deployment Guide v1.1)**

## **1\. Problem Operacyjny: Brak Pythona, Starsze Systemy (Windows 7 / Toughbook) i Odcięcie od Sieci**

W warunkach polowych (np. taktyczne punkty dowodzenia TOC, polowe stacje EWS, stacje kryptograficzne, laboratoria badawcze) operatorzy często dysponują terminalami:

* **Pracującymi pod kontrolą starszych systemów:** Laptopy pancerne (np. Panasonic Toughbook CF-19, CF-31) z systemem **Windows 7 SP1 / Windows Embedded Standard 7**, dedykowane do obsługi certyfikowanego oprogramowania radiowego i planistycznego.  
* **Pozbawionymi dostępu do Internetu:** Brak możliwości wykonania apt update, winget czy pobrania instalatora z sieci.  
* **Z surowym systemem operacyjnym:** Ze względów bezpieczeństwa nie zainstalowano na nich środowisk programistycznych ani interpreterów.  
* **Z ograniczonymi uprawnieniami:** Brak praw administratora do instalowania bibliotek.

Projektowanie narzędzi audytorskich dla takich środowisk opiera się na **trzech sprawdzonych metodach wdrożenia polowego**.

## **2\. Metoda 1 (Rekomendowana): Kompilacja do Samodzielnego Pliku Wykonywalnego (Standalone Binary)**

Najwygodniejszym standardem w wojsku i przemyśle jest uprzednie spakowanie skryptu Pythona do pojedynczego pliku wykonywalnego:

* Dla Windows: **TABI.-.Tactical.Air-gap.Bastion.Inspector.exe** (działa na Windows 7 SP1, 8, 8.1, 10, 11 oraz Windows Server)  
* Dla Linux: **tabi** (samodzielny plik binarny ELF dla dystrybucji x86\_64)

Plik binarny zawiera wewnątrz skompresowany interpreter Pythona oraz biblioteki standardowe. **Działa natychmiast po uruchomieniu, nie wymagając instalacji czegokolwiek w systemie docelowym.**

### **Jak przygotować binarkę kompatybilną z Windows 7 aż po Windows 11:**

> ⚠️ **Kluczowa uwaga techniczna dotycząca Windows 7:**

> Oficjalny Python 3.9+ porzucił wsparcie dla Windows 7\. Aby wygenerowany plik wykonywalny działał zarówno na zabytkowych terminalach Windows 7, jak i najnowszych Windows 11, **do budowy binarki na stacji inżynierskiej zaleca się użycie środowiska Python 3.8.10 (64-bit lub 32-bit)**.

\# 1\. Usunięcie pozostałości po poprzedniej kompilacji v1.0:  
Remove-Item \-Recurse \-Force build, dist \-ErrorAction SilentlyContinue

\# 2\. Budowa pojedynczego pliku .exe dla Windows (z ikoną i ujednoliconą nazwą):  
python \-m PyInstaller \--onefile \--console \--clean \--icon="TABILogo.ico" \--name "TABI.-.Tactical.Air-gap.Bastion.Inspector" tabi.py

\# 3\. Budowa pojedynczego pliku binarnego dla Linux:  
pyinstaller \--onefile \--name tabi tabi.py

Wynikowy plik (dist/TABI.-.Tactical.Air-gap.Bastion.Inspector.exe lub dist/tabi) waży kilkanaście megabajtów.

### **Dystrybucja do operatorów:**

1. Gotowy plik TABI.-.Tactical.Air-gap.Bastion.Inspector.exe umieszcza się w sekcji **Releases** na GitHubie (v1.1.0).  
2. Żołnierz / audytor pobiera gotowy plik na zatwierdzony nośnik (np. płyta CD-R lub pendrive z fizycznym przełącznikiem *Write-Protect*).  
3. Na stacji w terenie uruchamia dwuklikiem lub wpisuje w konsoli:  
   .\\TABI.-.Tactical.Air-gap.Bastion.Inspector.exe

## **3\. Metoda 2: Oficjalny „Windows Embeddable Package” (Przenośny Python bez instalacji)**

Fundacja Python dostarcza oficjalne paczki **Windows embeddable package** o wadze ok. 10 MB. Jest to czysty, przenośny interpreter, który:

* Nie wymaga uprawnień administratora,  
* Nie modyfikuje rejestru Windows,  
* Nie wymaga wpisów do zmiennej środowiskowej PATH.

Dla stacji z **Windows 7** wystarczy pobrać paczkę python-3.8.10-embed-amd64.zip.

### **Przygotowanie paczki polowej USB (Folder TABI\_PORTABLE):**

Struktura katalogu na nośniku przenośnym:

TABI\_PORTABLE/  
├── python-3.8.10-embed-amd64/    \<-- rozpakowany oficjalny zip z python.org  
│   ├── python.exe  
│   └── ...  
├── tabi.py  
└── URUCHOM\_TABI.bat

Zawartość pliku wsadowego URUCHOM\_TABI.bat:

@echo off  
cd /d "%\~dp0"  
.\\python-3.8.10-embed-amd64\\python.exe tabi.py  
pause

## **4\. Metoda 3: Linux Live / Środowiska Wbudowane**

W przypadku systemów Linux używanych w taktycznych laptopach i stacjach łączności:

* Praktycznie każda dystrybucja Linuksa (Debian, Ubuntu, Red Hat, RHEL Tactical, Alpine) posiada domyślnie zainstalowanego Pythona 3\.  
* Ponieważ TABI ma **ZERO zależności zewnętrznych**, na dowolnym Linuksie rusza od razu:  
  python3 tabi.py

## **5\. Dobre Praktyki Bezpieczeństwa w Środowiskach Niejawnych (SOP)**

1. **Nośniki jednokrotnego zapisu (WORM / Write-Once):** Dostarczanie audytora na płytach CD-R / DVD-R lub nośnikach z fizyczną blokadą zapisu uniemożliwia zainfekowanie narzędzia przez badaną stację.  
2. **Integralność kryptograficzna:** Weryfikacja sumy kontrolnej SHA-256 pliku binarnego przed uruchomieniem:  
   Get-FileHash ".\\TABI.-.Tactical.Air-gap.Bastion.Inspector.exe" \-Algorithm SHA256

   sha256sum tabi

3. **Tryb cichy / pasywny (--quick):** W przypadku stacji pracujących pod nadzorem radiowym zaleca się uruchomienie z flagą \-q, aby zminimalizować emisje elektromagnetyczne.