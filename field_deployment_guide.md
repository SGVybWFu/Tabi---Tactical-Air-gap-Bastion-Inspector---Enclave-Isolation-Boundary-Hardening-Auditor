# **TABI — Field Deployment & Air-Gap Operations Guide (v1.1)**

## **1\. Operational Context: Zero-Connectivity, Legacy Terminals (Windows 7 / Toughbook), and Missing Interpreters**

In field conditions (e.g., Tactical Operations Centers \[TOC\], forward electronic warfare shelters, cryptographic vaults, and classified research laboratories), operators frequently encounter host environments characterized by:

* **Legacy & Ruggedized Operating Systems:** Armored tactical laptops (such as the Panasonic Toughbook CF-19 / CF-31) running **Windows 7 SP1 / Windows Embedded Standard 7**, dedicated to running certified radio planning or military payload software.  
* **Complete Network Isolation (Air-Gap):** Zero internet access—commands such as apt update, winget, or downloading online setup bundles fail immediately.  
* **Stock OS Deployments:** For security compliance, no development tools, package managers, or language runtimes are pre-installed.  
* **Restricted Privileges:** Operators or auditors may not possess administrative rights to modify system PATH variables or install software.

Designing security audit tooling for these environments relies on **three verified field deployment strategies**.

## **2\. Method 1 (Recommended): Standalone Executable Compilation (Self-Contained Binaries)**

The standard operational procedure for defense and critical infrastructure auditing is compiling the Python script into a self-contained binary beforehand:

* **Windows:** TABI.-.Tactical.Air-gap.Bastion.Inspector.exe (compatible across Windows 7 SP1, 8, 8.1, 10, 11, and Windows Server)  
* **Linux:** tabi (standalone ELF binary for x86\_64 Linux distributions)

The compiled binary embeds a compressed Python runtime and the required standard library modules. **It executes immediately upon double-click or CLI invocation without requiring any pre-installed software on the target host.**

### **Building Binaries with Windows 7 through Windows 11 Cross-Compatibility:**

> ⚠️ **Key Technical Advisory for Windows 7:**

> Upstream Python 3.9+ dropped support for Windows 7\. To ensure the compiled binary executes seamlessly on legacy Windows 7 / Embedded Standard 7 terminals as well as modern Windows 11 systems, **build the executable on an engineering workstation equipped with Python 3.8.10 (32-bit or 64-bit)**.

#### **Build Commands on the Engineering Workstation:**

\# 1\. Clean previous build artifacts (important for v1.1 upgrade)  
Remove-Item \-Recurse \-Force build, dist \-ErrorAction SilentlyContinue

\# 2\. Build single standalone .exe with embedded icon and console support:  
python \-m PyInstaller \--onefile \--console \--clean \--icon="TABILogo.ico" \--name "TABI.-.Tactical.Air-gap.Bastion.Inspector" tabi.py

\# 3\. Build standalone ELF binary on Linux:  
pyinstaller \--onefile \--name tabi tabi.py

The resulting binary (dist/TABI.-.Tactical.Air-gap.Bastion.Inspector.exe or dist/tabi) is self-contained (\~9–12 MB).

### **Field Distribution Workflow:**

1. The compiled executable is published as a verified artifact in the GitHub repository's **Releases** tab (v1.1.0).  
2. An operator downloads the binary onto an approved transfer medium (e.g., a CD-R disc or a flash drive equipped with a hardware *Write-Protect* switch).  
3. On the target field terminal, run directly:  
   .\\TABI.-.Tactical.Air-gap.Bastion.Inspector.exe

## **3\. Method 2: Official "Windows Embeddable Package" (Zero-Install Portable Python)**

The Python Software Foundation provides official, lightweight **Windows embeddable zip packages** (\~10 MB). This is a clean, fully portable interpreter environment that:

* Requires zero administrative privileges to run,  
* Does not touch the Windows Registry,  
* Requires no system PATH modifications.

For legacy **Windows 7** stations, download python-3.8.10-embed-amd64.zip (or the 32-bit x86 variant for older 32-bit Toughbook units).

### **Preparing a Portable USB Package (TABI\_PORTABLE):**

Directory structure on the deployment drive:

TABI\_PORTABLE/  
├── python-3.8.10-embed-amd64/    \<-- Extracted official archive from python.org  
│   ├── python.exe  
│   └── ...  
├── tabi.py  
└── RUN\_TABI.bat

Contents of the launcher batch script RUN\_TABI.bat:

@echo off  
cd /d "%\~dp0"  
.\\python-3.8.10-embed-amd64\\python.exe tabi.py  
pause

## **4\. Method 3: Linux Live & Tactical Embedded Systems**

On tactical workstations and field communications shelters powered by Linux:

* Nearly all tactical enterprise distributions (Debian, RHEL Tactical, Ubuntu, Alpine) include a functional Python 3 environment out of the box.  
* Because TABI enforces a strict **zero external dependencies** rule, it runs natively on standard interpreters without any network connectivity:  
  python3 tabi.py

## **5\. Security Standard Operating Procedures (SOP) for Classified Enclaves**

1. **Write-Once-Read-Many (WORM) Transfer Media:** Supplying audit tooling on finalized CD-R/DVD-R media or flash drives with physical write-lock toggles prevents malicious hosts from tampering with or infecting the auditor toolset.  
2. **Cryptographic Verification (SHA-256):** Always verify the SHA-256 hash of the binary prior to execution on an operational asset:  
   Get-FileHash ".\\TABI.-.Tactical.Air-gap.Bastion.Inspector.exe" \-Algorithm SHA256

   sha256sum tabi

3. **Passive / Stealth Mode (--quick):** On workstations operating under strict radio silence or emission security policies, run TABI with the \-q / \--quick flag to eliminate all outbound network probes and test strictly local boundary controls.