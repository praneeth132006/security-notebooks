# Security Notebooks

337 chapters across 47 notebooks covering offensive and defensive security, from Linux fundamentals to red team operations.

**Read it as a site:** https://praneeth132006.github.io/security-notebooks/

The chapter files are generated, so please don't open PRs against them. Corrections and questions are welcome as [issues](https://github.com/praneeth132006/security-notebooks/issues) or in the comments under each chapter.

> Everything here is for learning and for authorized testing only. Only test systems you own or have written permission to test.

## Contents

### Foundations

- **Linux**
  - [01 · Linux Fundamentals, History & Filesystem Hierarchy](src/content/docs/linux/01-linux-fundamentals-and-filesystem.md)
  - [02 · The Shell & Terminal: Navigation and File Management Mastery](src/content/docs/linux/02-the-shell-and-terminal-navigation-and-file-management.md)
  - [03 · Linux Permissions Deep Dive: chmod, chown, umask, SUID/SGID/Sticky](src/content/docs/linux/03-linux-permissions-deep-dive-chmod-chown-umask-suid.md)
  - [04 · Users, Groups, sudo, PAM & Authentication](src/content/docs/linux/04-users-groups-sudo-pam-and-authentication.md)
  - [05 · Package Management & Compiling Software from Source](src/content/docs/linux/05-package-management-and-compiling-software-from-source.md)
  - [06 · Bash Scripting Essentials: Variables, Logic, Loops & Functions](src/content/docs/linux/06-bash-scripting-essentials-variables-logic-loops-and-functions.md)
  - [07 · Text Processing & Regex Mastery: grep, sed, awk, cut, sort](src/content/docs/linux/07-text-processing-and-regex-mastery-grep-sed-awk.md)
  - [08 · Processes, systemd, Services, Signals & Scheduling (cron)](src/content/docs/linux/08-processes-systemd-services-signals-and-scheduling-cron.md)
  - [09 · Linux Networking, SSH & Tunneling from the Command Line](src/content/docs/linux/09-linux-networking-ssh-and-tunneling-from-the-command.md)
  - [10 · Logging, Hardening & the Linux Security Baseline](src/content/docs/linux/10-logging-hardening-and-the-linux-security-baseline.md)
- **Networking**
  - [01 · How the Internet Works: Packets, Encapsulation & the Big Picture](src/content/docs/networking/01-how-the-internet-works-packets-encapsulation-and-the.md)
  - [02 · OSI & TCP/IP Models Layer by Layer](src/content/docs/networking/02-osi-and-tcp-ip-models-layer-by-layer.md)
  - [03 · IP Addressing, Binary Math, Subnetting & CIDR Mastery](src/content/docs/networking/03-ip-addressing-binary-math-subnetting-and-cidr-mastery.md)
  - [04 · Ethernet, MAC Addresses, Switching, ARP & VLANs](src/content/docs/networking/04-ethernet-mac-addresses-switching-arp-and-vlans.md)
  - [05 · Routing, NAT & the Default Gateway](src/content/docs/networking/05-routing-nat-and-the-default-gateway.md)
  - [06 · TCP Deep Dive: Handshake, Flags, Sequence Numbers & States](src/content/docs/networking/06-tcp-deep-dive-handshake-flags-sequence-numbers-and.md)
  - [07 · UDP, ICMP & Connectionless Protocols](src/content/docs/networking/07-udp-icmp-and-connectionless-protocols.md)
  - [08 · DNS Completely Explained: Records, Resolution & Zones](src/content/docs/networking/08-dns-completely-explained-records-resolution-and-zones.md)
  - [09 · DHCP & Dynamic Address Assignment](src/content/docs/networking/09-dhcp-and-dynamic-address-assignment.md)
  - [10 · HTTP, HTTPS, TLS/SSL & PKI in Practice](src/content/docs/networking/10-http-https-tls-ssl-and-pki-in-practice.md)
  - [11 · Firewalls, IDS/IPS, Proxies, VPNs & Network Segmentation](src/content/docs/networking/11-firewalls-ids-ips-proxies-vpns-and-network-segmentation.md)
  - [12 · Wireless 802.11 Fundamentals & Network Analysis Methodology](src/content/docs/networking/12-wireless-802-11-fundamentals-and-network-analysis-methodology.md)
- **Windows Internals**
  - [01 · Windows Architecture, Processes, Threads & the Registry](src/content/docs/windows-fundamentals/01-windows-architecture-processes-threads-and-the-registry.md)
  - [02 · Windows File System, Permissions, ACLs & Security Descriptors](src/content/docs/windows-fundamentals/02-windows-file-system-permissions-acls-and-security-descriptors.md)
  - [03 · Windows Authentication: SAM, LSASS, NTLM & Kerberos Explained](src/content/docs/windows-fundamentals/03-windows-authentication-sam-lsass-ntlm-and-kerberos-explained.md)
  - [04 · PowerShell Fundamentals & the Object Pipeline](src/content/docs/windows-fundamentals/04-powershell-fundamentals-and-the-object-pipeline.md)
  - [05 · PowerShell Remoting, WMI/CIM & Living-off-the-Land (LOLBAS)](src/content/docs/windows-fundamentals/05-powershell-remoting-wmi-cim-and-living-off-the.md)
  - [06 · SMB, RPC, Named Pipes & Windows Networking Services](src/content/docs/windows-fundamentals/06-smb-rpc-named-pipes-and-windows-networking-services.md)
  - [07 · Windows Event Logs, Sysmon & Telemetry](src/content/docs/windows-fundamentals/07-windows-event-logs-sysmon-and-telemetry.md)
- **Active Directory Basics**
  - [01 · What is Active Directory? Domains, Forests, Trees & OUs](src/content/docs/active-directory-fundamentals/01-what-is-active-directory-domains-forests-trees-and.md)
  - [02 · Domain Controllers, Global Catalog, LDAP & DNS in AD](src/content/docs/active-directory-fundamentals/02-domain-controllers-global-catalog-ldap-and-dns-in.md)
  - [03 · Users, Groups, Computers, SIDs, RIDs & Security Principals](src/content/docs/active-directory-fundamentals/03-users-groups-computers-sids-rids-and-security-principals.md)
  - [04 · Group Policy (GPO), Delegation & Administrative Tiering](src/content/docs/active-directory-fundamentals/04-group-policy-gpo-delegation-and-administrative-tiering.md)
  - [05 · Kerberos Authentication Flow Step by Step (TGT, TGS, PAC)](src/content/docs/active-directory-fundamentals/05-kerberos-authentication-flow-step-by-step-tgt-tgs.md)
- **Programming for Security**
  - [01 · Python for Security Part 1: Syntax, Data Types & Control Flow](src/content/docs/programming-for-security/01-python-for-security-part-1-syntax-data-types.md)
  - [02 · Python for Security Part 2: Functions, Files, Modules & Requests](src/content/docs/programming-for-security/02-python-for-security-part-2-functions-files-modules.md)
  - [03 · Python for Security Part 3: Sockets, Scapy & Writing Your First Tools](src/content/docs/programming-for-security/03-python-for-security-part-3-sockets-scapy-and.md)
  - [04 · Bash Scripting for Offensive & Defensive Automation](src/content/docs/programming-for-security/04-bash-scripting-for-offensive-and-defensive-automation.md)
  - [05 · Understanding C, Memory Layout, Pointers & the Stack](src/content/docs/programming-for-security/05-understanding-c-memory-layout-pointers-and-the-stack.md)
  - [06 · JavaScript & the DOM for Web Security](src/content/docs/programming-for-security/06-javascript-and-the-dom-for-web-security.md)
  - [07 · PowerShell & C# for Windows Tooling](src/content/docs/programming-for-security/07-powershell-and-c-for-windows-tooling.md)
  - [08 · Go for Fast, Portable Security Tooling](src/content/docs/programming-for-security/08-go-for-fast-portable-security-tooling.md)
- **How the Web Works**
  - [01 · How the Web Works End to End: Client, Server, DNS & Rendering](src/content/docs/web-fundamentals/01-how-the-web-works-end-to-end-client.md)
  - [02 · HTTP in Depth: Verbs, Headers, Cookies, Caching & Redirects](src/content/docs/web-fundamentals/02-http-in-depth-verbs-headers-cookies-caching-and.md)
  - [03 · Sessions, Cookies, Tokens & Stateful vs Stateless Auth](src/content/docs/web-fundamentals/03-sessions-cookies-tokens-and-stateful-vs-stateless-auth.md)
  - [04 · Same-Origin Policy, CORS & the Browser Security Model](src/content/docs/web-fundamentals/04-same-origin-policy-cors-and-the-browser-security.md)
  - [05 · REST APIs, GraphQL & Modern API Architecture](src/content/docs/web-fundamentals/05-rest-apis-graphql-and-modern-api-architecture.md)
  - [06 · Encoding & Serialization: URL, Base64, JSON, XML, Hex & CyberChef](src/content/docs/web-fundamentals/06-encoding-and-serialization-url-base64-json-xml-hex.md)
- **Cryptography**
  - [01 · Cryptography Foundations: Encoding vs Encryption vs Hashing](src/content/docs/cryptography/01-cryptography-foundations-encoding-vs-encryption-vs-hashing.md)
  - [02 · Symmetric Encryption: AES, Block Modes & Stream Ciphers](src/content/docs/cryptography/02-symmetric-encryption-aes-block-modes-and-stream-ciphers.md)
  - [03 · Asymmetric Encryption: RSA, ECC & Diffie-Hellman Key Exchange](src/content/docs/cryptography/03-asymmetric-encryption-rsa-ecc-and-diffie-hellman-key.md)
  - [04 · Hashing, Salting, HMAC & Integrity](src/content/docs/cryptography/04-hashing-salting-hmac-and-integrity.md)
  - [05 · Password Storage Done Right: bcrypt, scrypt, Argon2, PBKDF2](src/content/docs/cryptography/05-password-storage-done-right-bcrypt-scrypt-argon2-pbkdf2.md)
  - [06 · PKI, Digital Signatures, Certificates & Chains of Trust](src/content/docs/cryptography/06-pki-digital-signatures-certificates-and-chains-of-trust.md)
  - [07 · Practical Crypto Attacks: XOR, ECB, Padding Oracle & CTF Techniques](src/content/docs/cryptography/07-practical-crypto-attacks-xor-ecb-padding-oracle-and.md)
- **Security Theory**
  - [01 · The CIA Triad, AAA, Threats, Vulnerabilities & Risk](src/content/docs/security-foundations/01-the-cia-triad-aaa-threats-vulnerabilities-and-risk.md)
  - [02 · Threat Modeling: STRIDE, DREAD & Attack Trees](src/content/docs/security-foundations/02-threat-modeling-stride-dread-and-attack-trees.md)
  - [03 · The Cyber Kill Chain & MITRE ATT&CK Framework](src/content/docs/security-foundations/03-the-cyber-kill-chain-and-mitre-attandck-framework.md)
  - [04 · Security Roles, Teams (Red/Blue/Purple) & Career Fields Explained](src/content/docs/security-foundations/04-security-roles-teams-red-blue-purple-and-career.md)
  - [05 · Law & Ethics: Authorization, Scope & Rules of Engagement](src/content/docs/security-foundations/05-law-and-ethics-authorization-scope-and-rules-of.md)
  - [06 · Building Your Hacking Lab: Kali/Parrot, VMs & Vulnerable Targets](src/content/docs/security-foundations/06-building-your-hacking-lab-kali-parrot-vms-and.md)

### Penetration Testing

- **Methodology & Lab**
  - [01 · Pentest Methodology & the Engagement Lifecycle](src/content/docs/pentest-methodology/01-pentest-methodology-and-the-engagement-lifecycle.md)
  - [02 · Scoping, Rules of Engagement, Legal Boundaries & Ethics](src/content/docs/pentest-methodology/02-scoping-rules-of-engagement-legal-boundaries-and-ethics.md)
  - [03 · Building Your Hacking Lab: Kali, VMs, Targets, HTB & THM](src/content/docs/pentest-methodology/03-building-your-hacking-lab-kali-vms-targets-htb-and-thm.md)
- **Recon & OSINT**
  - [01 · Reconnaissance: Passive vs Active & the Attack Surface](src/content/docs/pentest-recon-osint/01-reconnaissance-passive-vs-active-and-the-attack-surface.md)
  - [02 · Passive Recon: WHOIS, DNS Enumeration & Certificate Transparency](src/content/docs/pentest-recon-osint/02-passive-recon-whois-dns-enumeration-and-certificate-transparency.md)
  - [03 · OSINT Foundations: Discipline, OPSEC & Sock-Puppet Accounts](src/content/docs/pentest-recon-osint/03-osint-foundations-discipline-opsec-and-sock-puppet-accounts.md)
  - [04 · Google Dorking & Search-Engine Recon for Hackers](src/content/docs/pentest-recon-osint/04-google-dorking-and-search-engine-recon-for-hackers.md)
  - [05 · Subdomain Enumeration: Amass, Subfinder, Sublist3r & Assetfinder](src/content/docs/pentest-recon-osint/05-subdomain-enumeration-amass-subfinder-sublist3r-and-assetfinder.md)
  - [06 · OSINT Frameworks: theHarvester, Recon-ng, SpiderFoot & Maltego](src/content/docs/pentest-recon-osint/06-osint-frameworks-theharvester-recon-ng-spiderfoot-and-maltego.md)
  - [07 · Username, Email & Account OSINT: Sherlock, Maigret & Holehe](src/content/docs/pentest-recon-osint/07-username-email-and-account-osint-sherlock-maigret-and-holehe.md)
  - [08 · Breach Data, Credential Leaks & Dark-Web OSINT](src/content/docs/pentest-recon-osint/08-breach-data-credential-leaks-and-dark-web-osint.md)
  - [09 · Shodan, Censys & Internet-Wide Asset Discovery](src/content/docs/pentest-recon-osint/09-shodan-censys-and-internet-wide-asset-discovery.md)
  - [10 · Active Recon & Tech Fingerprinting: httpx, whatweb & Wappalyzer](src/content/docs/pentest-recon-osint/10-active-recon-and-tech-fingerprinting-httpx-whatweb-and-wappalyzer.md)
  - [11 · Image, Geolocation & Metadata OSINT: ExifTool, Reverse Image & GEOINT](src/content/docs/pentest-recon-osint/11-image-geolocation-and-metadata-osint-exiftool-reverse-image-and-geoint.md)
  - [12 · Corporate, People & Social-Media OSINT for Red Teams](src/content/docs/pentest-recon-osint/12-corporate-people-and-social-media-osint-for-red-teams.md)
  - [13 · Automating Recon: Building an End-to-End OSINT & Attack-Surface Pipeline](src/content/docs/pentest-recon-osint/13-automating-recon-building-an-end-to-end-osint-and-attack-surface-pipeline.md)
- **Scanning & Enumeration**
  - [01 · Host Discovery & the Scanning Methodology](src/content/docs/pentest-scanning-enum/01-host-discovery-and-the-scanning-methodology.md)
  - [02 · Nmap Part 1: Install, Host Discovery & Scan Types](src/content/docs/pentest-scanning-enum/02-nmap-part-1-install-host-discovery-and-scan-types.md)
  - [03 · Nmap Part 2: Service/OS Detection, Timing & Output Formats](src/content/docs/pentest-scanning-enum/03-nmap-part-2-service-os-detection-timing-and-output-formats.md)
  - [04 · Nmap Part 3: NSE Scripting Engine & Firewall/IDS Evasion](src/content/docs/pentest-scanning-enum/04-nmap-part-3-nse-scripting-engine-and-firewall-ids-evasion.md)
  - [05 · Masscan & RustScan: High-Speed Scanning](src/content/docs/pentest-scanning-enum/05-masscan-and-rustscan-high-speed-scanning.md)
  - [06 · Service Enumeration: FTP, SSH, SMTP, Telnet & Banner Grabbing](src/content/docs/pentest-scanning-enum/06-service-enumeration-ftp-ssh-smtp-telnet-and-banner-grabbing.md)
  - [07 · SMB, RPC & NetBIOS Enumeration: enum4linux, smbclient, NetExec](src/content/docs/pentest-scanning-enum/07-smb-rpc-and-netbios-enumeration-enum4linux-smbclient-netexec.md)
  - [08 · SNMP, LDAP, NFS & Database Service Enumeration](src/content/docs/pentest-scanning-enum/08-snmp-ldap-nfs-and-database-service-enumeration.md)
- **Vulnerability Assessment**
  - [01 · Vulnerability Scanning Concepts: CVE, CVSS & CWE](src/content/docs/pentest-vuln-assessment/01-vulnerability-scanning-concepts-cve-cvss-and-cwe.md)
  - [02 · Nessus: Installation, Policies, Scanning & Reporting](src/content/docs/pentest-vuln-assessment/02-nessus-installation-policies-scanning-and-reporting.md)
  - [03 · OpenVAS/Greenbone & Nikto Web Scanning](src/content/docs/pentest-vuln-assessment/03-openvas-greenbone-and-nikto-web-scanning.md)
  - [04 · Manual Vulnerability Validation & Triage](src/content/docs/pentest-vuln-assessment/04-manual-vulnerability-validation-and-triage.md)
- **Web App Pentest**
  - [01 · Web Application Pentest Methodology & the OWASP Testing Guide](src/content/docs/pentest-web/01-web-application-pentest-methodology-and-the-owasp-testing-guide.md)
  - [02 · Mapping the Web Attack Surface: Crawling, Params & Hidden Endpoints](src/content/docs/pentest-web/02-mapping-the-web-attack-surface-crawling-params-and-hidden-endpoints.md)
  - [03 · Authentication, Session & Access-Control Testing in Practice](src/content/docs/pentest-web/03-authentication-session-and-access-control-testing-in-practice.md)
  - [04 · From Web Bug to Shell: Chaining Web Vulns in a Pentest](src/content/docs/pentest-web/04-from-web-bug-to-shell-chaining-web-vulns-in-a-pentest.md)
- **Network Attacks**
  - [01 · Wireshark Part 1: Capturing & Packet Anatomy](src/content/docs/pentest-network-attacks/01-wireshark-part-1-capturing-and-packet-anatomy.md)
  - [02 · Wireshark Part 2: Display Filters, Streams & Protocol Analysis](src/content/docs/pentest-network-attacks/02-wireshark-part-2-display-filters-streams-and-protocol-analysis.md)
  - [03 · Wireshark Part 3: Analyzing Attacks & Extracting Credentials](src/content/docs/pentest-network-attacks/03-wireshark-part-3-analyzing-attacks-and-extracting-credentials.md)
  - [04 · tcpdump & Command-Line Packet Capture](src/content/docs/pentest-network-attacks/04-tcpdump-and-command-line-packet-capture.md)
  - [05 · Man-in-the-Middle & ARP Spoofing: Ettercap & Bettercap](src/content/docs/pentest-network-attacks/05-man-in-the-middle-and-arp-spoofing-ettercap-and-bettercap.md)
  - [06 · DNS Spoofing, SSL Stripping & Traffic Manipulation](src/content/docs/pentest-network-attacks/06-dns-spoofing-ssl-stripping-and-traffic-manipulation.md)
  - [07 · Responder, LLMNR/NBT-NS Poisoning & Credential Capture](src/content/docs/pentest-network-attacks/07-responder-llmnr-nbt-ns-poisoning-and-credential-capture.md)
  - [08 · Pivoting & Tunneling: chisel, sshuttle, ligolo-ng & proxychains](src/content/docs/pentest-network-attacks/08-pivoting-and-tunneling-chisel-sshuttle-ligolo-ng-and-proxychains.md)
- **Password Attacks**
  - [01 · Password Fundamentals: Hashes, Storage, Entropy & Attack Types](src/content/docs/pentest-password-attacks/01-password-fundamentals-hashes-storage-entropy-and-attack-types.md)
  - [02 · Wordlists & Rules: rockyou, crunch, CeWL & Mangling](src/content/docs/pentest-password-attacks/02-wordlists-and-rules-rockyou-crunch-cewl-and-mangling.md)
  - [03 · Hydra: Online Brute Force of Login Services](src/content/docs/pentest-password-attacks/03-hydra-online-brute-force-of-login-services.md)
  - [04 · John the Ripper: Offline Cracking, Formats & Rules](src/content/docs/pentest-password-attacks/04-john-the-ripper-offline-cracking-formats-and-rules.md)
  - [05 · Hashcat: GPU Cracking, Attack Modes & Masks](src/content/docs/pentest-password-attacks/05-hashcat-gpu-cracking-attack-modes-and-masks.md)
  - [06 · Credential Stuffing, Spraying & Hash Identification](src/content/docs/pentest-password-attacks/06-credential-stuffing-spraying-and-hash-identification.md)
- **Exploitation**
  - [01 · Exploitation Fundamentals: Shells, Payloads & Delivery](src/content/docs/pentest-exploitation/01-exploitation-fundamentals-shells-payloads-and-delivery.md)
  - [02 · Finding & Using Public Exploits: Exploit-DB & searchsploit](src/content/docs/pentest-exploitation/02-finding-and-using-public-exploits-exploit-db-and-searchsploit.md)
  - [03 · Metasploit Part 1: Architecture, msfconsole & Modules](src/content/docs/pentest-exploitation/03-metasploit-part-1-architecture-msfconsole-and-modules.md)
  - [04 · Metasploit Part 2: Exploits, Payloads, Sessions & Meterpreter](src/content/docs/pentest-exploitation/04-metasploit-part-2-exploits-payloads-sessions-and-meterpreter.md)
  - [05 · Metasploit Part 3: msfvenom Payloads & Encoders](src/content/docs/pentest-exploitation/05-metasploit-part-3-msfvenom-payloads-and-encoders.md)
  - [06 · Metasploit Part 4: Post Modules, Pivoting & Automation](src/content/docs/pentest-exploitation/06-metasploit-part-4-post-modules-pivoting-and-automation.md)
  - [07 · Reverse vs Bind Shells, Stabilization & TTY Upgrading](src/content/docs/pentest-exploitation/07-reverse-vs-bind-shells-stabilization-and-tty-upgrading.md)
  - [08 · Netcat & Socat: The Swiss-Army Knives of Shells](src/content/docs/pentest-exploitation/08-netcat-and-socat-the-swiss-army-knives-of-shells.md)
- **Privilege Escalation**
  - [01 · Post-Exploitation Methodology & Situational Awareness](src/content/docs/pentest-privilege-escalation/01-post-exploitation-methodology-and-situational-awareness.md)
  - [02 · Linux Privilege Escalation Part 1: Enumeration (LinPEAS & Manual)](src/content/docs/pentest-privilege-escalation/02-linux-privilege-escalation-part-1-enumeration-linpeas-and-manual.md)
  - [03 · Linux Privilege Escalation Part 2: SUID, Capabilities, Cron, PATH, Kernel](src/content/docs/pentest-privilege-escalation/03-linux-privilege-escalation-part-2-suid-capabilities-cron-path-kernel.md)
  - [04 · Windows Privilege Escalation Part 1: Enumeration (WinPEAS, Seatbelt)](src/content/docs/pentest-privilege-escalation/04-windows-privilege-escalation-part-1-enumeration-winpeas-seatbelt.md)
  - [05 · Windows Privilege Escalation Part 2: Services, Tokens, UAC, Unquoted Paths](src/content/docs/pentest-privilege-escalation/05-windows-privilege-escalation-part-2-services-tokens-uac-unquoted-paths.md)
  - [06 · Credential Harvesting: Mimikatz, LSASS & SAM/NTDS](src/content/docs/pentest-privilege-escalation/06-credential-harvesting-mimikatz-lsass-and-sam-ntds.md)
  - [07 · Persistence & Lateral Movement Across Linux & Windows](src/content/docs/pentest-privilege-escalation/07-persistence-and-lateral-movement-across-linux-and-windows.md)
- **Active Directory**
  - [01 · AD Attack Methodology & the Assumed-Breach Mindset](src/content/docs/pentest-active-directory/01-ad-attack-methodology-and-the-assumed-breach-mindset.md)
  - [02 · BloodHound & SharpHound: Mapping AD Attack Paths](src/content/docs/pentest-active-directory/02-bloodhound-and-sharphound-mapping-ad-attack-paths.md)
  - [03 · PowerView, ADRecon & AD Enumeration (kerbrute user spray)](src/content/docs/pentest-active-directory/03-powerview-adrecon-and-ad-enumeration-kerbrute-user-spray.md)
  - [04 · Kerberoasting & AS-REP Roasting (Rubeus & Impacket)](src/content/docs/pentest-active-directory/04-kerberoasting-and-as-rep-roasting-rubeus-and-impacket.md)
  - [05 · Pass-the-Hash, Pass-the-Ticket & Overpass-the-Hash](src/content/docs/pentest-active-directory/05-pass-the-hash-pass-the-ticket-and-overpass-the-hash.md)
  - [06 · Golden, Silver & Diamond Ticket Attacks](src/content/docs/pentest-active-directory/06-golden-silver-and-diamond-ticket-attacks.md)
  - [07 · DCSync, DCShadow & Domain Dominance](src/content/docs/pentest-active-directory/07-dcsync-dcshadow-and-domain-dominance.md)
  - [08 · Kerberos Delegation Attacks: Unconstrained, Constrained & RBCD](src/content/docs/pentest-active-directory/08-kerberos-delegation-attacks-unconstrained-constrained-and-rbcd.md)
  - [09 · ACL/ACE Abuse in Active Directory](src/content/docs/pentest-active-directory/09-acl-ace-abuse-in-active-directory.md)
  - [10 · NTLM Relay & Coercion: ntlmrelayx, PetitPotam, Coercer](src/content/docs/pentest-active-directory/10-ntlm-relay-and-coercion-ntlmrelayx-petitpotam-coercer.md)
  - [11 · AD Certificate Services (AD CS / ESC) Attacks with Certipy](src/content/docs/pentest-active-directory/11-ad-certificate-services-ad-cs-esc-attacks-with-certipy.md)
  - [12 · Impacket, NetExec/CrackMapExec & the AD Attacker Toolkit](src/content/docs/pentest-active-directory/12-impacket-netexec-crackmapexec-and-the-ad-attacker-toolkit.md)
- **Wireless**
  - [01 · Wi-Fi Security Fundamentals: WEP, WPA, WPA2, WPA3 & Handshakes](src/content/docs/pentest-wireless/01-wi-fi-security-fundamentals-wep-wpa-wpa2-wpa3-and-handshakes.md)
  - [02 · Aircrack-ng Suite: Monitor Mode, Capture & Cracking](src/content/docs/pentest-wireless/02-aircrack-ng-suite-monitor-mode-capture-and-cracking.md)
  - [03 · WPA/WPA2 PSK & PMKID Attacks with hcxdumptool](src/content/docs/pentest-wireless/03-wpa-wpa2-psk-and-pmkid-attacks-with-hcxdumptool.md)
  - [04 · Evil Twin, Rogue AP & Captive Portal Attacks (wifiphisher)](src/content/docs/pentest-wireless/04-evil-twin-rogue-ap-and-captive-portal-attacks-wifiphisher.md)
  - [05 · Deauthentication, WPS (Reaver/Bully) & Client-Side Attacks](src/content/docs/pentest-wireless/05-deauthentication-wps-reaver-bully-and-client-side-attacks.md)
  - [06 · Bluetooth, BLE & Other Radio Attack Surfaces](src/content/docs/pentest-wireless/06-bluetooth-ble-and-other-radio-attack-surfaces.md)
- **Capstone**
  - [01 · Full-Scope Internal Pentest: External to Domain Admin Walkthrough](src/content/docs/pentest-capstone/01-full-scope-internal-pentest-external-to-domain-admin-walkthrough.md)
  - [02 · Solving a Boot-to-Root CTF Machine End to End (HTB/THM Style)](src/content/docs/pentest-capstone/02-solving-a-boot-to-root-ctf-machine-end-to-end-htb-thm-style.md)
  - [03 · Professional Pentest Report Writing & CVSS Scoring](src/content/docs/pentest-capstone/03-professional-pentest-report-writing-and-cvss-scoring.md)

### Bug Bounty & AppSec

- **Bug Bounty Foundations**
  - [01 · How Bug Bounty Works: Platforms, Scope, Disclosure & Payouts](src/content/docs/appsec-bugbounty-intro/01-how-bug-bounty-works-platforms-scope-disclosure-and-payouts.md)
  - [02 · Bug Bounty Recon at Scale: Assets, Subdomains & Content Discovery](src/content/docs/appsec-bugbounty-intro/02-bug-bounty-recon-at-scale-assets-subdomains-and-content-discovery.md)
- **Web Tooling**
  - [01 · Burp Suite Part 1: Setup, Proxy, Intercept & Scope](src/content/docs/appsec-web-tooling/01-burp-suite-part-1-setup-proxy-intercept-and-scope.md)
  - [02 · Burp Suite Part 2: Repeater, Intruder, Sequencer & Decoder](src/content/docs/appsec-web-tooling/02-burp-suite-part-2-repeater-intruder-sequencer-and-decoder.md)
  - [03 · Burp Suite Part 3: Scanner, BApp Extensions & Collaborator](src/content/docs/appsec-web-tooling/03-burp-suite-part-3-scanner-bapp-extensions-and-collaborator.md)
  - [04 · OWASP ZAP as a Free Alternative](src/content/docs/appsec-web-tooling/04-owasp-zap-as-a-free-alternative.md)
  - [05 · Content & Parameter Discovery: ffuf, feroxbuster, dirsearch, Arjun](src/content/docs/appsec-web-tooling/05-content-and-parameter-discovery-ffuf-feroxbuster-dirsearch-arjun.md)
  - [06 · Nuclei: Template-Based Vulnerability Scanning at Scale](src/content/docs/appsec-web-tooling/06-nuclei-template-based-vulnerability-scanning-at-scale.md)
  - [07 · OWASP Top 10 & Web Attack-Surface Mapping](src/content/docs/appsec-web-tooling/07-owasp-top-10-and-web-attack-surface-mapping.md)
- **Injection**
  - [01 · SQL Injection Part 1: Databases, SQL & Discovering Injection](src/content/docs/appsec-injection/01-sql-injection-part-1-databases-sql-and-discovering-injection.md)
  - [02 · SQL Injection Part 2: UNION, Error-Based & Blind Exploitation](src/content/docs/appsec-injection/02-sql-injection-part-2-union-error-based-and-blind-exploitation.md)
  - [03 · SQL Injection Part 3: WAF Bypass, Second-Order & sqlmap](src/content/docs/appsec-injection/03-sql-injection-part-3-waf-bypass-second-order-and-sqlmap.md)
  - [04 · OS Command Injection](src/content/docs/appsec-injection/04-os-command-injection.md)
  - [05 · Server-Side Template Injection (SSTI)](src/content/docs/appsec-injection/05-server-side-template-injection-ssti.md)
  - [06 · XML External Entity (XXE) Injection](src/content/docs/appsec-injection/06-xml-external-entity-xxe-injection.md)
- **Client-Side**
  - [01 · Cross-Site Scripting (XSS) Part 1: Reflected & Stored](src/content/docs/appsec-client-side/01-cross-site-scripting-xss-part-1-reflected-and-stored.md)
  - [02 · Cross-Site Scripting (XSS) Part 2: DOM-Based, Mutation & Filter Bypass](src/content/docs/appsec-client-side/02-cross-site-scripting-xss-part-2-dom-based-mutation-and-filter-bypass.md)
  - [03 · Weaponizing XSS: Session Theft & the BeEF Framework](src/content/docs/appsec-client-side/03-weaponizing-xss-session-theft-and-the-beef-framework.md)
  - [04 · Cross-Site Request Forgery (CSRF) & SameSite Defenses](src/content/docs/appsec-client-side/04-cross-site-request-forgery-csrf-and-samesite-defenses.md)
  - [05 · CORS Misconfiguration Exploitation](src/content/docs/appsec-client-side/05-cors-misconfiguration-exploitation.md)
- **Access & Logic**
  - [01 · Broken Access Control & IDOR](src/content/docs/appsec-access-logic/01-broken-access-control-and-idor.md)
  - [02 · Authentication Attacks: Brute Force, Logic Flaws & MFA Bypass](src/content/docs/appsec-access-logic/02-authentication-attacks-brute-force-logic-flaws-and-mfa-bypass.md)
  - [03 · JWT & Token Attacks: Forgery, Algorithm Confusion & Weak Secrets](src/content/docs/appsec-access-logic/03-jwt-and-token-attacks-forgery-algorithm-confusion-and-weak-secrets.md)
  - [04 · Session Management Flaws & Fixation](src/content/docs/appsec-access-logic/04-session-management-flaws-and-fixation.md)
  - [05 · Business Logic Vulnerabilities & Abuse Cases](src/content/docs/appsec-access-logic/05-business-logic-vulnerabilities-and-abuse-cases.md)
- **Server-Side**
  - [01 · Server-Side Request Forgery (SSRF) & Cloud Metadata Attacks](src/content/docs/appsec-server-side/01-server-side-request-forgery-ssrf-and-cloud-metadata-attacks.md)
  - [02 · File Upload Vulnerabilities & Web Shells](src/content/docs/appsec-server-side/02-file-upload-vulnerabilities-and-web-shells.md)
  - [03 · Path Traversal, LFI & RFI](src/content/docs/appsec-server-side/03-path-traversal-lfi-and-rfi.md)
  - [04 · Insecure Deserialization](src/content/docs/appsec-server-side/04-insecure-deserialization.md)
  - [05 · HTTP Request Smuggling & Desync Attacks](src/content/docs/appsec-server-side/05-http-request-smuggling-and-desync-attacks.md)
  - [06 · Race Conditions & TOCTOU in Web Apps](src/content/docs/appsec-server-side/06-race-conditions-and-toctou-in-web-apps.md)
  - [07 · Web Cache Poisoning & Deception](src/content/docs/appsec-server-side/07-web-cache-poisoning-and-deception.md)
  - [08 · Subdomain Takeover & Dangling DNS](src/content/docs/appsec-server-side/08-subdomain-takeover-and-dangling-dns.md)
- **APIs & CMS**
  - [01 · REST API Security Testing Methodology](src/content/docs/appsec-api-bugbounty/01-rest-api-security-testing-methodology.md)
  - [02 · GraphQL API Attacks](src/content/docs/appsec-api-bugbounty/02-graphql-api-attacks.md)
  - [03 · CMS & Framework Testing: WPScan, JoomScan & Known-Vuln Exploitation](src/content/docs/appsec-api-bugbounty/03-cms-and-framework-testing-wpscan-joomscan-and-known-vuln-exploitation.md)
  - [04 · Chaining Bugs for Maximum Impact: Real Bug-Bounty Kill Chains](src/content/docs/appsec-api-bugbounty/04-chaining-bugs-for-maximum-impact-real-bug-bounty-kill-chains.md)
  - [05 · Bug Bounty Methodology: Recon-to-Report Workflow & Automation](src/content/docs/appsec-api-bugbounty/05-bug-bounty-methodology-recon-to-report-workflow-and-automation.md)
  - [06 · Writing High-Quality Vulnerability Reports & Maximizing Payouts](src/content/docs/appsec-api-bugbounty/06-writing-high-quality-vulnerability-reports-and-maximizing-payouts.md)

### Red Team

- **Social Engineering**
  - [01 · The Human Attack Surface & the Psychology of Influence](src/content/docs/redteam-social-engineering/01-the-human-attack-surface-and-the-psychology-of-influence.md)
  - [02 · Social-Engineering Recon & Pretext Development](src/content/docs/redteam-social-engineering/02-social-engineering-recon-and-pretext-development.md)
  - [03 · Phishing Fundamentals: Pretexts, Lures & Payload Delivery](src/content/docs/redteam-social-engineering/03-phishing-fundamentals-pretexts-lures-and-payload-delivery.md)
  - [04 · Email Spoofing, SPF/DKIM/DMARC & Deliverability](src/content/docs/redteam-social-engineering/04-email-spoofing-spf-dkim-dmarc-and-deliverability.md)
  - [05 · Social-Engineer Toolkit (SET) & Credential Harvesters](src/content/docs/redteam-social-engineering/05-social-engineer-toolkit-set-and-credential-harvesters.md)
  - [06 · Gophish: Running a Full Phishing Campaign](src/content/docs/redteam-social-engineering/06-gophish-running-a-full-phishing-campaign.md)
  - [07 · Malicious Documents, Macros & Payload Pretexts](src/content/docs/redteam-social-engineering/07-malicious-documents-macros-and-payload-pretexts.md)
  - [08 · Evilginx & Adversary-in-the-Middle (AiTM) Phishing: Bypassing MFA](src/content/docs/redteam-social-engineering/08-evilginx-and-adversary-in-the-middle-aitm-phishing-bypassing-mfa.md)
  - [09 · Vishing, Smishing & Physical Pretexting](src/content/docs/redteam-social-engineering/09-vishing-smishing-and-physical-pretexting.md)
  - [10 · Deepfakes & AI-Driven Social Engineering](src/content/docs/redteam-social-engineering/10-deepfakes-and-ai-driven-social-engineering.md)
  - [11 · Defending Against Social Engineering & Security Awareness](src/content/docs/redteam-social-engineering/11-defending-against-social-engineering-and-security-awareness.md)
- **Malware & Evasion**
  - [01 · Malware Taxonomy: Trojans, RATs, Ransomware, Rootkits & Loaders](src/content/docs/redteam-malware-evasion/01-malware-taxonomy-trojans-rats-ransomware-rootkits-and-loaders.md)
  - [02 · Building Payloads & Droppers (Lab-Scoped)](src/content/docs/redteam-malware-evasion/02-building-payloads-and-droppers-lab-scoped.md)
  - [03 · Antivirus & EDR Evasion: Obfuscation, Packing & Encoding Concepts](src/content/docs/redteam-malware-evasion/03-antivirus-and-edr-evasion-obfuscation-packing-and-encoding-concepts.md)
  - [04 · AMSI Bypass & In-Memory Execution Concepts](src/content/docs/redteam-malware-evasion/04-amsi-bypass-and-in-memory-execution-concepts.md)
  - [05 · Process Injection, Hollowing & DLL Techniques (Conceptual)](src/content/docs/redteam-malware-evasion/05-process-injection-hollowing-and-dll-techniques-conceptual.md)
- **Operations**
  - [01 · Red Team vs Pentest: Objectives, OPSEC & Engagement Lifecycle](src/content/docs/redteam-operations/01-red-team-vs-pentest-objectives-opsec-and-engagement-lifecycle.md)
  - [02 · Command & Control (C2) Concepts & Beaconing](src/content/docs/redteam-operations/02-command-and-control-c2-concepts-and-beaconing.md)
  - [03 · Cobalt Strike Overview: Beacons, Malleable C2 & Listeners](src/content/docs/redteam-operations/03-cobalt-strike-overview-beacons-malleable-c2-and-listeners.md)
  - [04 · Open-Source C2: Sliver, Mythic, Havoc & Empire](src/content/docs/redteam-operations/04-open-source-c2-sliver-mythic-havoc-and-empire.md)
  - [05 · Red Team Infrastructure: Redirectors, Domains & OPSEC](src/content/docs/redteam-operations/05-red-team-infrastructure-redirectors-domains-and-opsec.md)
  - [06 · Initial Access: Phishing Infra, Payloads & Delivery](src/content/docs/redteam-operations/06-initial-access-phishing-infra-payloads-and-delivery.md)
  - [07 · Living-off-the-Land, EDR Evasion & OPSEC in Depth](src/content/docs/redteam-operations/07-living-off-the-land-edr-evasion-and-opsec-in-depth.md)
  - [08 · Full Adversary Emulation: Chaining the Kill Chain End to End](src/content/docs/redteam-operations/08-full-adversary-emulation-chaining-the-kill-chain-end-to-end.md)
  - [09 · Red Team Reporting, Attack Narratives & Deliverables](src/content/docs/redteam-operations/09-red-team-reporting-attack-narratives-and-deliverables.md)

### SOC & Blue Team

- **SOC Analyst**
  - [01 · Defensive Foundations: SOC Roles, Tiers & Defense-in-Depth](src/content/docs/blueteam-soc/01-defensive-foundations-soc-roles-tiers-and-defense-in-depth.md)
  - [02 · The Detection Mindset: Logs, Telemetry & Data Sources](src/content/docs/blueteam-soc/02-the-detection-mindset-logs-telemetry-and-data-sources.md)
  - [03 · The Cyber Kill Chain & MITRE ATT&CK for Analysts](src/content/docs/blueteam-soc/03-the-cyber-kill-chain-and-mitre-att-and-ck-for-analysts.md)
  - [04 · SIEM Fundamentals with Splunk: Searching & SPL](src/content/docs/blueteam-soc/04-siem-fundamentals-with-splunk-searching-and-spl.md)
  - [05 · Microsoft Sentinel & KQL for SOC Analysts](src/content/docs/blueteam-soc/05-microsoft-sentinel-and-kql-for-soc-analysts.md)
  - [06 · The Elastic Stack (ELK), Wazuh & Log Aggregation](src/content/docs/blueteam-soc/06-the-elastic-stack-elk-wazuh-and-log-aggregation.md)
  - [07 · Windows Event Log Analysis for Analysts](src/content/docs/blueteam-soc/07-windows-event-log-analysis-for-analysts.md)
  - [08 · Linux & Network Log Analysis for Analysts](src/content/docs/blueteam-soc/08-linux-and-network-log-analysis-for-analysts.md)
  - [09 · Email & Phishing Analysis for the SOC](src/content/docs/blueteam-soc/09-email-and-phishing-analysis-for-the-soc.md)
  - [10 · Network Security Monitoring: Zeek, Suricata, Snort & NIDS](src/content/docs/blueteam-soc/10-network-security-monitoring-zeek-suricata-snort-and-nids.md)
  - [11 · EDR Fundamentals & Endpoint Investigation](src/content/docs/blueteam-soc/11-edr-fundamentals-and-endpoint-investigation.md)
  - [12 · Alert Triage, Enrichment & Reducing False Positives](src/content/docs/blueteam-soc/12-alert-triage-enrichment-and-reducing-false-positives.md)
  - [13 · Incident Handling for Tier 1 & Tier 2 Analysts](src/content/docs/blueteam-soc/13-incident-handling-for-tier-1-and-tier-2-analysts.md)
- **Detection Engineering**
  - [01 · Detection Engineering with Sigma Rules](src/content/docs/blueteam-detection/01-detection-engineering-with-sigma-rules.md)
  - [02 · Endpoint Detection: Sysmon, Osquery & Velociraptor](src/content/docs/blueteam-detection/02-endpoint-detection-sysmon-osquery-and-velociraptor.md)
  - [03 · YARA: Writing Rules to Detect Malware](src/content/docs/blueteam-detection/03-yara-writing-rules-to-detect-malware.md)
  - [04 · Writing Splunk & KQL Detections for Real Attacks](src/content/docs/blueteam-detection/04-writing-splunk-and-kql-detections-for-real-attacks.md)
  - [05 · Mapping Detections to MITRE ATT&CK](src/content/docs/blueteam-detection/05-mapping-detections-to-mitre-att-and-ck.md)
  - [06 · SOC Automation & SOAR: Playbooks & Response](src/content/docs/blueteam-detection/06-soc-automation-and-soar-playbooks-and-response.md)
  - [07 · Building a Detection Lab & Testing Your Coverage](src/content/docs/blueteam-detection/07-building-a-detection-lab-and-testing-your-coverage.md)

### DFIR

- **DFIR**
  - [01 · Incident Response Lifecycle: Prepare, Detect, Contain, Eradicate, Recover](src/content/docs/dfir/01-incident-response-lifecycle-prepare-detect-contain-eradicate-recover.md)
  - [02 · Digital Forensics Fundamentals: Evidence, Chain of Custody & Imaging](src/content/docs/dfir/02-digital-forensics-fundamentals-evidence-chain-of-custody-and-imaging.md)
  - [03 · Disk Forensics: File Systems, Artifacts & Autopsy/Sleuth Kit](src/content/docs/dfir/03-disk-forensics-file-systems-artifacts-and-autopsy-sleuth-kit.md)
  - [04 · Memory Forensics with Volatility](src/content/docs/dfir/04-memory-forensics-with-volatility.md)
  - [05 · Windows Artifacts & Triage: Registry, MFT, KAPE & Eric Zimmerman Tools](src/content/docs/dfir/05-windows-artifacts-and-triage-registry-mft-kape-and-eric-zimmerman-tools.md)
  - [06 · Linux & Cloud Forensics](src/content/docs/dfir/06-linux-and-cloud-forensics.md)
  - [07 · Log-Based Investigation & Timeline Analysis](src/content/docs/dfir/07-log-based-investigation-and-timeline-analysis.md)
  - [08 · Ransomware & Breach Investigation Case Study](src/content/docs/dfir/08-ransomware-and-breach-investigation-case-study.md)

### Threat Intel & Hunting

- **Threat Intel & Hunting**
  - [01 · Cyber Threat Intelligence: Strategic, Operational & Tactical](src/content/docs/threat-intel-hunting/01-cyber-threat-intelligence-strategic-operational-and-tactical.md)
  - [02 · IOCs, IOAs, the Pyramid of Pain & the Diamond Model](src/content/docs/threat-intel-hunting/02-iocs-ioas-the-pyramid-of-pain-and-the-diamond-model.md)
  - [03 · Threat Actor Profiling, TTPs & Attribution](src/content/docs/threat-intel-hunting/03-threat-actor-profiling-ttps-and-attribution.md)
  - [04 · Threat Intel Platforms & Feeds: MISP, OpenCTI & STIX/TAXII](src/content/docs/threat-intel-hunting/04-threat-intel-platforms-and-feeds-misp-opencti-and-stix-taxii.md)
  - [05 · Threat Hunting Methodology & Hypothesis-Driven Hunting](src/content/docs/threat-intel-hunting/05-threat-hunting-methodology-and-hypothesis-driven-hunting.md)
  - [06 · Hunting Across Endpoint, Network & Identity Telemetry](src/content/docs/threat-intel-hunting/06-hunting-across-endpoint-network-and-identity-telemetry.md)

### Malware Analysis & RE

- **Malware Analysis & RE**
  - [01 · Malware Analysis Environment & Safe Handling](src/content/docs/malware-analysis-re/01-malware-analysis-environment-and-safe-handling.md)
  - [02 · Static Analysis: Strings, PE Headers, Imports (PEStudio, Detect It Easy)](src/content/docs/malware-analysis-re/02-static-analysis-strings-pe-headers-imports-pestudio-detect-it-easy.md)
  - [03 · Dynamic Analysis: Sandboxing & Sysinternals (Procmon, Process Explorer)](src/content/docs/malware-analysis-re/03-dynamic-analysis-sandboxing-and-sysinternals-procmon-process-explorer.md)
  - [04 · x86/x64 Assembly Crash Course for Analysts](src/content/docs/malware-analysis-re/04-x86-x64-assembly-crash-course-for-analysts.md)
  - [05 · Ghidra & radare2/Cutter: Reverse Engineering & Decompilation](src/content/docs/malware-analysis-re/05-ghidra-and-radare2-cutter-reverse-engineering-and-decompilation.md)
  - [06 · x64dbg & Debugging Windows Malware](src/content/docs/malware-analysis-re/06-x64dbg-and-debugging-windows-malware.md)
  - [07 · Unpacking, Deobfuscation & Anti-Analysis Tricks](src/content/docs/malware-analysis-re/07-unpacking-deobfuscation-and-anti-analysis-tricks.md)
  - [08 · Analyzing Real Malware: From Sample to Report](src/content/docs/malware-analysis-re/08-analyzing-real-malware-from-sample-to-report.md)

### Vulnerability Research

- **Binary Exploitation**
  - [01 · GDB, pwndbg & Debugging Native Binaries](src/content/docs/vuln-research-binexp/01-gdb-pwndbg-and-debugging-native-binaries.md)
  - [02 · Stack Buffer Overflows: From Crash to Working Exploit](src/content/docs/vuln-research-binexp/02-stack-buffer-overflows-from-crash-to-working-exploit.md)
  - [03 · Return-Oriented Programming (ROP) & Bypassing DEP/NX](src/content/docs/vuln-research-binexp/03-return-oriented-programming-rop-and-bypassing-dep-nx.md)
  - [04 · ASLR, Stack Canaries, PIE & Mitigation Bypasses](src/content/docs/vuln-research-binexp/04-aslr-stack-canaries-pie-and-mitigation-bypasses.md)
  - [05 · Format String Vulnerabilities](src/content/docs/vuln-research-binexp/05-format-string-vulnerabilities.md)
  - [06 · Heap Exploitation Fundamentals](src/content/docs/vuln-research-binexp/06-heap-exploitation-fundamentals.md)
  - [07 · Shellcoding & Position-Independent Payloads](src/content/docs/vuln-research-binexp/07-shellcoding-and-position-independent-payloads.md)
  - [08 · Fuzzing for Bugs: AFL++, libFuzzer & Crash Triage](src/content/docs/vuln-research-binexp/08-fuzzing-for-bugs-afl-libfuzzer-and-crash-triage.md)

### Cloud Security

- **Cloud Security**
  - [01 · Cloud Security Fundamentals: Shared Responsibility & Attack Surface](src/content/docs/cloud-security/01-cloud-security-fundamentals-shared-responsibility-and-attack-surface.md)
  - [02 · AWS Security & Recon: IAM, S3, EC2 & Metadata Attacks](src/content/docs/cloud-security/02-aws-security-and-recon-iam-s3-ec2-and-metadata-attacks.md)
  - [03 · Cloud Pentest Tooling: Pacu, ScoutSuite & Prowler](src/content/docs/cloud-security/03-cloud-pentest-tooling-pacu-scoutsuite-and-prowler.md)
  - [04 · Azure & Entra ID (Azure AD) Attacks](src/content/docs/cloud-security/04-azure-and-entra-id-azure-ad-attacks.md)
  - [05 · GCP Security Essentials & Enumeration](src/content/docs/cloud-security/05-gcp-security-essentials-and-enumeration.md)
  - [06 · Docker Security, Image Scanning (Trivy) & Container Breakouts](src/content/docs/cloud-security/06-docker-security-image-scanning-trivy-and-container-breakouts.md)
  - [07 · Kubernetes Attacks: RBAC, Pods, Secrets, kube-hunter & kube-bench](src/content/docs/cloud-security/07-kubernetes-attacks-rbac-pods-secrets-kube-hunter-and-kube-bench.md)
  - [08 · Serverless, CI/CD & Supply-Chain Attacks](src/content/docs/cloud-security/08-serverless-ci-cd-and-supply-chain-attacks.md)
  - [09 · Cloud Detection, Logging & Defensive Guardrails](src/content/docs/cloud-security/09-cloud-detection-logging-and-defensive-guardrails.md)

### Mobile & IoT

- **Mobile, IoT & Hardware**
  - [01 · Mobile App Security Fundamentals & the Android Architecture](src/content/docs/mobile-iot-hardware/01-mobile-app-security-fundamentals-and-the-android-architecture.md)
  - [02 · Android Pentest Setup: Emulator, adb, Burp & Traffic Interception](src/content/docs/mobile-iot-hardware/02-android-pentest-setup-emulator-adb-burp-and-traffic-interception.md)
  - [03 · Android Static Analysis: apktool, jadx & MobSF](src/content/docs/mobile-iot-hardware/03-android-static-analysis-apktool-jadx-and-mobsf.md)
  - [04 · Android Dynamic Analysis & Instrumentation: Frida & Objection](src/content/docs/mobile-iot-hardware/04-android-dynamic-analysis-and-instrumentation-frida-and-objection.md)
  - [05 · Bypassing Root Detection & SSL Pinning](src/content/docs/mobile-iot-hardware/05-bypassing-root-detection-and-ssl-pinning.md)
  - [06 · Android IPC: Deep Links, Intents & Exported Components](src/content/docs/mobile-iot-hardware/06-android-ipc-deep-links-intents-and-exported-components.md)
  - [07 · iOS Pentesting Fundamentals](src/content/docs/mobile-iot-hardware/07-ios-pentesting-fundamentals.md)
  - [08 · Mobile API & Backend Testing](src/content/docs/mobile-iot-hardware/08-mobile-api-and-backend-testing.md)
  - [09 · IoT & Firmware Analysis: Extraction, Emulation & Attacks](src/content/docs/mobile-iot-hardware/09-iot-and-firmware-analysis-extraction-emulation-and-attacks.md)
  - [10 · Hardware Hacking: UART, SPI, JTAG & Physical Interfaces](src/content/docs/mobile-iot-hardware/10-hardware-hacking-uart-spi-jtag-and-physical-interfaces.md)

### AI/ML Security

- **AI/ML Security**
  - [01 · AI/ML Security Landscape: Why It Matters Now](src/content/docs/ai-ml-security/01-ai-ml-security-landscape-why-it-matters-now.md)
  - [02 · Machine Learning & LLM Fundamentals for Security People](src/content/docs/ai-ml-security/02-machine-learning-and-llm-fundamentals-for-security-people.md)
  - [03 · Adversarial ML: Evasion, Poisoning & Model Extraction](src/content/docs/ai-ml-security/03-adversarial-ml-evasion-poisoning-and-model-extraction.md)
  - [04 · LLM Attacks: Prompt Injection, Jailbreaks & Data Leakage](src/content/docs/ai-ml-security/04-llm-attacks-prompt-injection-jailbreaks-and-data-leakage.md)
  - [05 · Securing AI Agents, RAG & Tool-Use Pipelines](src/content/docs/ai-ml-security/05-securing-ai-agents-rag-and-tool-use-pipelines.md)
  - [06 · The OWASP Top 10 for LLM Applications](src/content/docs/ai-ml-security/06-the-owasp-top-10-for-llm-applications.md)
  - [07 · AI Red-Teaming Tools: garak, PyRIT & Promptfoo](src/content/docs/ai-ml-security/07-ai-red-teaming-tools-garak-pyrit-and-promptfoo.md)
  - [08 · AI for Defense: ML-Driven Detection & Automation](src/content/docs/ai-ml-security/08-ai-for-defense-ml-driven-detection-and-automation.md)
  - [09 · Red-Teaming AI Systems: Methodology & Full Engagement](src/content/docs/ai-ml-security/09-red-teaming-ai-systems-methodology-and-full-engagement.md)

### Quantum Security

- **Quantum Security**
  - [01 · Quantum Computing Primer for Security Professionals](src/content/docs/quantum-security/01-quantum-computing-primer-for-security-professionals.md)
  - [02 · The Quantum Threat: Shor's & Grover's Algorithms Explained](src/content/docs/quantum-security/02-the-quantum-threat-shor-s-and-grover-s-algorithms-explained.md)
  - [03 · Harvest-Now-Decrypt-Later & Crypto-Agility Risk](src/content/docs/quantum-security/03-harvest-now-decrypt-later-and-crypto-agility-risk.md)
  - [04 · Post-Quantum Cryptography: Kyber, Dilithium & NIST Standards](src/content/docs/quantum-security/04-post-quantum-cryptography-kyber-dilithium-and-nist-standards.md)
  - [05 · Migrating to Post-Quantum: Planning & Real-World Rollout](src/content/docs/quantum-security/05-migrating-to-post-quantum-planning-and-real-world-rollout.md)

### Purple Team

- **Purple Team**
  - [01 · Purple Teaming: Bridging Offense & Defense](src/content/docs/purple-team/01-purple-teaming-bridging-offense-and-defense.md)
  - [02 · Adversary Emulation with Atomic Red Team & CALDERA](src/content/docs/purple-team/02-adversary-emulation-with-atomic-red-team-and-caldera.md)
  - [03 · Detection Validation & Closing Coverage Gaps](src/content/docs/purple-team/03-detection-validation-and-closing-coverage-gaps.md)
  - [04 · Running a Full Purple Team Exercise End to End](src/content/docs/purple-team/04-running-a-full-purple-team-exercise-end-to-end.md)

### GRC & Architecture

- **GRC & Architecture**
  - [01 · Governance, Risk & Compliance (GRC) Fundamentals](src/content/docs/grc-architecture/01-governance-risk-and-compliance-grc-fundamentals.md)
  - [02 · Security Frameworks & Standards: NIST CSF, ISO 27001, CIS, SOC 2](src/content/docs/grc-architecture/02-security-frameworks-and-standards-nist-csf-iso-27001-cis-soc-2.md)
  - [03 · Risk Assessment, Management & Quantification](src/content/docs/grc-architecture/03-risk-assessment-management-and-quantification.md)
  - [04 · Security Architecture & Zero-Trust Design](src/content/docs/grc-architecture/04-security-architecture-and-zero-trust-design.md)
  - [05 · Identity & Access Management (IAM) at Enterprise Scale](src/content/docs/grc-architecture/05-identity-and-access-management-iam-at-enterprise-scale.md)
  - [06 · Privacy, Data Protection & Regulations (GDPR, HIPAA, PCI-DSS)](src/content/docs/grc-architecture/06-privacy-data-protection-and-regulations-gdpr-hipaa-pci-dss.md)

### Career

- **CTF & Wargames**
  - [01 · CTF 101: Formats, Platforms, Scoring & How to Practice](src/content/docs/ctf-wargames/01-ctf-101-formats-platforms-scoring-and-how-to-practice.md)
  - [02 · Web Exploitation CTF Challenges: Patterns, Tricks & Tooling](src/content/docs/ctf-wargames/02-web-exploitation-ctf-challenges-patterns-tricks-and-tooling.md)
  - [03 · Cryptography CTF Challenges: Classic to Modern Attacks](src/content/docs/ctf-wargames/03-cryptography-ctf-challenges-classic-to-modern-attacks.md)
  - [04 · Forensics & Steganography CTF Challenges](src/content/docs/ctf-wargames/04-forensics-and-steganography-ctf-challenges.md)
  - [05 · OSINT CTF Challenges: Finding the Needle](src/content/docs/ctf-wargames/05-osint-ctf-challenges-finding-the-needle.md)
  - [06 · Reverse Engineering CTF Challenges](src/content/docs/ctf-wargames/06-reverse-engineering-ctf-challenges.md)
  - [07 · Binary Exploitation (Pwn) CTF Challenges](src/content/docs/ctf-wargames/07-binary-exploitation-pwn-ctf-challenges.md)
  - [08 · Building a CTF Workflow, Toolkit & Team Strategy](src/content/docs/ctf-wargames/08-building-a-ctf-workflow-toolkit-and-team-strategy.md)
- **Career**
  - [01 · Choosing Your Path: Mapping Fields to Real Job Roles](src/content/docs/career-mastery/01-choosing-your-path-mapping-fields-to-real-job-roles.md)
  - [02 · Certification Roadmaps: OSCP, PNPT, CRTP/CRTO, eJPT, Security+, CISSP & More](src/content/docs/career-mastery/02-certification-roadmaps-oscp-pnpt-crtp-crto-ejpt-security-cissp-and-more.md)
  - [03 · Building a Portfolio, Home Lab & CTF Practice Plan](src/content/docs/career-mastery/03-building-a-portfolio-home-lab-and-ctf-practice-plan.md)
  - [04 · Resume, Interviews & Landing a FAANG-Level Security Role](src/content/docs/career-mastery/04-resume-interviews-and-landing-a-faang-level-security-role.md)
  - [05 · Staying Current: Research, Community & Lifelong Learning](src/content/docs/career-mastery/05-staying-current-research-community-and-lifelong-learning.md)

### Product Security

- **Product Security Foundations**
  - [01 · The Product Security Engineer Role: Scope, Responsibilities & Career Path](src/content/docs/product-security-foundations/01-the-product-security-engineer-role-scope-responsibilities-and-career-path.md)
  - [02 · Secure Software Development Lifecycle (S-SDLC), Shift-Left & Security Gates](src/content/docs/product-security-foundations/02-secure-software-development-lifecycle-s-sdlc-shift-left-and-security-gates.md)
  - [03 · Threat Modeling for Products: PASTA, Data Flow Diagrams & Design-Level Risk](src/content/docs/product-security-foundations/03-threat-modeling-for-products-pasta-data-flow-diagrams-and-design-level-risk.md)
  - [04 · Conducting Security Design Reviews: Architecture, Data Flow & Trust Boundaries](src/content/docs/product-security-foundations/04-conducting-security-design-reviews-architecture-data-flow-and-trust-boundaries.md)
  - [05 · Threat Modeling Tools & Automation: OWASP Threat Dragon, Microsoft TMT & IriusRisk](src/content/docs/product-security-foundations/05-threat-modeling-tools-and-automation-owasp-threat-dragon-microsoft-tmt-and-iriusrisk.md)
  - [06 · Secure Coding Principles: OWASP Guidelines, Input Validation & Defense in Depth](src/content/docs/product-security-foundations/06-secure-coding-principles-owasp-guidelines-input-validation-and-defense-in-depth.md)
  - [07 · Language-Specific Secure Coding: Python, JavaScript, Java, Go & C/C++ Patterns](src/content/docs/product-security-foundations/07-language-specific-secure-coding-python-javascript-java-go-and-c-cpp-patterns.md)
  - [08 · Common Vulnerability Patterns in Source Code: CWE Top 25 Deep Dive](src/content/docs/product-security-foundations/08-common-vulnerability-patterns-in-source-code-cwe-top-25-deep-dive.md)
- **Secure Code Review**
  - [01 · Secure Code Review Fundamentals: Methodology, Checklists & Prioritization](src/content/docs/secure-code-review-sast-sca/01-secure-code-review-fundamentals-methodology-checklists-and-prioritization.md)
  - [02 · Manual Secure Code Review: Reading Code for Injection, Auth & Logic Flaws](src/content/docs/secure-code-review-sast-sca/02-manual-secure-code-review-reading-code-for-injection-auth-and-logic-flaws.md)
  - [03 · SAST Deep Dive: Semgrep, SonarQube & CodeQL for Automated Code Analysis](src/content/docs/secure-code-review-sast-sca/03-sast-deep-dive-semgrep-sonarqube-and-codeql-for-automated-code-analysis.md)
  - [04 · DAST & IAST in the SDLC: Runtime Scanning & Feedback Loops](src/content/docs/secure-code-review-sast-sca/04-dast-and-iast-in-the-sdlc-runtime-scanning-and-feedback-loops.md)
  - [05 · Software Composition Analysis: Snyk, Dependabot, SBOM & Supply-Chain Risk](src/content/docs/secure-code-review-sast-sca/05-software-composition-analysis-snyk-dependabot-sbom-and-supply-chain-risk.md)
  - [06 · Secrets Detection & Credential Scanning: GitLeaks, TruffleHog & Pre-Commit Hooks](src/content/docs/secure-code-review-sast-sca/06-secrets-detection-and-credential-scanning-gitleaks-trufflehog-and-pre-commit-hooks.md)
  - [07 · Integrating Security into CI/CD Pipelines: GitHub Actions, GitLab CI & Jenkins](src/content/docs/secure-code-review-sast-sca/07-integrating-security-into-ci-cd-pipelines-github-actions-gitlab-ci-and-jenkins.md)
  - [08 · Container & IaC Security Scanning: Trivy, Checkov, tfsec & Policy-as-Code](src/content/docs/secure-code-review-sast-sca/08-container-and-iac-security-scanning-trivy-checkov-tfsec-and-policy-as-code.md)
  - [09 · Vulnerability Management & SLA-Driven Remediation Workflows](src/content/docs/secure-code-review-sast-sca/09-vulnerability-management-and-sla-driven-remediation-workflows.md)
- **Security Program**
  - [01 · Building a Product Security Program: Vision, Maturity Models & Metrics](src/content/docs/product-security-program/01-building-a-product-security-program-vision-maturity-models-and-metrics.md)
  - [02 · Security Champions: Scaling Security Through Engineering Teams](src/content/docs/product-security-program/02-security-champions-scaling-security-through-engineering-teams.md)
  - [03 · Bug Bounty & Responsible Disclosure Program Management](src/content/docs/product-security-program/03-bug-bounty-and-responsible-disclosure-program-management.md)
  - [04 · Third-Party & Vendor Security Assessments](src/content/docs/product-security-program/04-third-party-and-vendor-security-assessments.md)
  - [05 · Privacy Engineering & Data Protection by Design (GDPR, CCPA in Code)](src/content/docs/product-security-program/05-privacy-engineering-and-data-protection-by-design-gdpr-ccpa-in-code.md)
  - [06 · Security Metrics, Dashboards & Communicating Risk to Leadership](src/content/docs/product-security-program/06-security-metrics-dashboards-and-communicating-risk-to-leadership.md)
  - [07 · Product Security Capstone: Full S-SDLC Engagement from Design to Deployment](src/content/docs/product-security-program/07-product-security-capstone-full-s-sdlc-engagement-from-design-to-deployment.md)

## License

The notes are licensed [CC BY-NC-SA 4.0](LICENSE). You can share and adapt them for non-commercial use, with credit and under the same license.
