# Computer System Security: Offensive Techniques & System Hardening

This repository compiles a series of labs and reports from my Computer System Security course, demonstrating a practical understanding of vulnerability exploitation, penetration testing methodologies, and robust system hardening strategies. The projects highlight hands-on experience with industry-standard tools and a deep dive into real-world cybersecurity scenarios.

## Labs & Projects Overview:

Each component within this repository represents a significant learning outcome, covering various facets of system security:

### 1. Reconnaissance (OSINT & Network Scanning)
* **Target Identification:** Initiated information gathering on a real-world target (school website) using **Google Dorking** to uncover publicly available sensitive information (principal's contact, email, internal documents).
* **Domain Analysis:** Utilized `builtwith.com` to analyze the target's web technologies and identify related domains, revealing shared infrastructure.
* **Network Footprinting (Shodan):** Employed **Shodan** to discover open ports and services, identify administrative panels (cPanel), and uncover running web servers (Tomcat) on the target's IP address.
* **Social Engineering Pre-computation:** Formulated potential social engineering attacks based on gathered OSINT for targeted phishing.

### 2. Vulnerability Exploitation (Metasploit & SUID)
* **RPC Buffer Overflow (Metasploit):**
    * **Vulnerability Identification:** Searched for and selected the `ms03_026_dcom` exploit for a Microsoft RPC DCOM Interface Overflow.
    * **Payload Deployment:** Utilized both `windows/meterpreter/reverse_tcp` (for firewall evasion) and `windows/shell/bind_tcp` payloads to establish command and meterpreter sessions on a vulnerable Windows XP machine.
    * **Post-Exploitation:** Demonstrated successful remote command execution and file access (`hi.txt`) on the exploited system.
* **SUID Exploitation (Linux Privilege Escalation):**
    * **Vulnerability Concept:** Explored CVE-2023-0386 and the general concept of exploiting SUID (Set User ID) binaries in Linux.
    * **Vulnerable Binary Identification:** Used `find` to locate SUID binaries on a CentOS 7 system (`/usr/bin/zsh`).
    * **Privilege Escalation:** Successfully exploited the SUID bit on `zsh` to elevate privileges to `root` and access the `/etc/shadow` file, demonstrating a critical privilege escalation vector.
    * **Mitigation Strategies:** Understood the importance of properly configuring SUID permissions.

### 3. Remote Access & File Transfer (SOCAT)
* **Reverse Shell Establishment:** Utilized **SOCAT** to establish a reverse shell connection from a victim machine back to an attacker's machine, bypassing common firewall restrictions.
* **Bidirectional File Transfer:** Explored SOCAT's capabilities as a versatile bidirectional data relay tool, similar to `netcat` but with advanced features like multiplexing.
* **Victim System Interaction:** Demonstrated remote command execution (`ls`, `ifconfig`, `netstat`) on the compromised victim shell.

### 4. Sandbox Environment Design (Report)
* **Problem Statement:** Articulated the challenges faced by organizations in deploying new technologies without disrupting production systems, citing a real-world incident of system downtime due to incompatible software updates.
* **Importance of Sandboxing:** Justified the critical need for a dedicated sandbox environment for safe testing and validation of new hardware, software, and configurations.
* **Proposed Solution:** Outlined a comprehensive plan for building a sandbox, including virtual environments, mimicked infrastructure, automation tools, and a dedicated testing team.
* **Cost Estimation:** Provided a detailed cost breakdown for establishing and maintaining such an environment.

### 5. Vulnerability Research & Analysis (Exploit-DB & Book Review)
* **Exploit Analysis (Exploit-DB Choice):**
    * **Real-world Vulnerabilities:** Analyzed publicly disclosed vulnerabilities (CVE-2023-0386, others related to remote access) in a popular remote login provider, **TPlus**.
    * **Insecure Configurations:** Identified specific insecure files, folders, and cleartext credential storage within the TPlus web server, demonstrating common misconfigurations.
* **Web Application Security (Book Review):**
    * **"The Web Application Hacker's Handbook":** Provided a comprehensive review of this seminal book, highlighting its value for bug bounty hunters and web application security professionals.
    * **Core Concepts:** Summarized key web application vulnerabilities (authentication attacks, session management, XSS, CSRF, input validation, path traversal) and defensive mechanisms.
    * **Attacker Methodologies:** Explored the importance of understanding application architecture, access control, and using hacker toolkits.

### 6. Case Study Analysis (Solon's Case Study)
* **Digital Forensics in Legal Context:** Analyzed the "United States vs. Solon (2010)" case, focusing on the role and challenges of digital forensics in a legal battle.
* **Contradictory Evidence:** Discussed the conflicting arguments presented by the prosecution and defense regarding child pornography evidence and system compromise by malware.
* **Forensic Investigation Challenges:** Highlighted aspects like the financial burden of forensic experts, the impact of anti-forensic techniques, and the importance of thorough analysis.
* **Ethical and Procedural Issues:** Reflected on judicial conduct and the potential for bias or procedural errors to influence case outcomes, emphasizing the need for robust forensic practices.

## Key Skills Demonstrated:

* **Vulnerability Assessment & Exploitation:** Practical application of tools and techniques to identify and exploit software vulnerabilities.
* **System Administration & Hardening:** Understanding of secure system configurations and defensive measures.
* **Network Security:** Concepts of secure remote access, shell connections, and traffic manipulation.
* **Open-Source Intelligence (OSINT):** Skills in gathering and analyzing public information for reconnaissance.
* **Incident Response Planning:** Insight into the importance of preparatory measures for cybersecurity incidents.
* **Analytical Thinking:** Ability to dissect complex security problems, analyze technical details, and draw informed conclusions.
* **Technical Writing:** Clear and concise documentation of lab procedures, findings, and analysis.
* **Ethical Hacking Mindset:** Approaching security challenges from an attacker's perspective to better understand and mitigate risks.

This repository serves as a testament to my dedication and growing expertise in the dynamic field of computer system security.
