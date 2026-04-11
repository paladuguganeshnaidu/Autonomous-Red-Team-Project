# Autonomous Red Team Report

**Target:** `toriiminds.com`  
**Date:** 2026-04-11 18:27:16  
**Run ID:** `4d7ae929802f466396d641a8d6f2e79a`  
**Total iterations:** 4

## Final Intelligence Summary

Autonomous AI recon completed for toriiminds.com across 4 iterations.

- Overall risk: **medium**
- Confidence: **medium**

### Attack Surface

- Primary target: toriiminds.com
- Open port 22 (ssh)
- Open port 80 (http)
- Open port 443 (ssl/http)
- Web endpoint: http://toriiminds.com
- Web endpoint: https://toriiminds.com
- Web endpoint: http://toriiminds.com/FUZZ
- Discovered host: frs.toriiminds.com
- Discovered host: www.toriiminds.com

### High Value Findings

- Initial target: toriiminds.com
- Seeded URLs: http://toriiminds.com, https://toriiminds.com
- Discovered subdomain: frs.toriiminds.com
- Discovered subdomain: www.toriiminds.com
- Open TCP port 22 running ssh.
- Open TCP port 80 running http.
- Open TCP port 443 running ssl/http.

### Risk Signals

- nuclei returned exit code 1.
- LLM bypass active after an earlier transport failure.
- nmap command timed out; visibility may be incomplete.
- nmap returned exit code -1.

### Recommended Next Steps

- Validate high-confidence findings with targeted manual checks.
- Prioritize internet-facing assets and sensitive endpoints first.
- Run authenticated validation for confirmed candidates where in scope.

## Vulnerability Candidates

### V1: Sensitive service exposed on port 22
- Severity: **medium**
- Asset: toriiminds.com
- Source: nmap
- Evidence: TCP 22/ssh reported open by nmap.
- Recommendation: Validate service exposure and restrict access if unnecessary.

## Iteration Attack Chain

| Iter | Goal | Tools | Commands | Failures |
|------|------|-------|----------|----------|
| 1 | AI fallback recon expansion for iteration 1. | nmap, nuclei, subfinder | 3 | 1 |
| 2 | AI fallback recon expansion for iteration 2. | ffuf, nmap, nuclei | 3 | 1 |
| 3 | AI fallback recon expansion for iteration 3. | ffuf, nmap, nuclei | 3 | 2 |
| 4 | AI fallback recon expansion for iteration 4. | ffuf, nuclei, subfinder | 3 | 1 |

## Iteration Details

### Iteration 1
**Goal:** AI fallback recon expansion for iteration 1.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete. LLM issue: HTTPConnectionPool(host='localhost', port=11434): Read timed out. (read timeout=240)

**Analysis summary:** Iteration 1 produced 5 findings, 1 vulnerability candidates, and 1 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Key findings:**
- Discovered subdomain: frs.toriiminds.com
- Discovered subdomain: www.toriiminds.com
- Open TCP port 22 running ssh.
- Open TCP port 80 running http.
- Open TCP port 443 running ssl/http.

**Risk signals:**
- nuclei returned exit code 1.
- LLM bypass active after an earlier transport failure.

**Vulnerability candidates from this iteration:**
- [medium] Sensitive service exposed on port 22 @ toriiminds.com

#### Command 1: SUBFINDER
- Objective: Enumerate subdomains to expand attack surface.
- Timeout: 120
- Exit code: 0
- Timed out: False
- Duration sec: 33.49
- Command: `"C:\Users\ganes\go\bin\subfinder.exe" -d toriiminds.com -silent`

```
frs.toriiminds.com
www.toriiminds.com

```

#### Command 2: NMAP
- Objective: Map exposed ports and service versions.
- Timeout: 180
- Exit code: 0
- Timed out: False
- Duration sec: 20.26
- Command: `"C:\Users\ganes\nmap.exe" -sV -Pn -p 80,443,8080,8443,21,22,25,3306,3389 toriiminds.com`

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-11 18:13 +0530
Nmap scan report for toriiminds.com (98.130.140.62)
Host is up (0.11s latency).
Other addresses for toriiminds.com (not scanned): 64:ff9b::6282:8c3e
rDNS record for 98.130.140.62: ec2-98-130-140-62.ap-south-2.compute.amazonaws.com

PORT     STATE    SERVICE       VERSION
21/tcp   filtered ftp
22/tcp   open     ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
25/tcp   filtered smtp
80/tcp   open     http          nginx 1.24.0 (Ubuntu)
443/tcp  open     ssl/http      nginx 1.24.0 (Ubuntu)
3306/tcp filtered mysql
3389/tcp filtered ms-wbt-server
8080/tcp filtered http-proxy
8443/tcp filtered https-alt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.87 seconds

```

#### Command 3: NUCLEI
- Objective: Run quick vulnerability template checks on the primary endpoint.
- Timeout: 180
- Exit code: 1
- Timed out: False
- Duration sec: 22.7
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://toriiminds.com -severity critical,high,medium -silent`

```
Access is denied.

```

### Iteration 2
**Goal:** AI fallback recon expansion for iteration 2.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete. LLM issue: LLM bypass active after an earlier transport failure.

**Analysis summary:** Iteration 2 produced 3 findings, 1 vulnerability candidates, and 1 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Key findings:**
- Open TCP port 22 running ssh.
- Open TCP port 80 running http.
- Open TCP port 443 running ssl/http.

**Risk signals:**
- nuclei returned exit code 1.
- LLM bypass active after an earlier transport failure.

**Vulnerability candidates from this iteration:**
- [medium] Sensitive service exposed on port 22 @ toriiminds.com

#### Command 1: FFUF
- Objective: Discover hidden endpoints and sensitive paths quickly.
- Timeout: 180
- Exit code: 0
- Timed out: False
- Duration sec: 34.82
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://toriiminds.com/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 120`

```


?wsdl                   [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 37ms]


?view=log               [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 54ms]


                        [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 35ms]

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://toriiminds.com/FUZZ
 :: Wordlist         : FUZZ: C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________



:: Progress: [2/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [40/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [40/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [83/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [175/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [239/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [321/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [431/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [495/26468] :: Job [1/1] :: 666 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [606/26468] :: Job [1/1] :: 735 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [686/26468] :: Job [1/1] :: 840 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [766/26468] :: Job [1/1] :: 790 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [849/26468] :: Job [1/1] :: 660 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [945/26468] :: Job [1/1] :: 664 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [1029/26468] :: Job [1/1] :: 800 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [1119/26468] :: Job [1/1] :: 701 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [1211/26468] :: Job [1/1] :: 763 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1287/26468] :: Job [1/1] :: 701 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1401/26468] :: Job [1/1] :: 819 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1428/26468] :: Job [1/1] :: 687 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1509/26468] :: Job [1/1] :: 555 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1600/26468] :: Job [1/1] :: 729 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1705/26468] :: Job [1/1] :: 813 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1807/26468] :: Job [1/1] :: 865 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1902/26468] :: Job [1/1] :: 829 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [1974/26468] :: Job [1/1] :: 826 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2035/26468] :: Job [1/1] :: 558 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2136/26468] :: Job [1/1] :: 574 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2249/26468] :: Job [1/1] :: 806 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2337/26468] :: Job [1/1] :: 778 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2453/26468] :: Job [1/1] :: 881 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2537/26468] :: Job [1/1] :: 836 req/sec :: Duration: [
... [truncated]
```

#### Command 2: NUCLEI
- Objective: Correlate path discovery with known vulnerability signatures.
- Timeout: 180
- Exit code: 1
- Timed out: False
- Duration sec: 61.31
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://toriiminds.com -severity critical,high,medium -silent`

```
Access is denied.

```

#### Command 3: NMAP
- Objective: Re-validate active service versions on discovered ports.
- Timeout: 180
- Exit code: 0
- Timed out: False
- Duration sec: 15.01
- Command: `"C:\Users\ganes\nmap.exe" -sV -Pn -p 22,80,443 toriiminds.com`

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-11 18:16 +0530
Nmap scan report for toriiminds.com (98.130.140.62)
Host is up (0.030s latency).
Other addresses for toriiminds.com (not scanned): 64:ff9b::6282:8c3e
rDNS record for 98.130.140.62: ec2-98-130-140-62.ap-south-2.compute.amazonaws.com

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.77 seconds

```

### Iteration 3
**Goal:** AI fallback recon expansion for iteration 3.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete. LLM issue: LLM bypass active after an earlier transport failure.

**Analysis summary:** Iteration 3 produced 3 findings, 1 vulnerability candidates, and 3 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Key findings:**
- Open TCP port 22 running ssh.
- Open TCP port 80 running http.
- Open TCP port 443 running ssl/http.

**Risk signals:**
- nmap command timed out; visibility may be incomplete.
- nmap returned exit code -1.
- nuclei returned exit code 1.
- LLM bypass active after an earlier transport failure.

**Vulnerability candidates from this iteration:**
- [medium] Sensitive service exposed on port 22 @ toriiminds.com

#### Command 1: NMAP
- Objective: Run targeted service-level vulnerability scripts.
- Timeout: 240
- Exit code: -1
- Timed out: True
- Duration sec: 327.35
- Command: `"C:\Users\ganes\nmap.exe" -Pn -sV --script vuln -p 22,80,443 toriiminds.com`

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-11 18:16 +0530
Nmap scan report for toriiminds.com (98.130.140.62)
Host is up (0.12s latency).
Other addresses for toriiminds.com (not scanned): 64:ff9b::6282:8c3e
rDNS record for 98.130.140.62: ec2-98-130-140-62.ap-south-2.compute.amazonaws.com

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:9.6p1: 
|     	PACKETSTORM:179290	10.0	https://vulners.com/packetstorm/PACKETSTORM:179290	*EXPLOIT*
|     	1EEC8894-D2F7-547C-827C-915BE866875C	10.0	https://vulners.com/githubexploit/1EEC8894-D2F7-547C-827C-915BE866875C	*EXPLOIT*
|     	09B905C6-CD97-54E6-AD97-B0DD1AC4771B	10.0	https://vulners.com/githubexploit/09B905C6-CD97-54E6-AD97-B0DD1AC4771B	*EXPLOIT*
|     	33D623F7-98E0-5F75-80FA-81AA666D1340	9.8	https://vulners.com/githubexploit/33D623F7-98E0-5F75-80FA-81AA666D1340	*EXPLOIT*
|     	F8981437-1287-5B69-93F1-657DFB1DCE59	9.3	https://vulners.com/githubexploit/F8981437-1287-5B69-93F1-657DFB1DCE59	*EXPLOIT*
|     	CB2926E1-2355-5C82-A42A-D4F72F114F9B	9.3	https://vulners.com/githubexploit/CB2926E1-2355-5C82-A42A-D4F72F114F9B	*EXPLOIT*
|     	B6C4923E-8565-5D3E-8E68-8D182C3DAD5C	9.3	https://vulners.com/githubexploit/B6C4923E-8565-5D3E-8E68-8D182C3DAD5C	*EXPLOIT*
|     	8DEE261C-33D4-5057-BA46-E4293B705BAE	9.3	https://vulners.com/githubexploit/8DEE261C-33D4-5057-BA46-E4293B705BAE	*EXPLOIT*
|     	6FD8F914-B663-533D-8866-23313FD37804	9.3	https://vulners.com/githubexploit/6FD8F914-B663-533D-8866-23313FD37804	*EXPLOIT*
|     	PACKETSTORM:190587	8.1	https://vulners.com/packetstorm/PACKETSTORM:190587	*EXPLOIT*
|     	FB2E9ED1-43D7-585C-A197-0D6628B20134	8.1	https://vulners.com/githubexploit/FB2E9ED1-43D7-585C-A197-0D6628B20134	*EXPLOIT*
|     	FA3992CE-9C4C-5350-8134-177126E0BD3F	8.1	https://vulners.com/githubexploit/FA3992CE-9C4C-5350-8134-177126E0BD3F	*EXPLOIT*
|     	EFD615F0-8F17-5471-AA83-0F491FD497AF	8.1	https://vulners.com/githubexploit/EFD615F0-8F17-5471-AA83-0F491FD497AF	*EXPLOIT*
|     	EC20B9C2-6857-5848-848A-A9F430D13EEB	8.1	https://vulners.com/githubexploit/EC20B9C2-6857-5848-848A-A9F430D13EEB	*EXPLOIT*
|     	EB13CBD6-BC93-5F14-A210-AC0B5A1D8572	8.1	https://vulners.com/githubexploit/EB13CBD6-BC93-5F14-A210-AC0B5A1D8572	*EXPLOIT*
|     	E543E274-C20A-582A-8F8E-F8E3F381C345	8.1	https://vulners.com/githubexploit/E543E274-C20A-582A-8F8E-F8E3F381C345	*EXPLOIT*
|     	E34FCCEC-226E-5A46-9B1C-BCD6EF7D3257	8.1	https://vulners.com/githubexploit/E34FCCEC-226E-5A46-9B1C-BCD6EF7D3257	*EXPLOIT*
|     	E24EEC0A-40F7-5BBC-9E4D-7B13522FF915	8.1	https://vulners.com/githubexploit/E24EEC0A-40F7-5BBC-9E4D-7B13522FF915	*EXPLOIT*
|     	DC1BB99A-8B57-5EE5-9AC4-3D9D59BFC346	8.1	https://vulners.com/githubexploit/DC1BB99A-8B57-5EE5-9AC4-3D9D59BFC346	*EXPLOIT*
|     	DA18D761-BB81-54B6-85CB-CFD73CE33621	8.1	https://vulners.com/githubexploit/DA18D761-BB81-54B6-85CB-CFD73CE33621	*EXPLOIT*
|     	D52370EF-02EE-507D-9212-2D8EA86CBA94	8.1	https://vulners.com/githubexploit/D52370EF-02EE-507D-9212-2D8EA86CBA94	*EXPLOIT*
|     	CVE-2026-35414	8.1	https://vulners.com/cve/CVE-2026-35414
|     	CVE-2024-6387	8.1	https://vulners.com/cve/CVE-2024-6387
|     	CFEBF7AF-651A-5302-80B8-F8146D5B33A6	8.1	https://vulners.com/githubexploit/CFEBF7AF-651A-5302-80B8-F8146D5B33A6	*EXPLOIT*
|     	C6FB6D50-F71D-5870-B671-D6A09A95627F	8.1	https://vulners.com/githubexploit/C6FB6D50-F71D-5870-B671-D6A09A95627F	*EXPLOIT*
|     	C623D558-C162-5D17-88A5-4799A2BEC001	8.1	https://vulners.com/githubexploit/C623D558-C162-5D17-88A5-4799A2BEC001	*EXPLOIT*
|     	C5B2D4A1-8C3B-5FF7-B620-EDE207B027A0	8.1	https://vulners.com/githubexploit/C5B2D4A1-8C3B-5FF7-B620-EDE207B027A0	*EXPLOIT*
|     	C185263E-3E67-5550-B9C0-AB9C15351960	8.1	https://vulners.com/githubexploit/C185263E-3E67-5550-B9C0-AB9C15351960	*EXPLOIT*
|     	BDA609DA-6936-50DC-A325-19FE2CC68562	8.1	https://vulners.com/githubexploit/BDA609DA-6936-50DC-A325-19FE2CC68562	*EXPLOIT*

... [truncated]
```

#### Command 2: FFUF
- Objective: Run deeper endpoint discovery for missed attack paths.
- Timeout: 240
- Exit code: 0
- Timed out: False
- Duration sec: 132.31
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://toriiminds.com/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 180`

```


/#.htaccess#            [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 40ms]


///evil.com/%2F..       [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 37ms]


//evil.com/%2F..        [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 46ms]

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://toriiminds.com/FUZZ
 :: Wordlist         : FUZZ: C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________



:: Progress: [1/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [44/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [131/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [212/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [252/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [292/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [372/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [412/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [466/90821] :: Job [1/1] :: 452 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [559/90821] :: Job [1/1] :: 468 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [623/90821] :: Job [1/1] :: 722 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [663/90821] :: Job [1/1] :: 546 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [745/90821] :: Job [1/1] :: 485 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [827/90821] :: Job [1/1] :: 719 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [840/90821] :: Job [1/1] :: 682 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [895/90821] :: Job [1/1] :: 498 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [965/90821] :: Job [1/1] :: 433 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1045/90821] :: Job [1/1] :: 558 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1068/90821] :: Job [1/1] :: 503 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1133/90821] :: Job [1/1] :: 493 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1218/90821] :: Job [1/1] :: 491 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1295/90821] :: Job [1/1] :: 589 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1385/90821] :: Job [1/1] :: 692 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1478/90821] :: Job [1/1] :: 787 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1580/90821] :: Job [1/1] :: 843 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [1671/90821] :: Job [1/1] :: 729 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [1742/90821] :: Job [1/1] :: 671 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [1853/90821] :: Job [1/1] :: 760 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [1933/90821] :: Job [1/1] :: 749 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2017/90821] :: Job [1/1] :: 687 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2134/90821] :: Job [1/1] :: 865 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2182/90821] :: Job [1/1] :: 714 req/sec :: Duration: [0:00:0
... [truncated]
```

#### Command 3: NUCLEI
- Objective: Perform broader template checks on the highest-priority endpoint.
- Timeout: 240
- Exit code: 1
- Timed out: False
- Duration sec: 103.27
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://toriiminds.com -silent -severity critical,high,medium`

```
Access is denied.

```

### Iteration 4
**Goal:** AI fallback recon expansion for iteration 4.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete. LLM issue: LLM bypass active after an earlier transport failure.

**Analysis summary:** Iteration 4 produced 2 findings, 0 vulnerability candidates, and 1 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Key findings:**
- Discovered subdomain: frs.toriiminds.com
- Discovered subdomain: www.toriiminds.com

**Risk signals:**
- nuclei returned exit code 1.
- LLM bypass active after an earlier transport failure.

#### Command 1: NUCLEI
- Objective: Confirm and expand final vulnerability evidence.
- Timeout: 240
- Exit code: 1
- Timed out: False
- Duration sec: 2.67
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://toriiminds.com -severity critical,high,medium,low -silent`

```
Access is denied.

```

#### Command 2: FFUF
- Objective: Re-check for high-signal hidden paths with bounded runtime.
- Timeout: 150
- Exit code: 0
- Timed out: False
- Duration sec: 45.81
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://toriiminds.com/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 90`

```


?wsdl                   [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 72ms]


?view=log               [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 60ms]


                        [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 44ms]

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://toriiminds.com/FUZZ
 :: Wordlist         : FUZZ: C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________



:: Progress: [1/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [40/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [59/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [171/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [238/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [349/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [457/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [572/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [689/26468] :: Job [1/1] :: 1030 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [788/26468] :: Job [1/1] :: 865 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [886/26468] :: Job [1/1] :: 829 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [969/26468] :: Job [1/1] :: 706 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [1069/26468] :: Job [1/1] :: 847 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [1176/26468] :: Job [1/1] :: 888 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [1272/26468] :: Job [1/1] :: 843 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [1377/26468] :: Job [1/1] :: 938 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

:: Progress: [1457/26468] :: Job [1/1] :: 781 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1564/26468] :: Job [1/1] :: 709 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1676/26468] :: Job [1/1] :: 943 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1769/26468] :: Job [1/1] :: 865 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1852/26468] :: Job [1/1] :: 833 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [1949/26468] :: Job [1/1] :: 766 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [2038/26468] :: Job [1/1] :: 816 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [2149/26468] :: Job [1/1] :: 775 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

:: Progress: [2244/26468] :: Job [1/1] :: 862 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2345/26468] :: Job [1/1] :: 809 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2417/26468] :: Job [1/1] :: 714 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2503/26468] :: Job [1/1] :: 701 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2593/26468] :: Job [1/1] :: 790 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2696/26468] :: Job [1/1] :: 816 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2781/26468] :: Job [1/1] :: 778 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

:: Progress: [2869/26468] :: Job [1/1] :: 829 req/sec :: Duratio
... [truncated]
```

#### Command 3: SUBFINDER
- Objective: Final subdomain sweep for completeness.
- Timeout: 120
- Exit code: 0
- Timed out: False
- Duration sec: 30.96
- Command: `"C:\Users\ganes\go\bin\subfinder.exe" -d toriiminds.com -silent`

```
frs.toriiminds.com
www.toriiminds.com

```

