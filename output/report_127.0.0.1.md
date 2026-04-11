# Autonomous Red Team Report

**Target:** `127.0.0.1`  
**Date:** 2026-04-10 19:33:45  
**Run ID:** `4b2457a2fa914b708d2f44fba9b4aa13`  
**Total iterations:** 4

## Final Intelligence Summary

Autonomous AI recon completed for 127.0.0.1 across 4 iterations.

- Overall risk: **medium**
- Confidence: **medium**

### Attack Surface

- Primary target: 127.0.0.1
- Open port 3306 (mysql)
- Web endpoint: http://127.0.0.1
- Web endpoint: https://127.0.0.1
- Web endpoint: http://127.0.0.1/FUZZ

### High Value Findings

- Initial target: 127.0.0.1
- Seeded URLs: http://127.0.0.1, https://127.0.0.1
- Open TCP port 3306 running mysql.

### Risk Signals

- nuclei command timed out; visibility may be incomplete.
- nuclei returned exit code -1.

### Recommended Next Steps

- Validate high-confidence findings with targeted manual checks.
- Prioritize internet-facing assets and sensitive endpoints first.
- Run authenticated validation for confirmed candidates where in scope.

## Vulnerability Candidates

No vulnerability candidates were extracted in this run.

## Iteration Attack Chain

| Iter | Goal | Tools | Commands | Failures |
|------|------|-------|----------|----------|
| 1 | AI fallback recon expansion for iteration 1. | nmap, nuclei | 2 | 1 |
| 2 | AI fallback recon expansion for iteration 2. | ffuf, nmap, nuclei | 3 | 1 |
| 3 | AI fallback recon expansion for iteration 3. | ffuf, nmap, nuclei | 3 | 1 |
| 4 | AI fallback recon expansion for iteration 4. | ffuf, nuclei | 2 | 1 |

## Iteration Details

### Iteration 1
**Goal:** AI fallback recon expansion for iteration 1.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete.

**Analysis summary:** Iteration 1 produced 1 findings, 0 vulnerability candidates, and 2 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Key findings:**
- Open TCP port 3306 running mysql.

**Risk signals:**
- nuclei command timed out; visibility may be incomplete.
- nuclei returned exit code -1.

#### Command 1: NMAP
- Objective: Map exposed ports and service versions.
- Timeout: 180
- Exit code: 0
- Timed out: False
- Duration sec: 1.0
- Command: `"C:\Users\ganes\nmap.exe" -sV -Pn -p 80,443,8080,8443,21,22,25,3306,3389 127.0.0.1`

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-10 19:16 +0530
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00034s latency).

PORT     STATE  SERVICE       VERSION
21/tcp   closed ftp
22/tcp   closed ssh
25/tcp   closed smtp
80/tcp   closed http
443/tcp  closed https
3306/tcp open   mysql         MySQL 8.0.43
3389/tcp closed ms-wbt-server
8080/tcp closed http-proxy
8443/tcp closed https-alt

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.79 seconds

```

#### Command 2: NUCLEI
- Objective: Run quick vulnerability template checks on the primary endpoint.
- Timeout: 180
- Exit code: -1
- Timed out: True
- Duration sec: 180.08
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://127.0.0.1 -severity critical,high,medium -silent`

```

```

### Iteration 2
**Goal:** AI fallback recon expansion for iteration 2.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete.

**Analysis summary:** Iteration 2 produced 1 findings, 0 vulnerability candidates, and 2 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Key findings:**
- Open TCP port 3306 running mysql.

**Risk signals:**
- nuclei command timed out; visibility may be incomplete.
- nuclei returned exit code -1.

#### Command 1: FFUF
- Objective: Discover hidden endpoints and sensitive paths quickly.
- Timeout: 180
- Exit code: 0
- Timed out: False
- Duration sec: 16.45
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://127.0.0.1/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 120`

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://127.0.0.1/FUZZ
 :: Wordlist         : FUZZ: C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________



:: Progress: [1/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [212/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 211 ::

:: Progress: [426/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 426 ::

:: Progress: [638/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 636 ::

:: Progress: [854/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 853 ::

:: Progress: [1070/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 1068 ::

:: Progress: [1278/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 1277 ::

:: Progress: [1486/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 1485 ::

:: Progress: [1690/26468] :: Job [1/1] :: 1639 req/sec :: Duration: [0:00:01] :: Errors: 1688 ::

:: Progress: [1890/26468] :: Job [1/1] :: 1612 req/sec :: Duration: [0:00:01] :: Errors: 1889 ::

:: Progress: [2095/26468] :: Job [1/1] :: 1639 req/sec :: Duration: [0:00:01] :: Errors: 2093 ::

:: Progress: [2300/26468] :: Job [1/1] :: 1666 req/sec :: Duration: [0:00:01] :: Errors: 2300 ::

:: Progress: [2509/26468] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:01] :: Errors: 2507 ::

:: Progress: [2715/26468] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:01] :: Errors: 2712 ::

:: Progress: [2912/26468] :: Job [1/1] :: 1587 req/sec :: Duration: [0:00:01] :: Errors: 2910 ::

:: Progress: [3124/26468] :: Job [1/1] :: 1709 req/sec :: Duration: [0:00:01] :: Errors: 3122 ::

:: Progress: [3331/26468] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:02] :: Errors: 3330 ::

:: Progress: [3540/26468] :: Job [1/1] :: 1694 req/sec :: Duration: [0:00:02] :: Errors: 3539 ::

:: Progress: [3749/26468] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:02] :: Errors: 3748 ::

:: Progress: [3957/26468] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:02] :: Errors: 3956 ::

:: Progress: [4161/26468] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:02] :: Errors: 4160 ::

:: Progress: [4377/26468] :: Job [1/1] :: 1739 req/sec :: Duration: [0:00:02] :: Errors: 4376 ::

:: Progress: [4589/26468] :: Job [1/1] :: 1709 req/sec :: Duration: [0:00:02] :: Errors: 4588 ::

:: Progress: [4805/26468] :: Job [1/1] :: 1754 req/sec :: Duration: [0:00:02] :: Errors: 4805 ::

:: Progress: [5013/26468] :: Job [1/1] :: 1694 req/sec :: Duration: [0:00:03] :: Errors: 5013 ::

:: Progress: [5223/26468] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:03] :: Errors: 5222 ::

:: Progress: [5432/26468] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:03] :: Errors: 5430 ::

:: Progress: [5638/26468] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:03] :: Errors: 5636 ::

:: Progress: [5841/26468] :: Job [1/1] :: 1626 req/sec :: Duration: [0:00:03] :: Errors: 5839 ::

:: Progress: [6055/26468] :: Job [1/1] :: 1709 req/sec :: Duration: [0:00:03] :: Errors: 6053 ::

:: Progress: [6259/26468] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:03] :: Errors: 6258 ::

:: Progress: [6470/26468] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:03] :: Errors: 6468 ::

:: Progress: [6682/26468] :: Job [1/1] :: 1709 req/sec :: Duration: [0:00:04] :: Errors: 6680 ::

:: Progress: [6891/2646
... [truncated]
```

#### Command 2: NUCLEI
- Objective: Correlate path discovery with known vulnerability signatures.
- Timeout: 180
- Exit code: -1
- Timed out: True
- Duration sec: 180.13
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://127.0.0.1 -severity critical,high,medium -silent`

```

```

#### Command 3: NMAP
- Objective: Re-validate active service versions on discovered ports.
- Timeout: 180
- Exit code: 0
- Timed out: False
- Duration sec: 0.61
- Command: `"C:\Users\ganes\nmap.exe" -sV -Pn -p 3306 127.0.0.1`

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-10 19:23 +0530
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00s latency).

PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 8.0.43

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds

```

### Iteration 3
**Goal:** AI fallback recon expansion for iteration 3.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete.

**Analysis summary:** Iteration 3 produced 1 findings, 0 vulnerability candidates, and 2 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Key findings:**
- Open TCP port 3306 running mysql.

**Risk signals:**
- nuclei command timed out; visibility may be incomplete.
- nuclei returned exit code -1.

#### Command 1: NMAP
- Objective: Run targeted service-level vulnerability scripts.
- Timeout: 240
- Exit code: 0
- Timed out: False
- Duration sec: 68.49
- Command: `"C:\Users\ganes\nmap.exe" -Pn -sV --script vuln -p 3306 127.0.0.1`

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-10 19:23 +0530
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00s latency).

PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 8.0.43
| vulners: 
|   cpe:/a:mysql:mysql:8.0.43: 
|_    	NODEJS:602	0.0	https://vulners.com/nodejs/NODEJS:602

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.28 seconds

```

#### Command 2: FFUF
- Objective: Run deeper endpoint discovery for missed attack paths.
- Timeout: 240
- Exit code: 0
- Timed out: False
- Duration sec: 55.43
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://127.0.0.1/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 180`

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://127.0.0.1/FUZZ
 :: Wordlist         : FUZZ: C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________



:: Progress: [2/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [202/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 199 ::

:: Progress: [402/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 400 ::

:: Progress: [600/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 596 ::

:: Progress: [791/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 791 ::

:: Progress: [992/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 989 ::

:: Progress: [1194/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 1192 ::

:: Progress: [1394/90821] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 1392 ::

:: Progress: [1596/90821] :: Job [1/1] :: 1639 req/sec :: Duration: [0:00:01] :: Errors: 1596 ::

:: Progress: [1798/90821] :: Job [1/1] :: 1626 req/sec :: Duration: [0:00:01] :: Errors: 1796 ::

:: Progress: [1997/90821] :: Job [1/1] :: 1600 req/sec :: Duration: [0:00:01] :: Errors: 1996 ::

:: Progress: [2203/90821] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:01] :: Errors: 2202 ::

:: Progress: [2412/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:01] :: Errors: 2411 ::

:: Progress: [2621/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:01] :: Errors: 2619 ::

:: Progress: [2825/90821] :: Job [1/1] :: 1639 req/sec :: Duration: [0:00:01] :: Errors: 2823 ::

:: Progress: [3033/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:01] :: Errors: 3032 ::

:: Progress: [3241/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:02] :: Errors: 3239 ::

:: Progress: [3451/90821] :: Job [1/1] :: 1694 req/sec :: Duration: [0:00:02] :: Errors: 3449 ::

:: Progress: [3658/90821] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:02] :: Errors: 3656 ::

:: Progress: [3865/90821] :: Job [1/1] :: 1666 req/sec :: Duration: [0:00:02] :: Errors: 3864 ::

:: Progress: [4075/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:02] :: Errors: 4072 ::

:: Progress: [4286/90821] :: Job [1/1] :: 1694 req/sec :: Duration: [0:00:02] :: Errors: 4284 ::

:: Progress: [4494/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:02] :: Errors: 4493 ::

:: Progress: [4706/90821] :: Job [1/1] :: 1709 req/sec :: Duration: [0:00:02] :: Errors: 4705 ::

:: Progress: [4917/90821] :: Job [1/1] :: 1694 req/sec :: Duration: [0:00:03] :: Errors: 4916 ::

:: Progress: [5133/90821] :: Job [1/1] :: 1739 req/sec :: Duration: [0:00:03] :: Errors: 5131 ::

:: Progress: [5341/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:03] :: Errors: 5340 ::

:: Progress: [5550/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:03] :: Errors: 5549 ::

:: Progress: [5759/90821] :: Job [1/1] :: 1666 req/sec :: Duration: [0:00:03] :: Errors: 5757 ::

:: Progress: [5966/90821] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:03] :: Errors: 5965 ::

:: Progress: [6175/90821] :: Job [1/1] :: 1666 req/sec :: Duration: [0:00:03] :: Errors: 6174 ::

:: Progress: [6383/90821] :: Job [1/1] :: 1666 req/sec :: Duration: [0:00:03] :: Errors: 6381 ::

:: Progress: [6590/90821] :: Job [1/1] :: 1694 req/sec :: Duration: [0:00:04] :: Errors: 6589 ::

:: Progress: [6800/90821] :: J
... [truncated]
```

#### Command 3: NUCLEI
- Objective: Perform broader template checks on the highest-priority endpoint.
- Timeout: 240
- Exit code: -1
- Timed out: True
- Duration sec: 240.1
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://127.0.0.1 -silent -severity critical,high,medium`

```

```

### Iteration 4
**Goal:** AI fallback recon expansion for iteration 4.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete.

**Analysis summary:** Iteration 4 produced 0 findings, 0 vulnerability candidates, and 2 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Risk signals:**
- nuclei command timed out; visibility may be incomplete.
- nuclei returned exit code -1.

#### Command 1: NUCLEI
- Objective: Confirm and expand final vulnerability evidence.
- Timeout: 240
- Exit code: -1
- Timed out: True
- Duration sec: 240.11
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://127.0.0.1 -severity critical,high,medium,low -silent`

```

```

#### Command 2: FFUF
- Objective: Re-check for high-signal hidden paths with bounded runtime.
- Timeout: 150
- Exit code: 0
- Timed out: False
- Duration sec: 15.81
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://127.0.0.1/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 90`

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://127.0.0.1/FUZZ
 :: Wordlist         : FUZZ: C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________



:: Progress: [1/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

:: Progress: [234/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 234 ::

:: Progress: [452/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 451 ::

:: Progress: [679/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 679 ::

:: Progress: [872/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 871 ::

:: Progress: [1089/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 1089 ::

:: Progress: [1309/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 1308 ::

:: Progress: [1530/26468] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 1530 ::

:: Progress: [1736/26468] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:01] :: Errors: 1734 ::

:: Progress: [1939/26468] :: Job [1/1] :: 1626 req/sec :: Duration: [0:00:01] :: Errors: 1937 ::

:: Progress: [2138/26468] :: Job [1/1] :: 1612 req/sec :: Duration: [0:00:01] :: Errors: 2136 ::

:: Progress: [2338/26468] :: Job [1/1] :: 1600 req/sec :: Duration: [0:00:01] :: Errors: 2335 ::

:: Progress: [2541/26468] :: Job [1/1] :: 1626 req/sec :: Duration: [0:00:01] :: Errors: 2535 ::

:: Progress: [2740/26468] :: Job [1/1] :: 1626 req/sec :: Duration: [0:00:01] :: Errors: 2738 ::

:: Progress: [2958/26468] :: Job [1/1] :: 1785 req/sec :: Duration: [0:00:01] :: Errors: 2957 ::

:: Progress: [3174/26468] :: Job [1/1] :: 1739 req/sec :: Duration: [0:00:01] :: Errors: 3173 ::

:: Progress: [3388/26468] :: Job [1/1] :: 1724 req/sec :: Duration: [0:00:02] :: Errors: 3388 ::

:: Progress: [3597/26468] :: Job [1/1] :: 1666 req/sec :: Duration: [0:00:02] :: Errors: 3595 ::

:: Progress: [3809/26468] :: Job [1/1] :: 1709 req/sec :: Duration: [0:00:02] :: Errors: 3807 ::

:: Progress: [4016/26468] :: Job [1/1] :: 1666 req/sec :: Duration: [0:00:02] :: Errors: 4014 ::

:: Progress: [4246/26468] :: Job [1/1] :: 1886 req/sec :: Duration: [0:00:02] :: Errors: 4246 ::

:: Progress: [4477/26468] :: Job [1/1] :: 1851 req/sec :: Duration: [0:00:02] :: Errors: 4477 ::

:: Progress: [4698/26468] :: Job [1/1] :: 1754 req/sec :: Duration: [0:00:02] :: Errors: 4696 ::

:: Progress: [4916/26468] :: Job [1/1] :: 1739 req/sec :: Duration: [0:00:02] :: Errors: 4914 ::

:: Progress: [5140/26468] :: Job [1/1] :: 1801 req/sec :: Duration: [0:00:03] :: Errors: 5139 ::

:: Progress: [5353/26468] :: Job [1/1] :: 1739 req/sec :: Duration: [0:00:03] :: Errors: 5352 ::

:: Progress: [5578/26468] :: Job [1/1] :: 1801 req/sec :: Duration: [0:00:03] :: Errors: 5577 ::

:: Progress: [5797/26468] :: Job [1/1] :: 1754 req/sec :: Duration: [0:00:03] :: Errors: 5795 ::

:: Progress: [6009/26468] :: Job [1/1] :: 1709 req/sec :: Duration: [0:00:03] :: Errors: 6007 ::

:: Progress: [6214/26468] :: Job [1/1] :: 1639 req/sec :: Duration: [0:00:03] :: Errors: 6212 ::

:: Progress: [6428/26468] :: Job [1/1] :: 1739 req/sec :: Duration: [0:00:03] :: Errors: 6427 ::

:: Progress: [6648/26468] :: Job [1/1] :: 1785 req/sec :: Duration: [0:00:03] :: Errors: 6648 ::

:: Progress: [6868/26468] :: Job [1/1] :: 1754 req/sec :: Duration: [0:00:04] :: Errors: 6867 ::

:: Progress: [7099/2646
... [truncated]
```

