# Autonomous Red Team Report

**Target:** `google.com`  
**Date:** 2026-04-13 13:42:18  
**Run ID:** `afdc5723c04b44cb8b0a50387d298653`  
**Total iterations:** 4

## Final Intelligence Summary

Autonomous AI recon completed for google.com across 4 iterations.

- Overall risk: **medium**
- Confidence: **medium**

### Attack Surface

- Primary target: google.com
- Web endpoint: http://google.com
- Web endpoint: https://google.com
- Web endpoint: http://google.com/FUZZ
- Discovered host: aarjav-b480g7k2ab9@checkout.google.com
- Discovered host: accounts.flexpack.google.com
- Discovered host: accounts.freezone.google.com
- Discovered host: accounts.google.com
- Discovered host: ads-compare.eem.corp.google.com
- Discovered host: adwords.google.com
- Discovered host: alt1.aspmx.l.google.com
- Discovered host: alt1.gmail-smtp-in.l.google.com
- Discovered host: alt1.gmr-smtp-in.l.google.com
- Discovered host: alt2.aspmx.l.google.com
- Discovered host: alt2.gmail-smtp-in.l.google.com
- Discovered host: alt2.gmr-smtp-in.l.google.com
- Discovered host: alt3.aspmx.l.google.com
- Discovered host: alt3.gmail-smtp-in.l.google.com
- Discovered host: alt3.gmr-smtp-in.l.google.com
- Discovered host: alt4.aspmx.l.google.com
- Discovered host: alt4.gmail-smtp-in.l.google.com
- Discovered host: alt4.gmr-smtp-in.l.google.com
- Discovered host: answers.google.com
- Discovered host: apps-secure-data-connector.google.com
- Discovered host: aspmx.l.google.com
- Discovered host: corpnat-104-132-231-69.corp.google.com
- Discovered host: corpnat-104-133-124-66.corp.google.com
- Discovered host: corpnat-104-133-194-69.corp.google.com
- Discovered host: guestnat-104-133-135-98.corp.google.com
- Discovered host: corpnat-104-132-178-88.corp.google.com

### High Value Findings

- Initial target: google.com
- Seeded URLs: http://google.com, https://google.com
- crt.sh returned 189 certificate names for google.com.
- RDAP registrar: unknown
- RDAP status: ['client delete prohibited', 'client transfer prohibited', 'client update prohibited', 'server delete prohibited', 'server transfer prohibited', 'server update prohibited']
- Discovered subdomain: corpnat-104-132-231-69.corp.google.com
- Discovered subdomain: corpnat-104-133-124-66.corp.google.com
- Discovered subdomain: corpnat-104-133-194-69.corp.google.com
- Discovered subdomain: guestnat-104-133-135-98.corp.google.com
- Discovered subdomain: corpnat-104-132-178-88.corp.google.com
- Discovered subdomain: corpnat-104-133-189-77.corp.google.com
- Discovered subdomain: google-proxy-66-249-81-90.google.com
- Discovered subdomain: google-proxy-66-249-83-4.google.com
- Discovered subdomain: google-proxy-74-125-208-113.google.com
- Discovered subdomain: corpnat-104-133-228-86.corp.google.com
- Discovered subdomain: corpnat-104-133-79-71.corp.google.com
- Discovered subdomain: guestnat-104-132-120-106.corp.google.com
- Discovered subdomain: corpnat-104-133-30-68.corp.google.com
- Discovered subdomain: google-proxy-66-249-81-212.google.com
- Discovered subdomain: corpnat-104-133-123-85.corp.google.com

### Risk Signals

- LLM bypass active after an earlier transport failure.
- subfinder command timed out; visibility may be incomplete.
- subfinder returned exit code -1.

### Recommended Next Steps

- Validate high-confidence findings with targeted manual checks.
- Prioritize internet-facing assets and sensitive endpoints first.
- Run authenticated validation for confirmed candidates where in scope.

## Vulnerability Candidates

No vulnerability candidates were extracted in this run.

## Iteration Attack Chain

| Iter | Goal | Tools | Commands | Failures |
|------|------|-------|----------|----------|
| 1 | Passive reconnaissance only. | passive_crtsh, passive_rdap | 2 | 0 |
| 2 | AI fallback recon expansion for iteration 2. | ffuf, nuclei | 2 | 1 |
| 3 | AI fallback recon expansion for iteration 3. | ffuf, nuclei | 2 | 1 |
| 4 | AI fallback recon expansion for iteration 4. | ffuf, nuclei, subfinder | 3 | 2 |

## Iteration Details

### Iteration 1
**Goal:** Passive reconnaissance only.

**Planner reasoning:** Collect passive intelligence before touching the target directly.

**Analysis summary:** Passive recon collected 3 findings and 189 targets.

**Confidence:** medium

**Next focus:** Validate the most promising passive discoveries with active scanning.

**Key findings:**
- crt.sh returned 189 certificate names for google.com.
- RDAP registrar: unknown
- RDAP status: ['client delete prohibited', 'client transfer prohibited', 'client update prohibited', 'server delete prohibited', 'server transfer prohibited', 'server update prohibited']

#### Command 1: PASSIVE_CRTSH
- Objective: Passive intelligence collection.
- Timeout: 0
- Exit code: 0
- Timed out: False
- Duration sec: 7.38
- Command: `https://crt.sh/?q=%25.google.com&output=json`

```
Found 189 names.
```

#### Command 2: PASSIVE_RDAP
- Objective: Passive intelligence collection.
- Timeout: 0
- Exit code: 0
- Timed out: False
- Duration sec: 2.94
- Command: `https://rdap.org/domain/google.com`

```
RDAP data collected.
```

### Iteration 2
**Goal:** AI fallback recon expansion for iteration 2.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete. LLM issue: LLM bypass active after an earlier transport failure.

**Analysis summary:** No significant findings parsed from this iteration output.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Risk signals:**
- LLM bypass active after an earlier transport failure.

#### Command 1: FFUF
- Objective: Discover hidden endpoints and sensitive paths quickly.
- Timeout: 180
- Exit code: 0
- Timed out: False
- Duration sec: 80.37
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://google.com/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 120`

```


accounts/clientsign_up  [Status: 302, Size: 250, Words: 14, Lines: 11, Duration: 76ms]


2006                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 14ms]


sites                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 21ms]


templates               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 19ms]


..;/manager/html        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 15ms]


services/graylog/.env   [Status: 301, Size: 241, Words: 9, Lines: 7, Duration: 17ms]


docs/html/admin/index.html [Status: 301, Size: 246, Words: 9, Lines: 7, Duration: 36ms]


docs/install.txt        [Status: 301, Size: 236, Words: 9, Lines: 7, Duration: 32ms]


docs/html/admin/ch03s07.html [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 19ms]


templates/jsn_glass_pro/ext/hikashop/jsn_ext_hikashop.css [Status: 301, Size: 277, Words: 9, Lines: 7, Duration: 13ms]


adview                  [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 54ms]


tmui/login.jsp/..;/tmui/locallb/workspace/fileread.jsp?filename=/etc/f5 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 15ms]


tools                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 26ms]


custom                  [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 18ms]


accounts/login.php      [Status: 302, Size: 246, Words: 14, Lines: 11, Duration: 57ms]


passwords               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 14ms]


2003                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 15ms]


password                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 17ms]


security                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 32ms]


apps/client/.env        [Status: 301, Size: 236, Words: 9, Lines: 7, Duration: 16ms]


policies                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 17ms]


script/performance/request [Status: 301, Size: 246, Words: 9, Lines: 7, Duration: 17ms]


apis/apps               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 45ms]


manifest                [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 319ms]


sites/all/modules/readme.txt [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 16ms]


docs/html/admin/ch01s04.html [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 28ms]


tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/config/bigip.license [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 54ms]


url                     [Status: 301, Size: 222, Words: 9, Lines: 7, Duration: 111ms]


newsletter/2008-04/intro.cfm [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 61ms]


tags                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 15ms]


script/plugin           [Status: 301, Size: 233, Words: 9, Lines: 7, Duration: 15ms]


story                   [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 54ms]


accounts/login          [Status: 302, Size: 242, Words: 14, Lines: 11, Duration: 243ms]


terms                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 33ms]


2005                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 17ms]


gemini                  [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 16ms]


apis/external.metrics.k8s.io [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 16ms]


sites/samples/knowledge/search/viewcode.asp [Status: 301, Size: 263, Words: 9, Lines: 7, Duration: 15ms]


apis/authorization.k8s.io/v1 [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 16ms]


script/jqueryplugins/datatables/extras/tabletools/media/swf/zeroclipboard.swf [Status: 301, Size: 297, Words: 9, Lines: 7, Duration: 15ms]


sites/samples/knowledge/membership/inspired/viewcode.asp [Status: 301, Size: 276, Words: 9, Lines: 7, Duration: 18ms]


voice                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 22ms]


static/../admin         [Status: 302, Size: 0, Words: 
... [truncated]
```

#### Command 2: NUCLEI
- Objective: Correlate path discovery with known vulnerability signatures.
- Timeout: 180
- Exit code: 1
- Timed out: False
- Duration sec: 2.87
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://google.com -severity critical,high,medium -silent`

```
Access is denied.

```

### Iteration 3
**Goal:** AI fallback recon expansion for iteration 3.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete. LLM issue: LLM bypass active after an earlier transport failure.

**Analysis summary:** No significant findings parsed from this iteration output.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Risk signals:**
- LLM bypass active after an earlier transport failure.

#### Command 1: FFUF
- Objective: Run deeper endpoint discovery for missed attack paths.
- Timeout: 240
- Exit code: 0
- Timed out: False
- Duration sec: 180.27
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://google.com/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 180`

```


2001                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 15ms]


2004                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 14ms]


2003                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 15ms]


2009                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 14ms]


2002                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 18ms]


2005                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 16ms]


2006                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 17ms]


2008                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 16ms]


2011                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 14ms]


2010                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 16ms]


2007                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 19ms]


2012                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 19ms]


a                       [Status: 301, Size: 221, Words: 9, Lines: 7, Duration: 18ms]


about                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 31ms]


account                 [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 33ms]


accessibility           [Status: 301, Size: 233, Words: 9, Lines: 7, Duration: 36ms]


accounts                [Status: 302, Size: 237, Words: 14, Lines: 11, Duration: 71ms]


action                  [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 71ms]


ads                     [Status: 301, Size: 223, Words: 9, Lines: 7, Duration: 14ms]


advertising             [Status: 301, Size: 231, Words: 9, Lines: 7, Duration: 16ms]


advertise               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 22ms]


android                 [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 15ms]


apis                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 19ms]


apps                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 22ms]


blog                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 17ms]


blogger                 [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 16ms]


books                   [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 18ms]


buy                     [Status: 301, Size: 223, Words: 9, Lines: 7, Duration: 14ms]


calendar                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 15ms]


cars                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 14ms]


careers                 [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 16ms]


business                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 57ms]


alerts                  [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 438ms]


chat                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 30ms]


chrome                  [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 16ms]


commerce                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 16ms]


company                 [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 13ms]


contact                 [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 14ms]


contacts                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 16ms]


custom                  [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 44ms]


customers               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 40ms]


deleted                 [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 17ms]


design                  [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 16ms]


desktop                 [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 19ms]


developer               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 16ms]


developers              [Status: 301, Size: 230, Words: 9, Lines: 7, Duration: 15m
... [truncated]
```

#### Command 2: NUCLEI
- Objective: Perform broader template checks on the highest-priority endpoint.
- Timeout: 240
- Exit code: 1
- Timed out: False
- Duration sec: 4.93
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://google.com -silent -severity critical,high,medium`

```
Access is denied.

```

### Iteration 4
**Goal:** AI fallback recon expansion for iteration 4.

**Planner reasoning:** Fallback strategy used because model response was invalid or incomplete. LLM issue: LLM bypass active after an earlier transport failure.

**Analysis summary:** Iteration 4 produced 300 findings, 0 vulnerability candidates, and 2 risk signals.

**Confidence:** medium

**Next focus:** Prioritize high-confidence endpoints and confirm vulnerability evidence.

**Key findings:**
- Discovered subdomain: corpnat-104-132-231-69.corp.google.com
- Discovered subdomain: corpnat-104-133-124-66.corp.google.com
- Discovered subdomain: corpnat-104-133-194-69.corp.google.com
- Discovered subdomain: guestnat-104-133-135-98.corp.google.com
- Discovered subdomain: corpnat-104-132-178-88.corp.google.com
- Discovered subdomain: corpnat-104-133-189-77.corp.google.com
- Discovered subdomain: google-proxy-66-249-81-90.google.com
- Discovered subdomain: google-proxy-66-249-83-4.google.com
- Discovered subdomain: google-proxy-74-125-208-113.google.com
- Discovered subdomain: corpnat-104-133-228-86.corp.google.com
- Discovered subdomain: corpnat-104-133-79-71.corp.google.com
- Discovered subdomain: guestnat-104-132-120-106.corp.google.com
- Discovered subdomain: corpnat-104-133-30-68.corp.google.com
- Discovered subdomain: google-proxy-66-249-81-212.google.com
- Discovered subdomain: corpnat-104-133-123-85.corp.google.com
- Discovered subdomain: guestnat-104-132-175-107.corp.google.com
- Discovered subdomain: guestnat-104-133-106-100.corp.google.com
- Discovered subdomain: google-proxy-66-249-82-41.google.com
- Discovered subdomain: googleproxy-66-102-6-234.google.com
- Discovered subdomain: corpnat-104-132-117-75.corp.google.com
- Discovered subdomain: corpnat-104-133-45-78.corp.google.com
- Discovered subdomain: corpnat-104-133-50-88.corp.google.com
- Discovered subdomain: guestnat-104-133-254-97.corp.google.com
- Discovered subdomain: pa21.cache.google.com
- Discovered subdomain: corpnat-104-132-140-80.corp.google.com
- Discovered subdomain: corpnat-104-132-196-90.corp.google.com
- Discovered subdomain: corpnat-104-133-17-94.corp.google.com
- Discovered subdomain: guestnat-104-133-159-110.corp.google.com
- Discovered subdomain: ncc-poc-104-133-129-40.corp.google.com
- Discovered subdomain: mail-ua1-f120.google.com
- Discovered subdomain: lh3-dg.photos6.sandbox.google.com
- Discovered subdomain: corpnat-104-132-218-69.corp.google.com
- Discovered subdomain: corpnat-104-133-164-72.corp.google.com
- Discovered subdomain: guestnat-104-132-247-105.corp.google.com
- Discovered subdomain: corpnat-104-132-189-64.corp.google.com
- Discovered subdomain: corpnat-104-132-30-88.corp.google.com
- Discovered subdomain: corpnat-104-133-252-76.corp.google.com
- Discovered subdomain: static-190-11-68-143.cache.google.com
- Discovered subdomain: corpnat-104-132-179-89.corp.google.com
- Discovered subdomain: corpnat-104-132-187-86.corp.google.com

**Risk signals:**
- subfinder command timed out; visibility may be incomplete.
- subfinder returned exit code -1.
- LLM bypass active after an earlier transport failure.

#### Command 1: NUCLEI
- Objective: Confirm and expand final vulnerability evidence.
- Timeout: 240
- Exit code: 1
- Timed out: False
- Duration sec: 4.74
- Command: `"C:\Users\ganes\go\bin\nuclei.exe" -u http://google.com -severity critical,high,medium,low -silent`

```
Access is denied.

```

#### Command 2: FFUF
- Objective: Re-check for high-signal hidden paths with bounded runtime.
- Timeout: 150
- Exit code: 0
- Timed out: False
- Duration sec: 90.29
- Command: `"C:\Users\ganes\go\bin\ffuf.exe" -u http://google.com/FUZZ -w "C:\Users\ganes\OneDrive\Desktop\Autonomous Red Team Project\wordlists\Wordlists\fuzz_wordlist.txt" -mc 200,204,301,302,307,401,403 -maxtime-job 90`

```


accounts/clientsign_up  [Status: 302, Size: 250, Words: 14, Lines: 11, Duration: 95ms]


2006                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 21ms]


sites                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 47ms]


templates               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 17ms]


..;/manager/html        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 16ms]


services/graylog/.env   [Status: 301, Size: 241, Words: 9, Lines: 7, Duration: 59ms]


docs/html/admin/index.html [Status: 301, Size: 246, Words: 9, Lines: 7, Duration: 16ms]


docs/install.txt        [Status: 301, Size: 236, Words: 9, Lines: 7, Duration: 17ms]


docs/html/admin/ch03s07.html [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 20ms]


templates/jsn_glass_pro/ext/hikashop/jsn_ext_hikashop.css [Status: 301, Size: 277, Words: 9, Lines: 7, Duration: 20ms]


adview                  [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 58ms]


tmui/login.jsp/..;/tmui/locallb/workspace/fileread.jsp?filename=/etc/f5 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 13ms]


tools                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 16ms]


custom                  [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 15ms]


passwords               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 16ms]


accounts/login.php      [Status: 302, Size: 246, Words: 14, Lines: 11, Duration: 256ms]


2003                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 18ms]


password                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 15ms]


security                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 16ms]


apps/client/.env        [Status: 301, Size: 236, Words: 9, Lines: 7, Duration: 49ms]


policies                [Status: 301, Size: 228, Words: 9, Lines: 7, Duration: 15ms]


script/performance/request [Status: 301, Size: 246, Words: 9, Lines: 7, Duration: 14ms]


apis/apps               [Status: 301, Size: 229, Words: 9, Lines: 7, Duration: 15ms]


manifest                [Status: 301, Size: 227, Words: 9, Lines: 7, Duration: 316ms]


sites/all/modules/readme.txt [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 15ms]


docs/html/admin/ch01s04.html [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 19ms]


tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/config/bigip.license [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 20ms]


url                     [Status: 301, Size: 222, Words: 9, Lines: 7, Duration: 51ms]


newsletter/2008-04/intro.cfm [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 18ms]


tags                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 17ms]


accounts/login          [Status: 302, Size: 242, Words: 14, Lines: 11, Duration: 94ms]


script/plugin           [Status: 301, Size: 233, Words: 9, Lines: 7, Duration: 18ms]


story                   [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 52ms]


terms                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 14ms]


2005                    [Status: 301, Size: 224, Words: 9, Lines: 7, Duration: 19ms]


gemini                  [Status: 301, Size: 226, Words: 9, Lines: 7, Duration: 15ms]


apis/external.metrics.k8s.io [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 15ms]


sites/samples/knowledge/search/viewcode.asp [Status: 301, Size: 263, Words: 9, Lines: 7, Duration: 17ms]


apis/authorization.k8s.io/v1 [Status: 301, Size: 248, Words: 9, Lines: 7, Duration: 24ms]


script/jqueryplugins/datatables/extras/tabletools/media/swf/zeroclipboard.swf [Status: 301, Size: 297, Words: 9, Lines: 7, Duration: 16ms]


sites/samples/knowledge/membership/inspired/viewcode.asp [Status: 301, Size: 276, Words: 9, Lines: 7, Duration: 20ms]


voice                   [Status: 301, Size: 225, Words: 9, Lines: 7, Duration: 22ms]


static/../admin         [Status: 302, Size: 0, Words: 1
... [truncated]
```

#### Command 3: SUBFINDER
- Objective: Final subdomain sweep for completeness.
- Timeout: 120
- Exit code: -1
- Timed out: True
- Duration sec: 188.65
- Command: `"C:\Users\ganes\go\bin\subfinder.exe" -d google.com -silent`

```
corpnat-104-132-231-69.corp.google.com
corpnat-104-133-124-66.corp.google.com
corpnat-104-133-194-69.corp.google.com
guestnat-104-133-135-98.corp.google.com
corpnat-104-132-178-88.corp.google.com
corpnat-104-133-189-77.corp.google.com
google-proxy-66-249-81-90.google.com
google-proxy-66-249-83-4.google.com
google-proxy-74-125-208-113.google.com
corpnat-104-133-228-86.corp.google.com
corpnat-104-133-79-71.corp.google.com
guestnat-104-132-120-106.corp.google.com
corpnat-104-133-30-68.corp.google.com
google-proxy-66-249-81-212.google.com
corpnat-104-133-123-85.corp.google.com
guestnat-104-132-175-107.corp.google.com
guestnat-104-133-106-100.corp.google.com
google-proxy-66-249-82-41.google.com
googleproxy-66-102-6-234.google.com
corpnat-104-132-117-75.corp.google.com
corpnat-104-133-45-78.corp.google.com
corpnat-104-133-50-88.corp.google.com
guestnat-104-133-254-97.corp.google.com
pa21.cache.google.com
corpnat-104-132-140-80.corp.google.com
corpnat-104-132-196-90.corp.google.com
corpnat-104-133-17-94.corp.google.com
guestnat-104-133-159-110.corp.google.com
ncc-poc-104-133-129-40.corp.google.com
mail-ua1-f120.google.com
lh3-dg.photos6.sandbox.google.com
corpnat-104-132-218-69.corp.google.com
corpnat-104-133-164-72.corp.google.com
guestnat-104-132-247-105.corp.google.com
corpnat-104-132-189-64.corp.google.com
corpnat-104-132-30-88.corp.google.com
corpnat-104-133-252-76.corp.google.com
static-190-11-68-143.cache.google.com
corpnat-104-132-179-89.corp.google.com
corpnat-104-132-187-86.corp.google.com
guestnat-104-132-86-105.corp.google.com
guestnat-104-133-116-109.corp.google.com
corpnat-104-132-201-93.corp.google.com
corpnat-104-132-22-67.corp.google.com
corpnat-104-133-134-87.corp.google.com
generativeai.devsite.corp.google.com
guestnat-104-132-81-104.corp.google.com
pub-9249882159442734.afd.ghs.google.com
google-proxy-66-249-80-179.google.com
google-proxy-66-249-82-117.google.com
corpnat-104-132-90-85.corp.google.com
corpnat-104-133-77-91.corp.google.com
guestnat-104-133-243-99.corp.google.com
google-proxy-64-233-173-48.google.com
ratelimited-proxy-66-249-91-83.google.com
corpnat-104-132-76-81.corp.google.com
corpnat-104-133-228-72.corp.google.com
googleproxy-66-249-81-1.google.com
corpnat-104-132-58-78.corp.google.com
gke044.feedproxy.ghs.google.com
corpnat-104-132-154-83.corp.google.com
corpnat-104-132-184-74.corp.google.com
corpnat-104-132-59-75.corp.google.com
guestnat-104-133-253-107.corp.google.com
corpnat-104-133-50-94.corp.google.com
guestnat-104-132-249-96.corp.google.com
guestnat-104-133-213-111.corp.google.com
185.g8-ggc-bsa.google.com
google-proxy-66-249-84-161.google.com
ip-195-43-73-250.cache.google.com
svx2-78.cache.google.com
cache2.google.com
au-edg-mel04-1-ac-corpa-nvr01.corp.google.com
corpnat-104-132-132-84.corp.google.com
corpnat-104-133-133-91.corp.google.com
google-proxy-74-125-208-85.google.com
corpnat-104-132-239-68.corp.google.com
corpnat-104-133-11-69.corp.google.com
ncc-poc-104-133-129-138.corp.google.com
google-proxy-66-249-80-87.google.com
google-proxy-66-249-83-231.google.com
mailwr0-f243.google.com
corpnat-104-133-49-93.corp.google.com
guestnat-104-133-229-106.corp.google.com
corpnat-104-133-209-79.corp.google.com
guestnat-104-133-222-101.corp.google.com
mailio0-f180.google.com
corpnat-104-132-171-86.corp.google.com
corpnat-104-132-239-95.corp.google.com
guestnat-104-132-98-100.corp.google.com
google-proxy-66-102-9-147.google.com
video.l.google.com
corpnat-104-132-173-83.corp.google.com
corpnat-104-133-72-82.corp.google.com
corpnat-104-133-73-89.corp.google.com
malachite-staging.corp.google.com
1mn6gtn.feedproxy.ghs.google.com
google-proxy-66-249-84-114.google.com
googleproxy-66-249-85-83.google.com
rate-limited-proxy-108-177-66-0.google.com
da-twd-8.da.ext.google.com
corpnat-104-132-42-92.corp.google.com
corpnat-104-132-9-87.corp.google.com
ewe-hb-ggc-node3-207.cache.google.com
corpnat-104-133-254-91.corp.google.com
guestnat-104-132-163-100.corp.google.com
guestnat-104-132-19-102.corp.google.com
gue
... [truncated]
```

