import ipaddress
import json
import re
import time
from urllib.parse import quote

import requests

import config


class PassiveRecon:
    def __init__(self, timeout=20):
        self.timeout = timeout
        self.proxies = None
        if config.ENABLE_PROXY and config.PROXY_URL:
            self.proxies = {
                "http": config.PROXY_URL,
                "https": config.PROXY_URL,
            }

    def run(self, target):
        results = []
        findings = []
        new_targets = []
        risk_signals = []

        domain = self._extract_domain(target)
        if domain:
            results.extend(self._crtsh(domain, findings, new_targets, risk_signals))
            results.extend(self._rdap(domain, findings, new_targets, risk_signals))

        ip_value = self._extract_ip(target)
        if ip_value and config.SHODAN_API_KEY:
            results.extend(self._shodan_host(ip_value, findings, new_targets, risk_signals))

        if domain and config.SHODAN_API_KEY:
            results.extend(self._shodan_dns(domain, findings, new_targets, risk_signals))

        analysis = {
            "summary": f"Passive recon collected {len(findings)} findings and {len(new_targets)} targets.",
            "key_findings": findings[:40],
            "new_targets": new_targets[:40],
            "risk_signals": risk_signals[:30],
            "vulnerability_candidates": [],
            "next_focus": "Validate the most promising passive discoveries with active scanning.",
            "confidence": "medium",
        }
        return results, analysis

    def _crtsh(self, domain, findings, new_targets, risk_signals):
        url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
        start = time.time()
        try:
            resp = requests.get(url, timeout=self.timeout, proxies=self.proxies)
            if resp.status_code >= 400:
                return [self._result("passive_crtsh", url, resp.status_code, time.time() - start, resp.text)]
            data = json.loads(resp.text) if resp.text.strip() else []
        except Exception as exc:
            risk_signals.append(f"crt.sh error: {exc}")
            return [self._result("passive_crtsh", url, -1, time.time() - start, str(exc))]

        names = set()
        for item in data:
            name_value = str(item.get("name_value", "")).strip()
            for line in name_value.splitlines():
                candidate = line.strip().lower()
                if candidate and "*" not in candidate:
                    names.add(candidate)
        for name in sorted(names):
            new_targets.append(name)
        findings.append(f"crt.sh returned {len(names)} certificate names for {domain}.")
        return [self._result("passive_crtsh", url, 0, time.time() - start, f"Found {len(names)} names.")]

    def _rdap(self, domain, findings, new_targets, risk_signals):
        url = f"https://rdap.org/domain/{quote(domain)}"
        start = time.time()
        try:
            resp = requests.get(url, timeout=self.timeout, proxies=self.proxies)
            if resp.status_code >= 400:
                return [self._result("passive_rdap", url, resp.status_code, time.time() - start, resp.text)]
            data = resp.json()
        except Exception as exc:
            risk_signals.append(f"RDAP error: {exc}")
            return [self._result("passive_rdap", url, -1, time.time() - start, str(exc))]

        registrar = data.get("registrar", "")
        status = data.get("status", [])
        findings.append(f"RDAP registrar: {registrar or 'unknown'}")
        if status:
            findings.append(f"RDAP status: {status}")
        return [self._result("passive_rdap", url, 0, time.time() - start, "RDAP data collected.")]

    def _shodan_host(self, ip_value, findings, new_targets, risk_signals):
        url = f"https://api.shodan.io/shodan/host/{quote(ip_value)}?key={config.SHODAN_API_KEY}"
        start = time.time()
        try:
            resp = requests.get(url, timeout=self.timeout, proxies=self.proxies)
            if resp.status_code >= 400:
                return [self._result("passive_shodan_host", url, resp.status_code, time.time() - start, resp.text)]
            data = resp.json()
        except Exception as exc:
            risk_signals.append(f"Shodan host error: {exc}")
            return [self._result("passive_shodan_host", url, -1, time.time() - start, str(exc))]

        ports = data.get("ports", [])
        if ports:
            findings.append(f"Shodan reports open ports: {ports[:20]}")
        hostnames = data.get("hostnames", [])
        for host in hostnames:
            if host:
                new_targets.append(host)
        return [self._result("passive_shodan_host", url, 0, time.time() - start, "Shodan host data collected.")]

    def _shodan_dns(self, domain, findings, new_targets, risk_signals):
        url = f"https://api.shodan.io/dns/domain/{quote(domain)}?key={config.SHODAN_API_KEY}"
        start = time.time()
        try:
            resp = requests.get(url, timeout=self.timeout, proxies=self.proxies)
            if resp.status_code >= 400:
                return [self._result("passive_shodan_dns", url, resp.status_code, time.time() - start, resp.text)]
            data = resp.json()
        except Exception as exc:
            risk_signals.append(f"Shodan DNS error: {exc}")
            return [self._result("passive_shodan_dns", url, -1, time.time() - start, str(exc))]

        subs = data.get("subdomains", [])
        for sub in subs:
            candidate = f"{sub}.{domain}"
            new_targets.append(candidate)
        findings.append(f"Shodan DNS returned {len(subs)} subdomains.")
        return [self._result("passive_shodan_dns", url, 0, time.time() - start, "Shodan DNS data collected.")]

    @staticmethod
    def _extract_domain(target):
        value = str(target or "").strip().lower()
        if not value or " " in value:
            return ""
        if value.startswith("http://") or value.startswith("https://"):
            value = re.sub(r"^https?://", "", value)
        value = value.split("/")[0]
        try:
            ipaddress.ip_address(value)
            return ""
        except ValueError:
            return value if "." in value else ""

    @staticmethod
    def _extract_ip(target):
        value = str(target or "").strip().lower()
        if value.startswith("http://") or value.startswith("https://"):
            value = re.sub(r"^https?://", "", value)
        value = value.split("/")[0]
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            return ""

    @staticmethod
    def _result(tool, command, exit_code, duration, output):
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tool": tool,
            "command": command,
            "exit_code": exit_code,
            "output": str(output)[:4000],
            "analysis_input": str(output)[:24000],
            "raw_output_size": len(str(output)),
            "duration_sec": round(duration, 2),
            "timed_out": False,
            "timeout_sec": 0,
            "verification": {"useful": bool(str(output).strip()), "signals": []},
        }
