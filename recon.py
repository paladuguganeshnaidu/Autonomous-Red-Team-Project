# recon.py
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import config


class ReconAgent:
    def __init__(self, target):
        self.target = target
        self.network_target = self._normalize_network_target(target)

    def quick_scan(self):
        """Fast nmap scan, returns open ports and services"""
        # Use connect scan + -Pn to work better on hosts that block ICMP or raw probes.
        cmd = [config.NMAP_PATH, "-sT", "-F", "-sV", "-Pn", "-oX", "-", self.network_target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                return {"error": (result.stderr or result.stdout or "nmap failed").strip()}
            if not result.stdout.strip():
                return {"error": "Nmap returned empty output."}

            # Parse XML output
            root = ET.fromstring(result.stdout)
            open_ports = []
            services = {}
            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    state_elem = port.find('state')
                    if state_elem is None:
                        continue
                    state = state_elem.get('state')
                    if state == 'open':
                        service_elem = port.find('service')
                        service = service_elem.get('name') if service_elem is not None else 'unknown'
                        if port_id and port_id not in open_ports:
                            open_ports.append(port_id)
                        services[port_id] = service
            return {
                "target": self.target,
                "network_target": self.network_target,
                "open_ports": open_ports,
                "services": services,
                "raw_nmap": result.stdout[:1000]
            }
        except FileNotFoundError:
            return {"error": f"Nmap executable not found: {config.NMAP_PATH}"}
        except ET.ParseError:
            return {"error": "Failed to parse nmap XML output."}
        except Exception as e:
            return {"error": str(e)}

    def enumerate_subdomains(self):
        """Optional – requires subfinder installed"""
        try:
            cmd = [config.SUBFINDER_PATH, "-d", self.network_target, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            subs = result.stdout.strip().split('\n')
            return [s for s in subs if s]
        except:
            return []

    def build_web_urls(self, open_ports):
        urls = []
        host = self.network_target
        for port in open_ports:
            if port == "443":
                urls.append(f"https://{host}")
            elif port == "80":
                urls.append(f"http://{host}")
            elif port in {"8080", "8000", "8888", "5357", "5000", "3000"}:
                urls.append(f"http://{host}:{port}")
            elif port == "8443":
                urls.append(f"https://{host}:{port}")
        return urls

    @staticmethod
    def _normalize_network_target(target):
        value = (target or "").strip()
        if "://" in value:
            parsed = urlparse(value)
            if parsed.hostname:
                return parsed.hostname
        if "/" in value:
            return value.split("/")[0]
        return value