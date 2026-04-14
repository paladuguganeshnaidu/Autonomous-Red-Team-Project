from urllib.parse import urlparse


class ReconAgent:
    def __init__(self, target):
        self.target = target
        self.network_target = self._normalize_network_target(target)

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
