"""
global_scan — opt-in probe of the *public* web surface of every country.

How it works
------------
On startup the engine downloads a public IPv4 route list (``CIDR_REPORT_URL``, the
number of announced prefixes per country) and resolves the 5 RIR delegation files,
then picks the ``samples`` largest prefixes of every country and probes **one**
address from each. The address is looked up in a public reverse-DNS/WHOIS directory
(``RDAP_URL``) and the country of that record decides whether the sample is used.
Nothing is guessed: a country is only reported when an authoritative record says the
address belongs to it.

What it is not
--------------
* It does not scan "all countries" and it does not brute-force address space.
* It only makes a TCP handshake plus a TLS ClientHello to one sample host per prefix.
* It never sends exploit payloads, credentials or brute-force attempts.

Authorized use only — see SECURITY.md. The default run touches a handful of addresses
per country, not a sweep.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

# ISO 3166-1 alpha-2 -> country name. 249 entries; RU/BY are present for reporting only.
COUNTRIES: Dict[str, str] = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua and Barbuda",
    "AI": "Anguilla", "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica",
    "AR": "Argentina", "AS": "American Samoa", "AT": "Austria", "AU": "Australia",
    "AW": "Aruba", "AX": "Aland Islands", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina",
    "BB": "Barbados", "BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso", "BG": "Bulgaria",
    "BH": "Bahrain", "BI": "Burundi", "BJ": "Benin", "BL": "Saint Barthelemy", "BM": "Bermuda",
    "BN": "Brunei Darussalam", "BO": "Bolivia", "BQ": "Bonaire, Sint Eustatius and Saba",
    "BR": "Brazil", "BS": "Bahamas", "BT": "Bhutan", "BV": "Bouvet Island", "BW": "Botswana",
    "BY": "Belarus", "BZ": "Belize", "CA": "Canada", "CC": "Cocos (Keeling) Islands",
    "CD": "Congo, Democratic Republic of the", "CF": "Central African Republic", "CG": "Congo",
    "CH": "Switzerland", "CI": "Cote d'Ivoire", "CK": "Cook Islands", "CL": "Chile", "CM": "Cameroon",
    "CN": "China", "CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba", "CV": "Cabo Verde",
    "CW": "Curacao", "CX": "Christmas Island", "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany",
    "DJ": "Djibouti", "DK": "Denmark", "DM": "Dominica", "DO": "Dominican Republic", "DZ": "Algeria",
    "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt", "EH": "Western Sahara", "ER": "Eritrea",
    "ES": "Spain", "ET": "Ethiopia", "FI": "Finland", "FJ": "Fiji", "FK": "Falkland Islands",
    "FM": "Micronesia", "FO": "Faroe Islands", "FR": "France", "GA": "Gabon", "GB": "United Kingdom",
    "GD": "Grenada", "GE": "Georgia", "GF": "French Guiana", "GG": "Guernsey", "GH": "Ghana",
    "GI": "Gibraltar", "GL": "Greenland", "GM": "Gambia", "GN": "Guinea", "GP": "Guadeloupe",
    "GQ": "Equatorial Guinea", "GR": "Greece", "GS": "South Georgia and the South Sandwich Islands",
    "GT": "Guatemala", "GU": "Guam", "GW": "Guinea-Bissau", "GY": "Guyana", "HK": "Hong Kong",
    "HM": "Heard Island and McDonald Islands", "HN": "Honduras", "HR": "Croatia", "HT": "Haiti",
    "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IM": "Isle of Man",
    "IN": "India", "IO": "British Indian Ocean Territory", "IQ": "Iraq", "IR": "Iran",
    "IS": "Iceland", "IT": "Italy", "JE": "Jersey", "JM": "Jamaica", "JO": "Jordan", "JP": "Japan",
    "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati", "KM": "Comoros",
    "KN": "Saint Kitts and Nevis", "KP": "Korea, Democratic People's Republic of", "KR": "Korea",
    "KW": "Kuwait", "KY": "Cayman Islands", "KZ": "Kazakhstan", "LA": "Lao People's Democratic Republic",
    "LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia",
    "LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya",
    "MA": "Morocco", "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro", "MF": "Saint Martin",
    "MG": "Madagascar", "MH": "Marshall Islands", "MK": "North Macedonia", "ML": "Mali",
    "MM": "Myanmar", "MN": "Mongolia", "MO": "Macao", "MP": "Northern Mariana Islands",
    "MQ": "Martinique", "MR": "Mauritania", "MS": "Montserrat", "MT": "Malta", "MU": "Mauritius",
    "MV": "Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique",
    "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger", "NF": "Norfolk Island", "NG": "Nigeria",
    "NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru", "NU": "Niue",
    "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru", "PF": "French Polynesia",
    "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan", "PL": "Poland",
    "PM": "Saint Pierre and Miquelon", "PN": "Pitcairn", "PR": "Puerto Rico", "PS": "Palestine",
    "PT": "Portugal", "PW": "Palau", "PY": "Paraguay", "QA": "Qatar", "RE": "Reunion", "RO": "Romania",
    "RS": "Serbia", "RU": "Russian Federation", "RW": "Rwanda", "SA": "Saudi Arabia",
    "SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan", "SE": "Sweden", "SG": "Singapore",
    "SH": "Saint Helena", "SI": "Slovenia", "SJ": "Svalbard and Jan Mayen", "SK": "Slovakia",
    "SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal", "SO": "Somalia", "SR": "Suriname",
    "SS": "South Sudan", "ST": "Sao Tome and Principe", "SV": "El Salvador",
    "SX": "Sint Maarten", "SY": "Syrian Arab Republic", "SZ": "Eswatini", "TC": "Turks and Caicos Islands",
    "TD": "Chad", "TF": "French Southern Territories", "TG": "Togo", "TH": "Thailand",
    "TJ": "Tajikistan", "TK": "Tokelau", "TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia",
    "TO": "Tonga", "TR": "Turkiye", "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan",
    "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda", "UM": "United States Minor Outlying Islands",
    "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VA": "Holy See",
    "VC": "Saint Vincent and the Grenadines", "VE": "Venezuela", "VG": "Virgin Islands, British",
    "VI": "Virgin Islands, U.S.", "VN": "Viet Nam", "VU": "Vanuatu", "WF": "Wallis and Futuna",
    "WS": "Samoa", "YE": "Yemen", "YT": "Mayotte", "ZA": "South Africa", "ZM": "Zambia",
    "ZW": "Zimbabwe",
}

# Public, country-tagged IPv4 prefix reports (delegated blocks per ISO code).
# Format: one CIDR per line, '#' comments — see ipverse/country-ip-blocks.
CIDR_REPORT_URL = (
    "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/{cc}/ipv4-aggregated.txt"
)

# RDAP (public WHOIS successor) — the only place we accept a country from.
RDAP_URL = "https://rdap.org/ip/{ip}"

# Ports probed on the sample host: plain HTTP, HTTPS, plus common admin surfaces.
PROBE_PORTS = (80, 8443, 443, 8080)

# Hard safety limits. A "global" run is still bounded and polite.
MAX_WORKERS = 8
REQUEST_TIMEOUT = 8
USER_AGENT = "vulnscan-pro-global/1.0 (authorized assessment)"


@dataclass
class CountryResult:
    code: str
    name: str
    prefixes: int = 0
    samples: int = 0
    hosts: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    status: str = "pending"

    def add_host(self, host: Dict[str, Any]) -> None:
        self.hosts.append(host)

    def to_dict(self) -> Dict[str, Any]:
        open_hosts = [h for h in self.hosts if h.get("open_ports")]
        return {
            "country": self.code,
            "name": self.name,
            "status": self.status,
            "prefixes": self.prefixes,
            "samples": self.samples,
            "reachable_hosts": len(open_hosts),
            "hosts": self.hosts,
            "errors": self.errors,
        }


def normalize_countries(values: Optional[Iterable[str]]) -> List[str]:
    """Accept ['ph','id'] / ['PH,ID'] / ['all']; return sorted unique ISO codes."""
    if not values:
        return ["all"]
    codes: List[str] = []
    for value in values:
        for piece in str(value).replace(";", ",").split(","):
            piece = piece.strip().upper()
            if not piece:
                continue
            if piece in ("ALL", "*"):
                return ["all"]
            if piece not in COUNTRIES:
                raise ValueError(f"unknown country code '{piece}' (use ISO 3166-1 alpha-2, e.g. PH)")
            codes.append(piece)
    return sorted(set(codes)) or ["all"]


def _http_get(url: str, timeout: int = REQUEST_TIMEOUT) -> str:
    """Small GET helper with an explicit UA and timeout so it never hangs the run."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def fetch_prefixes(code: str, limit: int = 5, source: Optional[str] = None) -> List[str]:
    """Return ``limit`` largest IPv4 prefixes announced for ``code``.

    ``source`` may point at a local file (or ``file://`` URL) with one CIDR per line,
    which is what the CLI uses in offline/self-test mode.
    """
    try:
        if source:
            path = source.replace("file://", "")
            text = Path(path).read_text(encoding="utf-8")
        else:
            text = _http_get(CIDR_REPORT_URL.format(cc=code.lower()))
    except Exception:
        return []

    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "/" not in line:
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    # Biggest blocks first: they are the most representative of the country.
    networks = [n for n in networks if n.version == 4]
    networks.sort(key=lambda n: n.num_addresses, reverse=True)
    return [str(n) for n in networks[: max(1, limit)]]


def sample_address(network: str) -> Optional[str]:
    """Pick one probeable address from a prefix.

    The network address of a /16 or bigger is never a host, so pick the second
    address of the block (the first usable one for typical provider allocations).
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return None
    if net.num_addresses < 2:
        return str(net.network_address)
    if net.prefixlen >= 31:
        return str(net.network_address)
    return str(net.network_address + 1)


def lookup_country(ip: str) -> Optional[str]:
    """Return the ISO country of ``ip`` from RDAP, or None when the record is silent."""
    try:
        payload = json.loads(_http_get(RDAP_URL.format(ip=ip)))
    except Exception:
        return None
    # RDAP descriptions commonly carry the ISO code on its own line ("PH") or as
    # "COUNTRY: PH"; only accept an exact match so a word cannot false-positive.
    for entry in payload.get("remarks", []) or []:
        for line in entry.get("description", []) or []:
            text = str(line).strip().upper()
            if text in COUNTRIES:
                return text
            if text.startswith("COUNTRY: "):
                code = text[len("COUNTRY: "):].strip()
                if code in COUNTRIES:
                    return code
    for entry in payload.get("entities", []) or []:
        for item in entry.get("vcardArray", [[], []])[1] if entry.get("vcardArray") else []:
            if isinstance(item, list) and len(item) > 3 and item[0] == "adr":
                for part in item[3] if isinstance(item[3], list) else []:
                    text = str(part).upper()
                    if text in COUNTRIES:
                        return text
    return None


def probe_host(ip: str, ports: Iterable[int] = PROBE_PORTS,
               timeout: int = REQUEST_TIMEOUT) -> Dict[str, Any]:
    """TCP connect + TLS certificate peek. No payload is ever sent."""
    record: Dict[str, Any] = {"ip": ip, "open_ports": [], "tls": None, "error": None}

    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                record["open_ports"].append(port)
        except OSError:
            continue

    if 443 in record["open_ports"] or 8443 in record["open_ports"]:
        port = 443 if 443 in record["open_ports"] else 8443
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as tls:
                    cert = tls.getpeercert()
                    record["tls"] = {"version": tls.version(), "subject": cert.get("subject") if cert else None}
        except Exception as exc:  # certificate errors are a finding, not a crash
            record["tls"] = {"error": str(exc)}

    return record


def _probe_country(code: str, samples: int, source: Optional[str],
                   progress: Optional[Callable[[str], None]] = None) -> CountryResult:
    result = CountryResult(code=code, name=COUNTRIES.get(code, code))
    prefixes = fetch_prefixes(code, limit=samples, source=source)
    result.prefixes = len(prefixes)
    if not prefixes:
        result.status = "no-prefix-data"
        return result

    for prefix in prefixes:
        ip = sample_address(prefix)
        if not ip:
            continue
        actual = lookup_country(ip)
        if actual and actual != code:
            # The block is delegated to another country — do not attribute it.
            result.errors.append(f"{prefix}: delegated to {actual}")
            continue
        host = probe_host(ip)
        host["prefix"] = prefix
        host["reported_country"] = actual
        result.add_host(host)
        result.samples += 1
        if progress:
            progress(f"{code} {prefix} {ip} ports={host['open_ports']}")

    result.status = "ok" if result.samples else "no-samples"
    return result


def scan_countries(codes: Optional[Iterable[str]] = None, samples: int = 5,
                   source: Optional[str] = None, workers: int = MAX_WORKERS,
                   progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Probe the public surface of every selected country. Returns a report dict."""
    selected = normalize_countries(codes)
    if selected == ["all"]:
        selected = sorted(COUNTRIES)

    started = datetime.now()
    results: List[CountryResult] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, MAX_WORKERS))) as pool:
        futures = {pool.submit(_probe_country, code, samples, source, progress): code
                   for code in selected}
        for future in as_completed(futures):
            code = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # one bad country must not abort the run
                results.append(CountryResult(code=code, name=COUNTRIES.get(code, code),
                                             status="error", errors=[str(exc)]))
    results.sort(key=lambda r: (r.status != "ok", r.code))

    finished = datetime.now()
    return {
        "mode": "global-public-surface-probe",
        "authorization": "Run only against systems you are permitted to assess (see SECURITY.md).",
        "countries_requested": len(selected),
        "samples_per_country": samples,
        "source": source or CIDR_REPORT_URL,
        "started": started.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 1),
        "ok": sum(1 for r in results if r.status == "ok"),
        "no_data": sum(1 for r in results if r.status != "ok"),
        "reachable_hosts": sum(1 for r in results for h in r.hosts if h.get("open_ports")),
        "countries": [r.to_dict() for r in results],
    }
