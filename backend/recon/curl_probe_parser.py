# blackline/backend/recon/curl_probe_parser.py

from typing import Dict, Optional


def parse_curl_headers(stdout: str) -> Dict:

    status: Optional[int] = None
    reason: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None

    lines = stdout.splitlines()

    for line in lines:
        line = line.strip()

        # Status line
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    status = int(parts[1])
                except ValueError:
                    status = None
                reason = " ".join(parts[2:])

        # Headers
        elif line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()

        elif line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip()

        elif line.lower().startswith("content-length:"):
            try:
                content_length = int(line.split(":", 1)[1].strip())
            except ValueError:
                content_length = None

    return {
        "status": status,
        "reason": reason,
        "server": server,
        "content_type": content_type,
        "content_length": content_length,
    }
