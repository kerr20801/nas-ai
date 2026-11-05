"""
ClamAV INSTREAM scanner — connects to clamd over TCP, streams file bytes,
returns verdict string: "clean" | "virus:<name>" | "error:<reason>"

Never raises — caller decides what to do with "error:*".
"""

import logging
import socket
import struct

log = logging.getLogger(__name__)

_CHUNK = 4096


def scan(data: bytes, host: str = "clamav", port: int = 3310, timeout: int = 15) -> str:
    """Stream data to clamd INSTREAM command. Returns verdict string."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), _CHUNK):
                chunk = data[i : i + _CHUNK]
                sock.sendall(struct.pack("!I", len(chunk)) + chunk)
            sock.sendall(struct.pack("!I", 0))  # end of stream

            response = b""
            while True:
                part = sock.recv(1024)
                if not part:
                    break
                response += part
                if b"\0" in part:
                    break

        resp = response.rstrip(b"\0").decode("utf-8", errors="replace").strip()
        log.debug("clamd response: %s", resp)

        if resp.endswith("OK"):
            return "clean"
        if "FOUND" in resp:
            # format: "stream: Eicar-Test-Signature FOUND"
            parts = resp.split(":")
            virus_name = parts[-1].replace("FOUND", "").strip() if len(parts) > 1 else "unknown"
            return f"virus:{virus_name}"
        return f"error:{resp}"

    except (ConnectionRefusedError, OSError) as e:
        log.warning("ClamAV unavailable (%s:%d): %s", host, port, e)
        return "error:unavailable"
    except Exception as e:
        log.warning("ClamAV scan error: %s", e)
        return f"error:{e}"
