"""
attacker_server.py - local exfiltration catcher used ONLY by run_experiment_B.py.

This stands in for an attacker-controlled server on the public internet.
For the experiment it binds to 127.0.0.1:9099 and logs whatever gets POSTed
to /collect, so we can prove - or disprove - that data left the "victim"
process. It never talks to anything outside localhost.

Run standalone for manual testing:
    python attacker_server.py
Then Ctrl+C to stop, or import `start_in_background()` / `stop()` from
run_experiment_B.py to control it programmatically.
"""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"
PORT = 9099

captured = []  # list of dicts: {"source_file": ..., "byte_count": ..., "raw_b64": ...}


class CollectorHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/collect":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        source_file = self.headers.get("X-Source-File", "<unknown>")
        captured.append({
            "source_file": source_file,
            "byte_count_b64": len(body),
            "byte_count_decoded": len(base64.b64decode(body)) if body else 0,
            "raw_b64_prefix": body[:60].decode(errors="replace"),
        })
        print(f"[ATTACKER] Received {len(body)} bytes (base64) claiming to be: {source_file}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *a):
        pass  # keep stdout clean; we print our own [ATTACKER] lines above


_server = None
_thread = None


def start_in_background():
    global _server, _thread
    captured.clear()
    _server = HTTPServer((HOST, PORT), CollectorHandler)
    _thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _thread.start()
    print(f"[ATTACKER] Listening on http://{HOST}:{PORT}/collect")


def stop():
    global _server
    if _server is not None:
        _server.shutdown()
        _server.server_close()
        _server = None
        print("[ATTACKER] Server stopped.")


def summary():
    return json.dumps(captured, indent=2)


if __name__ == "__main__":
    start_in_background()
    print("[ATTACKER] Ctrl+C to stop.")
    try:
        _thread.join()
    except KeyboardInterrupt:
        stop()
