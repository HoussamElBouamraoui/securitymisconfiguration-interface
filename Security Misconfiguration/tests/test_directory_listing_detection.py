import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from a02_security_misconfiguration.core.base_check import CheckConfig
from a02_security_misconfiguration.web.directory_listing_detection import DirectoryListingDetection


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Always return a simplistic directory listing signature
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><title>Index of /</title><body>Parent Directory</body></html>")

    def log_message(self, format, *args):
        return


@pytest.fixture()
def http_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://{host}:{port}"
    server.shutdown()


def test_directory_listing_detected(http_server):
    cfg = CheckConfig(connect_timeout=0.5, read_timeout=0.5)
    check = DirectoryListingDetection(cfg)
    r = check.run(http_server)
    d = r.to_dict()
    assert d["scan_type"] == "A02_Directory_Listing_Detection"
    assert d["status"] == "completed"
    assert d["severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    # Expect at least one hit due to heuristic
    assert any("Directory listing enabled" == f["title"] for f in d["findings"]) or d["severity"] == "HIGH"
