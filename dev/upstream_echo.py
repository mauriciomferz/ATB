from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true,"method":"GET"}')

    def do_POST(self):
        body = self._read_body()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true,"method":"POST","body":')
        self.wfile.write(body if body else b"null")
        self.wfile.write(b"}")


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
