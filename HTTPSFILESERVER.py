import os
import ssl
import sys
import threading
import http.server
from http.server import HTTPServer
from socketserver import ThreadingMixIn

# Configuration
PORT = 4443
DIRECTORY = r'C:\home'    # Directory to serve
CERT_FILE = r'C:\certs\fullchain.pem'  # Full chain: leaf + intermediates
KEY_FILE = r'C:\certs\private.key.pem'  # Ensure this file has strict permissions (e.g., chmod 600)
MAX_CONNECTIONS = 100  # Limit simultaneous connections to mitigate DoS risk
BLACKLIST_IP_FILE = r'C:/blacklist/blacklist_ips.txt'
BLACKLIST_DOMAIN_FILE = r'C:/blacklist/blacklist_domains.txt'

# Semaphore to throttle connections
active_connections = threading.Semaphore(MAX_CONNECTIONS)

# Load blacklists
def load_blacklist(file_path):
    try:
        with open(file_path, 'r') as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        return set()

BLACKLISTED_IPS = load_blacklist(BLACKLIST_IP_FILE)
BLACKLISTED_DOMAINS = load_blacklist(BLACKLIST_DOMAIN_FILE)

class MyHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler to add CORS headers, serve front page, and enforce blacklists."""
    def do_GET(self):
        client_ip = self.client_address[0]
        host = self.headers.get('Host', '')

        if client_ip in BLACKLISTED_IPS or host in BLACKLISTED_DOMAINS:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden: Access is denied.')
            return

        # Serve index.html for root
        if self.path in ('/', '/index.html'):
            self.path = '/index.html'
        return super().do_GET()

    def end_headers(self):
        # Allow all origins
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

class ThreadedSecureHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTPS server with SSL, connection throttling, and benign-error suppression."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, HandlerClass, ssl_context):
        super().__init__(server_address, HandlerClass)
        self.ssl_context = ssl_context

    def get_request(self):
        while True:
            raw_sock, addr = super().get_request()
            raw_sock.setblocking(True)
            try:
                ssl_sock = self.ssl_context.wrap_socket(raw_sock, server_side=True)
                return ssl_sock, addr
            except ssl.SSLError as e:
                msg = str(e)
                if 'EOF occurred in violation of protocol' in msg or 'HTTP_REQUEST' in msg:
                    raw_sock.close()
                    continue
                raise

    def process_request_thread(self, request, client_address):
        with active_connections:
            super().process_request_thread(request, client_address)

class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """HTTP-to-HTTPS redirect handler with blacklist enforcement."""
    def do_GET(self):
        client_ip = self.client_address[0]
        host = self.headers.get('Host', '')

        if client_ip in BLACKLISTED_IPS or host in BLACKLISTED_DOMAINS:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden: Access is denied.')
            return

        https_url = f"https://{host}{self.path}"
        self.send_response(301)
        self.send_header('Location', https_url)
        self.end_headers()

    def log_message(self, format, *args):
        return  # Suppress logging

class ThreadedHTTPRedirectServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == '__main__':
    os.chdir(DIRECTORY)

    # Configure SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    context.set_ciphers('ECDHE+AESGCM')
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # Start HTTP redirect server on port 80
    redirect_server = ThreadedHTTPRedirectServer(('0.0.0.0', 80), RedirectHandler)
    threading.Thread(target=redirect_server.serve_forever, daemon=True).start()
    print("HTTP redirect server running on port 80 → HTTPS")

    # Start HTTPS server on port 443
    https_server = ThreadedSecureHTTPServer(('0.0.0.0', PORT), MyHandler, context)
    print(f"Serving HTTPS on port {PORT} with max {MAX_CONNECTIONS} connections")
    try:
        https_server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        https_server.server_close()
        redirect_server.server_close()
        print("Servers closed.")
