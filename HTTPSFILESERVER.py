import os
import ssl
import sys
import threading
import time
import http.server
import configparser
from http.server import HTTPServer
from socketserver import ThreadingMixIn

# Load configuration from file
CONFIG_FILE = 'server.cfg'
config = configparser.ConfigParser()
if not os.path.exists(CONFIG_FILE):
    print(f"Configuration file '{CONFIG_FILE}' not found.")
    sys.exit(1)
config.read(CONFIG_FILE)

# Configuration section
try:
    section = config['server']
    PORT = section.getint('port')
    DIRECTORY = section.get('directory')
    CERT_FILE = section.get('cert_file')
    KEY_FILE = section.get('key_file')
    MAX_CONNECTIONS = section.getint('max_connections', fallback=100)
    BLACKLIST_IP_FILE = section.get('blacklist_ip_file', fallback='blacklist_ips.txt')
    BLACKLIST_DOMAIN_FILE = section.get('blacklist_domain_file', fallback='blacklist_domains.txt')
    RELOAD_INTERVAL = section.getint('reload_interval', fallback=60)
except KeyError as e:
    print(f"Missing configuration option: {e}")
    sys.exit(1)

# Semaphore to throttle connections
active_connections = threading.Semaphore(MAX_CONNECTIONS)

# Global blacklist sets
BLACKLISTED_IPS = set()
BLACKLISTED_DOMAINS = set()

# Load blacklists
def load_blacklist(file_path):
    try:
        with open(file_path, 'r') as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        return set()

# Background thread to reload blacklists periodically
def reload_blacklists():
    global BLACKLISTED_IPS, BLACKLISTED_DOMAINS
    while True:
        ip_set = load_blacklist(BLACKLIST_IP_FILE)
        domain_set = load_blacklist(BLACKLIST_DOMAIN_FILE)
        if ip_set != BLACKLISTED_IPS or domain_set != BLACKLISTED_DOMAINS:
            BLACKLISTED_IPS = ip_set
            BLACKLISTED_DOMAINS = domain_set
            print(f"Reloaded blacklists: {len(BLACKLISTED_IPS)} IPs, {len(BLACKLISTED_DOMAINS)} domains")
        time.sleep(RELOAD_INTERVAL)

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        host = self.headers.get('Host', '')
        if client_ip in BLACKLISTED_IPS:
            return  # silently drop
        if host in BLACKLISTED_DOMAINS:
            self.send_response(403)
            self.end_headers()
            return
        if self.path in ('/', '/index.html'):
            self.path = '/index.html'
        return super().do_GET()

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

class ThreadedSecureHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, HandlerClass, ssl_context):
        super().__init__(server_address, HandlerClass)
        self.ssl_context = ssl_context

    def get_request(self):
        while True:
            raw_sock, addr = super().get_request()
            client_ip = addr[0]
            if client_ip in BLACKLISTED_IPS:
                raw_sock.close()
                continue
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
    def do_GET(self):
        client_ip = self.client_address[0]
        host = self.headers.get('Host', '')
        if client_ip in BLACKLISTED_IPS:
            return
        if host in BLACKLISTED_DOMAINS:
            self.send_response(403)
            self.end_headers()
            return
        https_url = f"https://{host}{self.path}"
        self.send_response(301)
        self.send_header('Location', https_url)
        self.end_headers()

    def log_message(self, format, *args):
        return

class ThreadedHTTPRedirectServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def get_request(self):
        while True:
            raw_sock, addr = super().get_request()
            client_ip = addr[0]
            if client_ip in BLACKLISTED_IPS:
                raw_sock.close()
                continue
            return raw_sock, addr

if __name__ == '__main__':
    # Initial load of blacklists
    BLACKLISTED_IPS = load_blacklist(BLACKLIST_IP_FILE)
    BLACKLISTED_DOMAINS = load_blacklist(BLACKLIST_DOMAIN_FILE)
    print(f"Loaded blacklists: {len(BLACKLISTED_IPS)} IPs, {len(BLACKLISTED_DOMAINS)} domains")

    # Start blacklist reloader thread
    threading.Thread(target=reload_blacklists, daemon=True).start()

    # Validate paths
    for path in (CERT_FILE, KEY_FILE, DIRECTORY):
        if not os.path.exists(path):
            print(f"Error: Path not found: {path}")
            sys.exit(1)

    os.chdir(DIRECTORY)

    # Configure SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    context.set_ciphers('ECDHE+AESGCM')
    try:
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except ssl.SSLError as e:
        print(f"Failed to load certificate chain: {e}")
        sys.exit(1)

    # Start HTTP redirect server on port 80
    redirect_server = ThreadedHTTPRedirectServer(('0.0.0.0', 80), RedirectHandler)
    threading.Thread(target=redirect_server.serve_forever, daemon=True).start()
    print("HTTP redirect server running on port 80 → HTTPS")

    # Setup HTTPS server start function
    https_server = None
    https_thread = None

    def start_https_server():
        global https_server, https_thread
        if https_server:
            try:
                https_server.server_close()
            except Exception:
                pass
        https_server = ThreadedSecureHTTPServer(('0.0.0.0', PORT), MyHandler, context)
        https_thread = threading.Thread(target=https_server.serve_forever, daemon=True)
        https_thread.start()
        print(f"HTTPS server started on port {PORT}")

    # Start HTTPS server initially
    start_https_server()

    # Watchdog to restart HTTPS server if thread dies
    def https_watchdog():
        while True:
            time.sleep(30)
            if not https_thread.is_alive():
                print("Watchdog: HTTPS server thread stopped, restarting...")
                start_https_server()

    threading.Thread(target=https_watchdog, daemon=True).start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        if https_server:
            https_server.server_close()
        redirect_server.server_close()
        print("Servers closed.")
