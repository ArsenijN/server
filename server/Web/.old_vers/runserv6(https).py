#!/usr/bin/env python3
import http.server
import ssl
import threading
import time
import os
import sys
import datetime

# Change to the directory you want to serve
os.chdir('/home/arsen/servers/self-host/site/TestWeb')

# Set up logging
LOG_FILE = '/home/arsen/servers/self-host/site/Web/logsV2.txt'

class Logger:
    def __init__(self, log_file):
        self.log_file = log_file
        self.terminal = sys.stdout
        
    def write(self, message):
        timestamp = datetime.datetime.now().strftime('[%Y-%m-%d %H:%M:%S] ')
        if message.strip():  # Only add timestamp to non-empty messages
            formatted_message = timestamp + message
        else:
            formatted_message = message
            
        # Write to terminal
        self.terminal.write(formatted_message)
        
        # Write to log file
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(formatted_message)
            
    def flush(self):
        self.terminal.flush()

# Redirect stdout to our logger
sys.stdout = Logger(LOG_FILE)
sys.stderr = Logger(LOG_FILE)

# Define the path to the blacklist file
BLACKLIST_FILE = '/home/arsen/servers/self-host/site/Web/blklst.txt'

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"Request from: {self.client_address[0]} -> {self.path}")
        if self.client_address[0] in load_blacklist():
            print(f"BLOCKED: {self.client_address[0]} - Access Denied")
            self.send_error(403, "Access Denied", explain="Access Denied. If your IP blocked accidentally - please connect with the owner of this website by write in address link phrase '...&ABUSE=[contact information]&'. Thanks")
            return
        else:
            super().do_GET()
            
    def log_message(self, format, *args):
        # Override the default log_message to use our custom format
        print(f"HTTPS: {format % args}")

def load_blacklist():
    try:
        with open(BLACKLIST_FILE, 'r') as file:
            blacklist = {line.strip() for line in file}
            print(f"Blacklist loaded: {len(blacklist)} entries")
            return blacklist
    except FileNotFoundError:
        print(f"Blacklist file '{BLACKLIST_FILE}' not found.")
        return set()

def update_blacklist():
    while True:
        time.sleep(60)  # Check every minute
        print("Updating blacklist...")

# Start a thread to continuously update the blacklist
update_thread = threading.Thread(target=update_blacklist)
update_thread.daemon = True
update_thread.start()

# Create HTTP server
httpd = http.server.HTTPServer(('192.168.31.97', 1000), RequestHandler)

# Create SSL context (modern way)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile='/home/arsen/servers/self-host/site/Web/myCA.pem',
    keyfile='/home/arsen/servers/self-host/site/Web/myCA.key'
)

# Wrap the socket with SSL
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"Server starting on https://192.168.31.97:1000/")
print(f"Serving files from: {os.getcwd()}")
print("=" * 50)
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nServer stopped.")
except Exception as e:
    print(f"Server error: {e}")
