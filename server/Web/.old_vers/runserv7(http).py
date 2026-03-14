#!/usr/bin/env python3
import http.server
import threading
import time
import os
import sys
import datetime
import logging # Using standard logging module for better control

# --- Configuration ---
SERVE_DIRECTORY = '/home/arsen/servers/self-host/site/TestWeb'
LOG_FILE = '/home/arsen/servers/self-host/site/Web/logs.txt' # Log file for HTTP server
BLACKLIST_FILE = '/home/arsen/servers/self-host/site/Web/blklst.txt'
HTTP_PORT = 850
SERVER_IP = '192.168.31.97'
BLACKLIST_UPDATE_INTERVAL = 60 # seconds

# --- Custom Logger Class ---
class CustomLogger:
    """
    A custom logger class that redirects stdout/stderr to both the terminal
    and a specified log file. It uses Python's standard `logging` module
    for file output for better control and features like timestamping.
    """
    def __init__(self, log_file):
        self.log_file = log_file
        self.terminal = sys.stdout # Store original stdout
        
        # Configure a standard logger for file output
        self.file_logger = logging.getLogger(log_file)
        self.file_logger.setLevel(logging.INFO) # Set logging level
        
        # Define formatter for log file entries
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        
        # Create a file handler for writing to the log file
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter) # Apply formatter
        
        # Add the file handler to the logger
        self.file_logger.addHandler(file_handler)

    def write(self, message):
        """
        Writes the message to both the terminal and the log file.
        Messages with content (not just whitespace) are logged to the file.
        """
        # Write to the original terminal
        self.terminal.write(message)
        
        # Write to log file via the standard logger, only if the message has content
        # .strip() removes leading/trailing whitespace, so empty lines are not logged
        if message.strip():
            # The logging module will add its own timestamp, so we don't add it here
            self.file_logger.info(message.strip())

    def flush(self):
        """
        Flushes the buffers for both the terminal and the file logger.
        """
        self.terminal.flush()
        # Flush all handlers associated with the file logger
        for handler in self.file_logger.handlers:
            handler.flush()

# --- Global Blacklist and Lock ---
# `current_blacklist` stores the set of blacklisted IP addresses.
# `blacklist_lock` is a threading.Lock used to ensure thread-safe access
# to `current_blacklist` when it's being read or modified by different threads.
current_blacklist = set()
blacklist_lock = threading.Lock()
# `stop_update_event` is a threading.Event used for graceful shutdown
# of the blacklist update thread.
stop_update_event = threading.Event()

def load_blacklist_safely():
    """
    Loads the blacklist from the specified file in a thread-safe manner.
    It updates the global `current_blacklist` variable.
    """
    global current_blacklist # Declare intent to modify the global variable
    try:
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as file:
            # Read lines, strip whitespace, and filter out empty lines
            new_blacklist = {line.strip() for line in file if line.strip()}
            
            # Acquire the lock before modifying the global blacklist
            with blacklist_lock:
                current_blacklist = new_blacklist
            print(f"Blacklist loaded: {len(current_blacklist)} entries.")
            return current_blacklist
    except FileNotFoundError:
        print(f"Blacklist file '{BLACKLIST_FILE}' not found. Starting with an empty blacklist.")
        # Ensure the global blacklist is an empty set if the file is not found
        with blacklist_lock:
            current_blacklist = set()
        return set()
    except Exception as e:
        print(f"Error loading blacklist file '{BLACKLIST_FILE}': {e}")
        # In case of other errors, return the last known blacklist to avoid disruption
        return current_blacklist

def update_blacklist():
    """
    Periodically reloads the blacklist. This function runs in a separate thread.
    It uses `stop_update_event.wait()` to allow for graceful termination.
    """
    while not stop_update_event.is_set(): # Loop until the stop event is set
        print("Updating blacklist...") # Log before attempting to load
        load_blacklist_safely() # Load the blacklist
        # Wait for the specified interval, or until the stop event is set
        stop_update_event.wait(BLACKLIST_UPDATE_INTERVAL)

# --- Request Handler ---
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler that includes blacklist checking.
    """
    def __init__(self, *args, **kwargs):
        # Change to the directory we want to serve. This ensures the handler
        # serves files from the correct location regardless of where the script is run.
        os.chdir(SERVE_DIRECTORY)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """
        Handles GET requests. Checks if the client's IP address is in the blacklist.
        If blacklisted, sends a 403 Forbidden response; otherwise, serves the file.
        """
        client_ip = self.client_address[0] # Get client IP address
        requested_path = self.path # Get the requested path
        print(f"Request from: {client_ip} -> {requested_path}")

        # Acquire the lock before checking the blacklist to ensure thread safety
        with blacklist_lock:
            if client_ip in current_blacklist:
                print(f"BLOCKED: {client_ip} - Access Denied")
                # Send a 403 Forbidden error response
                self.send_error(403, "Access Denied")
                return # Stop processing this request
            else:
                # If not blacklisted, proceed with default file serving behavior
                super().do_GET()

    def log_message(self, format, *args):
        """
        Overrides the default log_message to route logs through our custom logger.
        """
        # This message will be routed through our CustomLogger due to sys.stdout/stderr redirect
        print(f"HTTP: {format % args}")

# --- Main Server Logic ---
if __name__ == "__main__":
    # Redirect stdout and stderr to our custom logger *before* starting any threads or servers.
    sys.stdout = CustomLogger(LOG_FILE)
    sys.stderr = CustomLogger(LOG_FILE)

    print(f"Serving files from: {os.getcwd()}")

    # Perform an initial load of the blacklist at startup
    load_blacklist_safely()

    # Start the blacklist update thread.
    # `daemon=True` means the thread will automatically exit when the main program exits.
    update_thread = threading.Thread(target=update_blacklist)
    update_thread.daemon = True
    update_thread.start()

    # Create the HTTP server instance
    httpd = http.server.HTTPServer((SERVER_IP, HTTP_PORT), RequestHandler)

    print(f"HTTP Server starting on http://{SERVER_IP}:{HTTP_PORT}/")
    print("=" * 50) # Separator for console output

    try:
        # Start serving requests indefinitely
        httpd.serve_forever()
    except KeyboardInterrupt:
        # Handle Ctrl+C (KeyboardInterrupt) to gracefully stop the server
        print("\nServer stopped. Signaling blacklist update thread to stop...")
        stop_update_event.set() # Signal the update thread to stop
        # Wait for the update thread to finish its current cycle and exit (with a timeout)
        update_thread.join(timeout=5)
        if update_thread.is_alive():
            print("Blacklist update thread did not terminate gracefully.")
    except Exception as e:
        # Catch any other unexpected exceptions during server operation
        print(f"Server error: {e}")
        stop_update_event.set() # Also signal stop event on other errors
        update_thread.join(timeout=5) # Attempt to join the thread
