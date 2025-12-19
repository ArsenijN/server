#!/usr/bin/env python3
import sys
import os
import threading
import time
import logging
import urllib.request
import traceback
import socket
import ssl

# Shared event used by the HTTP server health-check to wait until server is ready
server_ready = threading.Event()

# Global blacklist and synchronization primitives
current_blacklist = set()
blacklist_lock = threading.Lock()
stop_update_event = threading.Event()

# --- Custom Logger ---
class CustomLogger:
    def __init__(self, log_file):
        self.log_file = log_file
        self.terminal = sys.stdout
        self.file_logger = logging.getLogger(log_file)
        self.file_logger.setLevel(logging.INFO)
        # Prevent this logger from propagating to the root logger to avoid recursion
        self.file_logger.propagate = False
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.file_logger.addHandler(file_handler)

    def write(self, message):
        self.terminal.write(message)
        if message.strip():
            self.file_logger.info(message.strip())

    def flush(self):
        try:
            self.terminal.flush()
        except Exception:
            pass
        for handler in self.file_logger.handlers:
            try:
                handler.flush()
            except Exception:
                pass

# --- Blacklist utilities ---

def load_blacklist_safely(blacklist_file):
    global current_blacklist
    try:
        with open(blacklist_file, 'r', encoding='utf-8') as file:
            new_blacklist = {line.strip() for line in file if line.strip()}
            with blacklist_lock:
                current_blacklist = new_blacklist
        print(f"Blacklist loaded: {len(current_blacklist)} entries.")
        return current_blacklist
    except FileNotFoundError:
        print(f"Blacklist file '{blacklist_file}' not found. Starting with an empty blacklist.")
        with blacklist_lock:
            current_blacklist = set()
        return set()
    except Exception as e:
        print(f"Error loading blacklist file '{blacklist_file}': {e}")
        return current_blacklist


def update_blacklist(blacklist_file, interval, stop_event):
    while not stop_event.is_set():
        print("Updating blacklist...")
        load_blacklist_safely(blacklist_file)
        stop_event.wait(interval)

# --- Health check / restart utilities ---

def restart_server():
    print("Restarting server due to failed health check...")
    python = sys.executable
    os.execv(python, [python] + sys.argv)


def health_check_self_ping_http(server_ip, http_port):
    url = f"http://{server_ip}:{http_port}/"
    print("Health check waiting for server to be ready...")
    server_ready.wait()
    time.sleep(10)
    consecutive_failures = 0
    max_failures = 3
    while True:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    consecutive_failures = 0
                    print(f"Health check OK (status: {response.status})")
                else:
                    consecutive_failures += 1
                    print(f"Health check failed: status {response.status} (failure {consecutive_failures}/{max_failures})")
                    if consecutive_failures >= max_failures:
                        restart_server()
                        return
        except Exception as e:
            consecutive_failures += 1
            print(f"Health check failed: {e} (failure {consecutive_failures}/{max_failures})")
            if consecutive_failures >= max_failures:
                restart_server()
                return
        time.sleep(30)


def health_check_self_ping_https(server_ip, https_port):
    url = f"https://{server_ip}:{https_port}/"
    while True:
        try:
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(url, timeout=5, context=ctx) as response:
                if response.status != 200:
                    print(f"Health check failed: status {response.status}")
                    restart_server()
                    return
        except Exception as e:
            print(f"Health check failed: {e}\n{traceback.format_exc()}")
            restart_server()
            return
        time.sleep(30)
