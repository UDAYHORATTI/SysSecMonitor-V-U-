# SysSecMonitor-V-U-
#Advanced System Security Monitoring SysSecMonitor is a real-time system security monitoring tool designed to detect anomalies and unauthorized activities within a Linux environment. It actively monitors processes, file changes, and network traffic, making it a versatile solution for identifying potential threats and intrusions.
import os
import psutil
import time
import hashlib
from scapy.all import sniff
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ------------------------------
# File Integrity Monitoring
# ------------------------------
def check_file_integrity(file_path, original_hashes):
    """Checks if a file's hash matches the original hash to detect unauthorized changes."""
    with open(file_path, "rb") as f:
        file_data = f.read()
        current_hash = hashlib.sha256(file_data).hexdigest()
    if current_hash != original_hashes.get(file_path, ''):
        print(f"[ALERT] File integrity compromised: {file_path}")

# ------------------------------
# Process Monitoring
# ------------------------------
def monitor_processes(processes={}):
    """Monitor processes and alert on new or suspicious processes."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['pid'] not in processes:
            processes[proc.info['pid']] = proc.info['name']
            print(f"[ALERT] New Process Detected: {proc.info['name']} (PID: {proc.info['pid']})")

        # Example: Detecting a suspicious process
        if proc.info['name'] in ['bad_process_name']:  # Modify this for any known bad process
            print(f"[ALERT] Malicious Process Detected: {proc.info['name']} (PID: {proc.info['pid']})")

# ------------------------------
# File System Monitoring
# ------------------------------
class FileMonitor(FileSystemEventHandler):
    def __init__(self, original_hashes):
        self.original_hashes = original_hashes

    def on_modified(self, event):
        if event.is_directory:
            return
        check_file_integrity(event.src_path, self.original_hashes)
    
    def on_created(self, event):
        if event.is_directory:
            return
        check_file_integrity(event.src_path, self.original_hashes)
    
    def on_deleted(self, event):
        print(f"[ALERT] File deleted: {event.src_path}")

def monitor_files(directory="/tmp"):
    original_hashes = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "rb") as f:
                original_hashes[file_path] = hashlib.sha256(f.read()).hexdigest()

    event_handler = FileMonitor(original_hashes)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# ------------------------------
# Network Monitoring
# ------------------------------
def monitor_network(packet):
    """Sniff packets and alert on suspicious activity."""
    if packet.haslayer("IP"):
        src = packet["IP"].src
        dst = packet["IP"].dst
        print(f"[ALERT] Network Packet Detected: {src} -> {dst}")

def start_network_monitoring():
    print("[*] Monitoring network traffic...")
    sniff(prn=monitor_network, store=False)

# ------------------------------
# Main Monitoring Function
# ------------------------------
if __name__ == "__main__":
    print("[*] SysSecMonitor v1.0: Basic System Security Monitoring Tool")
    
    threshold = int(input("Enter process monitoring threshold (default: 5): ") or 5)
    directory = input("Enter directory to monitor (default: /tmp): ") or "/tmp"

    # Start monitoring processes
    monitor_processes()
    
    # Start monitoring files
    monitor_files(directory)
    
    # Start monitoring network traffic
    start_network_monitoring()
