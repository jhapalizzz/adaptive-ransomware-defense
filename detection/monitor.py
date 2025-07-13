import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import os
import time
import json
import shutil
import hashlib
import threading
import logging
import psutil
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from playsound import playsound

# === Configuration ===
BACKUP_DIR = "../backup"
TARGET_DIR = "test_dir"
MAX_BACKUPS = 5
SUSPICIOUS_THRESHOLD = 3
TIME_WINDOW = 5  # seconds
ALERT_COOLDOWN = 10  # seconds

# === Threat Feed ===
with open("threat_feed.json", "r") as f:
    threat_data = json.load(f)
    known_hashes = set(threat_data.get("hashes", []))
    known_filenames = set(threat_data.get("filenames", []))

# === Logging Setup ===
logging.basicConfig(
    filename='../logs/detection.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

_last_alert_time = 0

def alert_user(title="⚠️ Suspicious Activity", msg="Potential ransomware detected!"):
    global _last_alert_time
    now = time.time()
    if now - _last_alert_time < ALERT_COOLDOWN:
        return
    _last_alert_time = now
    try:
        print(f"[ALERT] {title}: {msg}")
        logging.warning(f"{title}: {msg}")
        threading.Thread(target=playsound, args=("../assets/alert.mp3",), daemon=True).start()

        def popup():
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning(title, msg)
            root.destroy()
        threading.Thread(target=popup, daemon=True).start()

    except Exception as e:
        logging.error(f"Alert failed: {e}")

def kill_process_by_name(name, exclude_pid):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if name.lower() in proc.info['name'].lower() and proc.info['pid'] != exclude_pid:
                print(f"[⚠️] Killing process: {proc.info['name']} (PID: {proc.info['pid']})")
                logging.warning(f"Killed suspicious process: {proc.info['name']}")
                psutil.Process(proc.info['pid']).terminate()
        except:
            continue

def calculate_md5(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

# === Recovery Function ===
def recover_files():
    print("[🔄] Starting file recovery from backups...")
    logging.info("Starting file recovery from backups...")

    if not os.path.exists(BACKUP_DIR):
        print("[!] Backup directory not found.")
        logging.warning("Backup directory not found.")
        return

    backup_files = [f for f in os.listdir(BACKUP_DIR) if f.endswith(".bak")]
    backup_files.sort(reverse=True)  # Restore latest first

    restored = set()
    restored_any = False

    for bak_file in backup_files:
        metadata_file = os.path.join(BACKUP_DIR, bak_file + ".json")
        backup_path = os.path.join(BACKUP_DIR, bak_file)

        if not os.path.exists(metadata_file):
            print(f"[!] Metadata missing for backup {bak_file}, skipping.")
            logging.warning(f"Metadata missing for {bak_file}, skipping.")
            continue

        try:
            with open(metadata_file, 'r') as meta:
                metadata = json.load(meta)

            original_name = metadata.get("original_name")
            if not original_name:
                print(f"[!] Missing 'original_name' in metadata for {bak_file}, skipping.")
                logging.warning(f"Missing 'original_name' in metadata for {bak_file}, skipping.")
                continue

            target_path = os.path.join(TARGET_DIR, original_name)
            if target_path in restored:
                continue

            shutil.copy2(backup_path, target_path)
            print(f"[🔄] Restored {backup_path} → {target_path}")
            logging.info(f"Restored backup {bak_file} to {target_path}")
            restored.add(target_path)
            restored_any = True

        except Exception as e:
            print(f"[!] Failed to restore {bak_file}: {e}")
            logging.error(f"Failed to restore {bak_file}: {e}")

    if restored_any:
        print("[✅] Recovery complete.")
        logging.info("Recovery complete.")
    else:
        print("[ℹ️] No backups restored.")
        logging.info("No backups restored.")

# === Ransomware Detection Handler ===
class RansomwareDetector(FileSystemEventHandler):
    def __init__(self):
        self.events_window = deque()
        self.alert_triggered = False

    def _hash_filename(self, filename):
        return hashlib.md5(filename.encode()).hexdigest()

    def backup_file(self, src_path):
        try:
            if not os.path.exists(BACKUP_DIR):
                os.makedirs(BACKUP_DIR)
            if not os.path.isfile(src_path):
                return
            filename = os.path.basename(src_path)
            base_name = self._hash_filename(filename)
            timestamp = time.strftime("%Y%m%d%H%M%S")
            backup_name = f"{base_name}_{timestamp}.bak"
            backup_path = os.path.join(BACKUP_DIR, backup_name)
            shutil.copy2(src_path, backup_path)
            with open(backup_path + ".json", 'w') as meta_file:
                json.dump({"original_name": filename, "backup_name": backup_name, "timestamp": timestamp}, meta_file)
            self.cleanup_old_backups(base_name)
        except Exception as e:
            logging.error(f"Backup failed: {e}")

    def cleanup_old_backups(self, base_name):
        try:
            files = [f for f in os.listdir(BACKUP_DIR) if f.startswith(base_name) and f.endswith(".bak")]
            files.sort(reverse=True)
            for f in files[MAX_BACKUPS:]:
                os.remove(os.path.join(BACKUP_DIR, f))
                json_file = os.path.join(BACKUP_DIR, f + ".json")
                if os.path.exists(json_file):
                    os.remove(json_file)
        except Exception as e:
            logging.error(f"Cleanup failed: {e}")

    def handle_event(self, description, src_path=None):
        now = time.time()
        self.events_window.append(now)
        print(f"[+] {description}")
        logging.info(description)

        if src_path and os.path.isfile(src_path):
            try:
                file_hash = calculate_md5(src_path)
                file_name = os.path.basename(src_path)

                if file_hash in known_hashes:
                    logging.warning(f"Threat Detected: Hash match - {file_name}")
                    alert_user("Threat Detected", f"Hash match: {file_name}")
                    return

                if file_name in known_filenames:
                    logging.warning(f"Threat Detected: Suspicious filename - {file_name}")
                    alert_user("Threat Detected", f"Suspicious filename: {file_name}")
                    return
            except Exception as e:
                logging.error(f"File check failed: {e}")

        while self.events_window and now - self.events_window[0] > TIME_WINDOW:
            self.events_window.popleft()

        if len(self.events_window) >= SUSPICIOUS_THRESHOLD and not self.alert_triggered:
            self.alert_triggered = True
            logging.warning("⚠️ Rapid file operations detected")
            alert_user()
            kill_process_by_name("python.exe", os.getpid())
            recover_files()  # <<< Replaced self.restore_files()

    def on_created(self, event):
        if not event.is_directory:
            self.backup_file(event.src_path)
            self.handle_event(f"Created: {os.path.basename(event.src_path)}", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.backup_file(event.src_path)
            self.handle_event(f"Modified: {os.path.basename(event.src_path)}", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.handle_event(f"Deleted: {os.path.basename(event.src_path)}")

def on_moved(self, event):
    if not event.is_directory:
        self.events_window.append(time.time())  # <-- Add this line
        self.handle_event(
            f"Renamed: from {os.path.basename(event.src_path)} to {os.path.basename(event.dest_path)}",
            event.dest_path
        )


# === Main Runner ===
if __name__ == "__main__":
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
    observer = Observer()
    observer.schedule(RansomwareDetector(), path=TARGET_DIR, recursive=True)
    observer.start()
    print(f"[+] Monitoring started on '{TARGET_DIR}'... Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
