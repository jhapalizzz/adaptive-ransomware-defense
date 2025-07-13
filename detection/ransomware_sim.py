import os
import time

# 🔧 Use absolute path (recommended)
target_dir = r"C:\Users\skill\adaptive-ransomware-defense\test_dir"

# ✅ Check if directory exists
if not os.path.exists(target_dir):
    print(f"❌ Target folder '{target_dir}' does not exist.")
    exit(1)

# 📝 List files to simulate ransomware behavior
files = os.listdir(target_dir)
if not files:
    print("⚠️ No files to encrypt in the target directory.")
    exit(0)

print(f"🔐 Simulating ransomware on {len(files)} files...")

# 🧨 Rename files to simulate encryption
for i, f in enumerate(files):
    src = os.path.join(target_dir, f)
    dst = os.path.join(target_dir, f"locked_{i}.enc")
    if os.path.isfile(src):
        os.rename(src, dst)
        print(f"Renamed: {f} ➜ locked_{i}.enc")
        time.sleep(0.3)  # Simulate ransomware delay

print("✅ Simulation complete.")
