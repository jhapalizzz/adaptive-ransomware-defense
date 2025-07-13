import os
import time

target_dir = "test_dir"

for i in range(3):  # Exceeds the threshold (10)
    with open(os.path.join(target_dir, f"file_{i}.txt"), "w") as f:
        f.write("suspicious content\n")
    time.sleep(0.3)  # Simulates fast file creation
