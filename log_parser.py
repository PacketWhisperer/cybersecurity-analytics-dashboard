from collections import defaultdict
import re

# Load the log file
log_file = "sample_auth.log"

# Dictionary to count how many times each IP failed
failed_ips = defaultdict(int)

# Open the log file and read it line by line
with open(log_file, 'r') as file:
    for line in file:
        # Look for lines that say "Failed password"
        if "Failed password" in line:
            # Use regex to extract the IP address from the line
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_ips[ip] += 1  # Increase the count for this IP

# Print the summary
print("\n📊 Failed Login Attempts by IP:\n")
for ip, count in failed_ips.items():
    status = "⚠️ Suspicious" if count >= 3 else "✅ OK"
    print(f"{ip}: {count} failed attempts {status}")
