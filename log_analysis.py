import re
from collections import defaultdict
import csv

# declaring constant
LOG_FILE = "sample.log"
CSV_FILE = "results.csv"
FAILED_LOGIN_THRESHOLD = 5 

ip_counts = defaultdict(int)
endpoint_counts = defaultdict(int)
failed_logins = defaultdict(int)
#regex pattern
ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
endpoint_pattern = r'"[A-Z]+\s([/\w.-]+)\s'
failed_login_pattern = r'401|Invalid credentials'

#read and process log file
with open(LOG_FILE, "r") as file:
    for line in file: # extract IP address
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            ip = ip_match.group()
            ip_counts[ip] += 1    
        endpoint_match = re.search(endpoint_pattern, line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counts[endpoint] += 1
        if re.search(failed_login_pattern, line): # detect failed login
            if ip_match:
                failed_logins[ip] += 1
most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get)
most_accessed_count = endpoint_counts[most_accessed_endpoint]

suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
# write result to csv file
with open(CSV_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        writer.writerow([ip, count])
    writer.writerow([])
    writer.writerow(["Most Frequently Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint, most_accessed_count])
    writer.writerow([])
    writer.writerow(["Suspicious IPs with Failed Logins"])
    writer.writerow(["IP Address", "Failed Login Attempts"])
    for ip, count in suspicious_ips.items():
        writer.writerow([ip, count])
print("Requests per IP:") # display result
for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip}: {count} requests")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint}: Accessed {most_accessed_count} times")

print("\nSuspicious Activity:")
if suspicious_ips:
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} failed login attempts")
else:
    print("No suspicious activity detected.")

print(f"\nResults saved to {CSV_FILE}")
