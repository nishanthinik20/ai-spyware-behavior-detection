import psutil
import time

print("Network Activity Monitor Started...")
print("Monitoring active network connections...\n")

while True:

    connections = psutil.net_connections(kind="inet")

    active = 0

    for connection in connections:

        if connection.status == "ESTABLISHED":
            active += 1

    print(f"Active Network Connections: {active}")

    time.sleep(5)