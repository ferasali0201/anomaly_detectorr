import socket
import subprocess
import time

def test_dns():
    print("[TEST] Triggering suspicious DNS lookup...")
    subprocess.run(["dig", "telemetry.badexample.com"])

def test_data_spike():
    print("[TEST] Triggering data spike...")
    subprocess.run(["curl", "-X", "POST", "https://httpbin.org/post", "-d", "$(head -c 600000 /dev/urandom)"], shell=True)

def test_malicious_ip():
    print("[TEST] Connecting to known malicious IP...")
    s = socket.socket()
    s.connect(("185.220.101.1", 80))
    s.close()

if __name__ == "__main__":
    test_dns()
    time.sleep(2)
    test_data_spike()
    time.sleep(2)
    test_malicious_ip()
