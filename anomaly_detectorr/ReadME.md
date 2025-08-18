

---

## Features

- Real-time monitoring of outbound TCP/UDP traffic
- Malicious IP detection via AbuseIPDB reputation scoring
- Tor exit node identification
- Suspicious DNS keyword detection (e.g., `telemetry`, `track`)
-Abnormal data spike detection with cumulative tracking
-  Process attribution using `psutil`
-  Rich terminal alerts with timestamp, process name, destination, and reason
-  Optional JSON logging for post-analysis
-  Configurable thresholds and reputation toggles

---

## 🧰 Setup

### 1. Clone the repository

```bash
git clone https://github.com/ferasali0201/anomaly_detector.git
cd anomaly_detector




#install dependencies 
pip install -r requirements.txt


#you may use
 python -m venv anomaly_env
source anomaly_env/bin/activate


