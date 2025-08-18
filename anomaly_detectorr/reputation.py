import requests

ip_cache = {}

def check_ip_reputation(ip, config):
    if not config["reputation_services"]["abuseipdb"]["enabled"]:
        return None
    if ip in ip_cache:
        return ip_cache[ip]

    key = config["reputation_services"]["abuseipdb"]["api_key"]
    threshold = config["reputation_services"]["abuseipdb"].get("threshold", 50)
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": key, "Accept": "application/json"}

    try:
        r = requests.get(url, headers=headers, timeout=2)
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        is_tor = data.get("isTor", False)

        reasons = []
        if score >= threshold:
            reasons.append(f"Malicious IP (AbuseIPDB score: {score})")
        if is_tor:
            reasons.append(f"Tor exit node: {ip}")

        result = "; ".join(reasons) if reasons else None
        ip_cache[ip] = result
        return result

    except Exception as e:
        ip_cache[ip] = None
        return None
