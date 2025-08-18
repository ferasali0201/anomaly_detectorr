import psutil, subprocess

port_process_cache = {}

def get_process_by_port(ip, port):
    key = f"{ip}:{port}"
    if key in port_process_cache:
        return port_process_cache[key]

    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.laddr.port == port:
                try:
                    name = psutil.Process(conn.pid).name()
                    port_process_cache[key] = name
                    return name
                except Exception:
                    break
    except Exception:
        pass

    try:
        output = subprocess.check_output(["lsof", "-nP", "-iUDP"]).decode()
        for line in output.splitlines()[1:]:
            if f":{port}" in line:
                parts = line.split()
                if len(parts) >= 1:
                    name = parts[0]
                    port_process_cache[key] = name
                    return name
    except Exception:
        pass

    port_process_cache[key] = "Unknown"
    return "Unknown"
