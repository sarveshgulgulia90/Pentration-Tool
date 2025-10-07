import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def resolve_target(target):
    """Resolve domain name to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"Could not resolve target: {target}")
        return None
def tcp_connect(target_ip, port, timeout=2):
    """Perform a TCP connection attempt and banner grab."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            try:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "No banner detected"
            s.close()
            return {"port": port, "protocol": "TCP", "status": "open", "banner": banner}
    except:
        pass
    return None
def http_probe(target, port):
    """Try HTTP GET to extract server headers."""
    try:
        url = f"http://{target}:{port}"
        r = requests.get(url, timeout=3)
        server = r.headers.get("Server", "Unknown server")
        return {"port": port, "protocol": "HTTP", "status": "open", "banner": f"HTTP {r.status_code} | {server}"}
    except:
        return None
def udp_probe(target_ip, port, timeout=2):
    """Send minimal UDP probes for common services."""
    probes = {
        53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01',
        123: b'\x1b' + 47 * b'\0',
        161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x9f\x0b\x66\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
        69: b'\x00\x01test\x00octet\x00',
    }
    probe = probes.get(port, b"Hello")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(probe, (target_ip, port))
        try:
            data, _ = s.recvfrom(1024)
            banner = data.decode(errors="ignore")[:80] if data else "Response received"
            return {"port": port, "protocol": "UDP", "status": "open", "banner": banner}
        except socket.timeout:
            # No response doesn't always mean closed for UDP
            return {"port": port, "protocol": "UDP", "status": "open|filtered", "banner": "No response (could be filtered)"}
    except Exception as e:
        pass
    return None
def scan_port(target, target_ip, port, mode="tcp"):
    """Choose appropriate scan method."""
    if mode == "udp":
        return udp_probe(target_ip, port)
    else:
        if port in (80, 8080, 8000, 443):
            res = http_probe(target, port)
            if res:
                return res
        return tcp_connect(target_ip, port)
def hybrid_scanner(target, start_port=1, end_port=1024, max_threads=200, mode="tcp"):
    target_ip = resolve_target(target)
    if not target_ip:
        return []

    print(f"\nStarting {mode.upper()} scan on {target} ({target_ip}) from port {start_port} to {end_port}")
    open_ports = []
    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, target, target_ip, port, mode): port for port in range(start_port, end_port + 1)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"{mode.upper()} {result['port']:>5} OPEN  | {result['banner']}")

    end_time = datetime.now()
    print(f"\n{mode.upper()} Scan complete in {(end_time - start_time).total_seconds():.2f}s")
    print(f"Total open ports: {len(open_ports)}")
    return open_ports
if __name__ == "__main__":
    target = input("Enter target IP or domain: ").strip()
    start_port = int(input("Enter start port (default 1): ") or 1)
    end_port = int(input("Enter end port (default 1024): ") or 1024)
    mode = input("Scan mode (tcp/udp): ").strip().lower() or "tcp"

    results = hybrid_scanner(target, start_port, end_port, mode=mode)

    if results:
        save = input("Save results to file? (y/n): ").lower()
        if save == "y":
            fname = f"scan_results_{target.replace('.', '_')}_{mode}.txt"
            with open(fname, "w") as f:
                for r in results:
                    f.write(f"{r['protocol']} Port {r['port']} | {r['status']} | {r['banner']}\n")
            print(f"Saved to {fname}")
