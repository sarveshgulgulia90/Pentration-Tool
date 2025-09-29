import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def scan_port(target, port, timeout=1):
    """Attempt to connect to a port and grab banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                    if not banner:
                        banner = "No banner detected"
                except:
                    banner = "No banner detected"
                return {"port": port, "status": "open", "banner": banner}
    except:
        pass
    return None

def port_scanner(target, start_port, end_port, max_threads=500):
    """Scan any range of ports on target using concurrency."""
    print(f"\n🔍 Starting scan on {target} from port {start_port} to {end_port}...\n")
    open_ports = []
    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in range(start_port, end_port + 1)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"[+] Port {result['port']:>5} OPEN  | Banner: {result['banner']}")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Scan completed in {duration:.2f} seconds")
    print(f"🧭 Total open ports found: {len(open_ports)}")
    return open_ports

if __name__ == "__main__":
    print("=== Mini-Nmap (Universal Port Scanner + Banner Grabber) ===")
    target = input("Enter target IP or domain: ").strip()
    if not target:
        print("❌ Target cannot be empty.")
        exit()

    try:
        start_port = int(input("Enter start port (default 1): ") or 1)
        end_port = int(input("Enter end port (default 1024): ") or 1024)

        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("Invalid port range.")
    except ValueError as e:
        print(f"❌ Error: {e}. Using default range 1–1024.")
        start_port, end_port = 1, 1024

    results = port_scanner(target, start_port, end_port)

    if results:
        save = input("\n💾 Save results to file? (y/n): ").lower()
        if save == "y":
            filename = f"scan_results_{target.replace('.', '_')}.txt"
            with open(filename, "w") as f:
                for r in sorted(results, key=lambda x: x["port"]):
                    f.write(f"Port {r['port']} OPEN | Banner: {r['banner']}\n")
            print(f"📁 Results saved to {filename}")
    else:
        print("🚫 No open ports found in the given range.")
