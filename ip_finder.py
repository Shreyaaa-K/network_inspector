import psutil
import socket
import ipaddress
from datetime import datetime

OUTPUT_FILE = "net_inspector_output.txt"


def get_network_processes():
    process_map = {}

    for conn in psutil.net_connections(kind='inet'):
        if conn.pid and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                name = proc.name()
                path = proc.exe()
                process_map[conn.pid] = (name, path)
            except:
                pass

    return sorted(process_map.items(), key=lambda x: x[1][0].lower())


def select_process(process_list):

    print("\nProcesses with active network connections:\n")

    for i, (pid, (name, path)) in enumerate(process_list, 1):
        print(f"[{i}] {name}")
        print(f"    PID : {pid}")
        print(f"    Path: {path}\n")

    while True:
        try:
            choice = int(input("Select process number: "))
            if 1 <= choice <= len(process_list):
                pid, (name, path) = process_list[choice - 1]
                return pid, name
        except:
            pass

        print("Invalid selection. Try again.")


def resolve_fqdn(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Not available"


def classify_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "Private"
        else:
            return "Public"
    except:
        return "Unknown"


def get_process_connections(pid):

    connections = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.pid == pid and conn.raddr:
            connections.append(conn)

    return connections


def write_report(process_name, pid, connections):

    with open(OUTPUT_FILE, "w") as f:

        f.write("=========================================\n")
        f.write("Network Inspector Report\n")
        f.write("=========================================\n\n")

        f.write(f"Process Name : {process_name}\n")
        f.write(f"PID          : {pid}\n")
        f.write(f"Generated    : {datetime.now()}\n\n")

        if not connections:
            f.write("No active network connections found.\n")
            return

        seen = set()

        count = 1

        for conn in connections:

            ip = conn.raddr.ip
            port = conn.raddr.port

            key = (ip, port)

            if key in seen:
                continue

            seen.add(key)

            fqdn = resolve_fqdn(ip)
            ip_type = classify_ip(ip)

            f.write("-----------------------------------------\n")
            f.write(f"Connection {count}\n")
            f.write("-----------------------------------------\n")

            f.write(f"Destination IP   : {ip}\n")
            f.write(f"Destination Port : {port}\n")
            f.write(f"FQDN             : {fqdn}\n")
            f.write(f"IP Type          : {ip_type}\n\n")

            count += 1

        f.write("=========================================\n")
        f.write("End of Report\n")
        f.write("=========================================\n")


def main():

    print("\nNetwork Inspector - Phase 1\n")

    process_list = get_network_processes()

    if not process_list:
        print("No active network processes found.")
        return

    pid, name = select_process(process_list)

    connections = get_process_connections(pid)

    write_report(name, pid, connections)

    print(f"\nReport saved to {OUTPUT_FILE}\n")


if __name__ == "__main__":
    main()