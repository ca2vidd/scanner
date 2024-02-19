import nmap
import re
import os
import socket
from tabulate import tabulate

# Function to clear the screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to check if an IP address is valid
def is_valid_ip(ip_addr):
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    return ip_pattern.match(ip_addr) and all(0 <= int(num) < 256 for num in ip_addr.rstrip().split('.'))

# Function to perform port scanning
def port_scanner(ip_address, ports, scan_type):
    nm = nmap.PortScanner()
    
    # Scan type argument mapping
    scan_type_args = {
        '1': '-sT',
        '2': '-sS',
        '3': '-sU',
        '4': '-sS -sU -sV -O -A -T4'
    }
    
    arguments = scan_type_args.get(scan_type, '-sT')
    print(f"\nStarting scan on {ip_address} with port range {ports}...\n")
    nm.scan(hosts=ip_address, ports=ports, arguments=arguments)
    scan_data = []
    for host in nm.all_hosts():
        print(f"Scanning Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                port_data = nm[host][proto][port]
                scan_data.append([proto.upper(), port, port_data['state'], port_data.get('name', ''), port_data.get('product', '')])
    print("\nScan results:\n")
    print(tabulate(scan_data, headers=["Protocol", "Port", "State", "Service", "Product"]))
    return scan_data

# Prompt user for IP address
def prompt_ip():
    while True:
        ip_address = input("Enter the IP address to scan (e.g., 192.168.0.1): ")
        if is_valid_ip(ip_address):
            return ip_address
        else:
            print("Error: Invalid IP address format. Please enter a valid IPv4 address.")

# Prompt user for port range
def prompt_ports():
    while True:
        ports = input("Enter the range of ports to scan (e.g., 20-80): ")
        if re.match(r'^\d+-\d+$', ports):
            start_port, end_port = [int(p) for p in ports.split('-')]
            if 0 <= start_port <= 65535 and 0 <= end_port <= 65535:
                return ports
        print("Error: Invalid port range. Please enter a valid port range (e.g., 20-80).")

# Function to get the local IP address of the user's machine
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception as e:
        print(f"Unable to get the local IP address: {e}")
        local_ip = "N/A"
    finally:
        s.close()
    return local_ip

# Main function
def main():
    clear_screen()
    local_ip = get_local_ip()
    print(f"Your local IP address is: {local_ip}\n")
    print("Welcome to the Advanced Network Scanner")
    print("1. Standard TCP Scan")
    print("2. SYN Scan")
    print("3. UDP Scan")
    print("4. Comprehensive Scan")
    
    while True:
        scan_type = input("Enter the number of the scan type you want to perform: ")
        if scan_type in ['1', '2', '3', '4']:
            break
        else:
            print("Invalid option. Please choose a valid scan type from the list.")

    ip_address = prompt_ip()
    ports = prompt_ports()

    try:
        scan_data = port_scanner(ip_address, ports, scan_type)
        choice = input("\nWould you like to save the results? (yes/no): ").lower()
        if choice == 'yes':
            filename = input("Enter the filename to save the results: ")
            with open(filename, 'w') as f:
                f.write(tabulate(scan_data, headers=["Protocol", "Port", "State", "Service", "Product"]))
                print(f"Results have been saved to {filename}")
    except nmap.PortScannerError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()