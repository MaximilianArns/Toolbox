import nmap
import os
import ipaddress
import argparse
import sys

#Funktion för att spara resultaten till en fil, 192.168.0.50
def save_results_to_file(ip_addr, scan_info, ip_status, open_ports, open_ports_keys, file_name):
    try:
        with open(file_name, 'a') as file:
            file.write(f"Scan results for IP: {ip_addr}\n")
            file.write(f"Scan Info: {scan_info}\n")
            file.write(f"IP Status: {ip_status}\n")
            file.write(f"Open Ports: {open_ports}{open_ports_keys}\n")
            file.write("-------------------------------------------------\n")
    except Exception as e:
        print(f"An error occurred while saving results to file: {e}")

#Funktion för att läsa IP-adresser från en fil
def read_ips_from_file(file_name):
    if os.path.exists(file_name):
        with open(file_name, 'r') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines]
        return lines
    else:
        print("File not found!")
        return []

#Funktion för att kontrollera ip-adress
def is_valid_ip(ip_addr):
    try:
        ipaddress.ip_address(ip_addr)
        return True
    except ValueError:
        return False 

#Funktion för att utföra nmap-skanningar
def perform_scan(scanner, ip_addr, scan_type):
    try:
        if scan_type == "syn":
            scanner.scan(ip_addr, "1-1024", "-v -sS")
            tcp_scan_info = scanner.scaninfo()
            return scanner[ip_addr], tcp_scan_info
        elif scan_type == "udp":
            scanner.scan(ip_addr, "1-1024", "-v -sU")
            udp_scan_info = scanner.scaninfo()
            return scanner[ip_addr], udp_scan_info
        elif scan_type == "compre":
            scanner.scan(ip_addr, "1-1024", "-v -sS -sV -sC -A -O")
            tcp_result = scanner[ip_addr]
            tcp_scan_info = scanner.scaninfo()

            scanner.scan(ip_addr, "1-1024", "-v -sU")
            udp_result = scanner[ip_addr]
            udp_scan_info = scanner.scaninfo()

            merged_result = tcp_result
            if 'udp' in udp_result:
                merged_result['udp'] = udp_result['udp']

            combined_scan_info = {**tcp_scan_info, **udp_scan_info}

            return merged_result, combined_scan_info

        else:
            return None
    except nmap.PortScannerError as e:
        print(f"Skanningsfel för IP {ip_addr}: {e}")
        return None, None

scanner = nmap.PortScanner()

parser = argparse.ArgumentParser(description="This is a nmap tool")
parser.add_argument("--mode", choices=["single_ip", "scan_file"], help="Chose IP addresse(s) to scan")
parser.add_argument("--scan_type", choices=["syn", "udp", "compre"], help="Chose which type of scan you want to do")
parser.add_argument("--ip_addr", help="Enter the IP address you want to scan")
parser.add_argument("--file_name", help="Enter the name of the file with the IP addresses")

args, unknown_args = parser.parse_known_args()

#Kontrollera okända argument
if unknown_args:
    print(f"Okända argument angavs: {', '.join(unknown_args)}")
    sys.exit(1)


#Skanna en specifik ip address
if args.mode == "single_ip":
    if not args.ip_addr:
        parser.error("You need to enter the IP address you want to scan. If you entered a file to scan then you need to enter scan_file as your --mode")
    
    if not is_valid_ip(args.ip_addr):
        print("Invalid IP address. Please try again")

    #Error hantering
    try:
        result, scan_info = perform_scan(scanner, args.ip_addr, args.scan_type) 
        if not result:
            print("Invalid scan type or scan returned no results. Please try again.")
        if result:
            ip_status =result.state()
            open_ports = result.all_protocols()

            if args.scan_type == "udp":
                open_ports_keys = result['udp'].keys() if 'udp' in result else []
            elif args.scan_type == "syn":
                open_ports_keys = result['tcp'].keys() if 'tcp' in result else []
            elif args.scan_type == "compre":
                open_ports_keys = []
                if 'tcp' in result:
                    open_ports_keys.extend(result['tcp'].keys())
                if 'udp' in result:
                    open_ports_keys.extend(result['udp'].keys())

            #Visar resultatet av skannen
            print(f"Scan for ip address: {args.ip_addr}")
            print(scan_info)
            print("IP Status:", ip_status)
            print("Protocols found:", open_ports)
            print("Open Ports:", open_ports_keys)
            print("")
            save_results_to_file(args.ip_addr, scan_info, ip_status, open_ports, open_ports_keys, "scan_results.txt")
    except Exception as e:
        print(f"An error occurred while scanning {args.ip_addr}: {e}")

#Skanna en fil av ip adresser
elif args.mode == "scan_file":
    #Error hantering
    try:
        ip_addresses = read_ips_from_file(args.file_name)
        print(f"Read IP Addresses: {ip_addresses}")
    except FileNotFoundError:
        print("The specified file was not found. Please try again.")

    #For loop för att gå igenom alla ip adresser i filen
    for ip_addr in ip_addresses:
        try:
            result, scan_info = perform_scan(scanner, ip_addr, args.scan_type)
            if result is None:
                print(f"Invalid scan type for {ip_addr}. Skipping scan.")
                continue
            
            ip_status = result.state()
            open_ports = result.all_protocols()

            if args.scan_type == "udp":
                open_ports_keys = result['udp'].keys() if 'udp' in result else []
            elif args.scan_type == "syn":
                open_ports_keys = result['tcp'].keys() if 'tcp' in result else []
            elif args.scan_type == "compre":
                open_ports_keys = []
                if 'tcp' in result:
                    open_ports_keys.extend(result['tcp'].keys())
                if 'udp' in result:
                    open_ports_keys.extend(result['udp'].keys())

            #Visar resultatet av skannen
            print(f"Scan for ip address: {ip_addr}")
            print(scan_info)
            print("IP Status:", ip_status)
            print("Protocols found:", open_ports)
            print("Open Ports:", open_ports_keys)
            print("")
            save_results_to_file(ip_addr, scan_info, ip_status, open_ports, open_ports_keys, "scan_results.txt")
        except Exception as e:
            print(f"An error occurred while scanning {ip_addr}: {e}")