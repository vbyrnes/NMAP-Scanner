#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<----------------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n""")
print("You have selected option: ", resp)
resp=int(resp)
if resp==1:
    print("nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS') #port range to scan, the last part is the scan type
    print(scanner.scaninfo())
    print("Scanner Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ",scanner[ip_addr]['tcp'].keys())
elif resp==2:
    print("nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sU') #port range to scan, the last part is the scan type
    print(scanner.scaninfo())
    print("Scanner Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ",scanner[ip_addr]['tcp'].keys())
elif resp==3:
    print("nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS -sV -sC -A -O') #port range to scan, the last part is the scan type
    print(scanner.scaninfo())
    print("Scanner Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ",scanner[ip_addr]['tcp'].keys())
else:
    print("Ivalid option. Please try again.")
    exit
    
    






