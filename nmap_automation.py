#!/usr/bin/env python3

# nmap_automation.py
#
# Description:
# This script automates the process of running an Nmap scan against a target
# and generating a simple text-based report of the findings.
#
# Requirements:
# - python-nmap library (install with: pip install python-nmap)
# - Nmap installed and accessible in the system's PATH.
# - Administrative/root privileges to run a SYN scan (-sS).

import nmap
import datetime
import sys

# --- Function Definitions ---

def perform_scan(target_ip):
    """
    Performs a SYN scan (-sS) with service/version detection (-sV) on the target IP.
    Args:
        target_ip (str): The IP address or hostname of the target to scan.
    Returns:
        tuple: A tuple containing the scan results (dict) and the command string.
               Returns (None, None) if the scan fails.
    """
    # Initialize the Nmap PortScanner object
    nm = nmap.PortScanner()

    print(f"[*] Starting SYN scan on {target_ip}...")
    print("[*] This may take a while depending on the target...")

    try:
        # Define the Nmap arguments:
        # -sS: TCP SYN scan (stealth)
        # -sV: Probe open ports to determine service/version info
        # -v: Verbose output to see progress in the terminal
        nmap_args = '-sS -sV -v'

        # Perform the scan
        # The 'sudo' argument is a hint to the library to use sudo for privileged scans
        nm.scan(target_ip, arguments=nmap_args, sudo=True)

        # Retrieve the command that was executed
        command_line = nm.command_line()

        print(f"[+] Scan complete for {target_ip}.")
        return nm, command_line

    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}", file=sys.stderr)
        print("[!] Please ensure Nmap is installed and you are running this script with sudo/administrator privileges.", file=sys.stderr)
        return None, None
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}", file=sys.stderr)
        return None, None


def generate_report(target_ip, scan_results, command_line, output_filename):
    """
    Generates a formatted text report from the Nmap scan results.
    Args:
        target_ip (str): The IP that was scanned.
        scan_results (nmap.PortScanner): The PortScanner object with results.
        command_line (str): The exact Nmap command that was run.
        output_filename (str): The name of the file to save the report to.
    """
    # Get all hosts that were found in the scan
    for host in scan_results.all_hosts():
        # Get the hostname and state (up/down)
        hostname = scan_results[host].hostname()
        state = scan_results[host].state()

        # Open the output file in write mode
        with open(output_filename, 'w') as report_file:
            # Write the report header
            report_file.write("="*60 + "\n")
            report_file.write("    AUTOMATED NMAP SCAN REPORT\n")
            report_file.write("="*60 + "\n\n")
            report_file.write(f"Scan Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report_file.write(f"Target IP: {host}\n")
            report_file.write(f"Hostname: {hostname if hostname else 'N/A'}\n")
            report_file.write(f"Host State: {state}\n")
            report_file.write(f"Command Executed: {command_line}\n\n")

            # Check if the host is up before trying to list ports
            if state == 'up':
                report_file.write("--- OPEN PORTS AND SERVICES ---\n")
                report_file.write("-"*40 + "\n")
                report_file.write(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'VERSION'}\n")
                report_file.write("-"*40 + "\n")

                # Iterate through all TCP ports found for the host
                for proto in scan_results[host].all_protocols():
                    ports = scan_results[host][proto].keys()
                    for port in sorted(ports):
                        port_state = scan_results[host][proto][port]['state']
                        service_name = scan_results[host][proto][port]['name']
                        service_version = scan_results[host][proto][port]['version']
                        service_product = scan_results[host][proto][port]['product']
                        
                        # Combine product and version for a more complete version string
                        full_version = f"{service_product} {service_version}".strip()

                        # Write the port information to the report
                        report_file.write(f"{port}/{proto:<7} {port_state:<10} {service_name:<20} {full_version}\n")
            else:
                report_file.write("Host is down. No port information available.\n")

            # Write the report footer
            report_file.write("\n" + "="*60 + "\n")
            report_file.write("END OF REPORT\n")
            report_file.write("="*60 + "\n")

    print(f"[+] Report successfully generated: {output_filename}")


# --- Main Execution Block ---

if __name__ == "__main__":
    # Check if a target IP was provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python3 nmap_automation.py <target_ip>")
        print("Example: python3 nmap_automation.py 192.168.1.100")
        sys.exit(1)

    # Get the target from the command-line argument
    target = sys.argv[1]

    # Define the output report filename
    report_file = 'scan_report.txt'

    # Perform the scan
    scanner_object, nmap_command = perform_scan(target)

    # Check if the scan was successful before generating a report
    if scanner_object:
        # Generate the report from the scan results
        generate_report(target, scanner_object, nmap_command, report_file)
        print("\n[*] Task finished successfully.")
    else:
        print("\n[!] Scan failed. No report generated.")
        sys.exit(1)
