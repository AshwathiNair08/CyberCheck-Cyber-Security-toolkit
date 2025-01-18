import os
import sys
sys.path.append('/home/ashwathi/ipwhois-master')
import subprocess
from bs4 import BeautifulSoup
import requests
import json
import nmap
import time
from urllib.parse import urlsplit, urljoin
from collections import deque
from urllib import request as urllib_request
import networkx as nx
import matplotlib.pyplot as plt
import re
import sys
import select
from scapy.all import *
import dns.resolver
from ipwhois import IPWhois

# Define script categories and associated scripts/options
SCRIPT_CATEGORIES = {
    '1': ('Certificates', ['ssl-cert', 'ssl-enum-ciphers'], '-sV -A --version-intensity 5'),
    '2': ('Vulnerabilities', ['vuln', 'http-vuln*'], '-sV -A --script-args vuln-cve2021-44228.uri=/'),
    '3': ('Directories and Files', ['http-enum', 'ftp-anon'], '-sS -A'),
    '4': ('SMB', ['smb-os-discovery', 'smb-enum-shares'], '-sU -A'),
    '5': ('HTTP', ['http-title', 'http-methods'], '-sS -A --script-args http-methods.test-all=true'),
    '6': ('Email', ['smtp-commands', 'smtp-enum-users'], '-sV -A'),
    '7': ('Firewall', ['http-waf-detect', 'firewalk'], '-A --script-args http-waf-detect.detect-all=1'),
    '8': ('Database', ['mysql-info', 'mongodb-info'], '-Pn -sV -A')
}

def run_command(command):
    """Execute a shell command and return its output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else result.stderr

def dns_lookup_menu(target):
    print("\nRunning selected DNS commands for domain:", target)
    print("Select the commands to execute:")
    print("1 - nslookup (A and MX records)")
    print("2 - dig (A and MX records, +short)")
    print("3 - dig +dnssec (with DNSSEC records)")
    print("4 - dig +answer (Answer section only)")
    print("5 - dig NS and SOA records (authoritative servers)")
    print("6 - dig +stats (Query statistics)")
    print("7 - host (A record, all records)")
    print("8 - OS Fingerprinting via DNS")
    print("9 - DNS Blacklist & Reputation Check")
    print("10 - DNS Malicious Domain Monitor")

    selected_commands = input("Enter your choices (e.g., 1,2,3): ").split(",")

    # Standard DNS Lookup Commands
    if '1' in selected_commands:
        print("nslookup - A Record:")
        print(run_command(f"nslookup -type=A {target}"))
        print("nslookup - MX Record:")
        print(run_command(f"nslookup -type=MX {target}"))

    if '2' in selected_commands:
        print("dig - A Record:")
        print(run_command(f"dig {target} A +short"))
        print("dig - MX Record:")
        print(run_command(f"dig {target} MX +short"))

    if '3' in selected_commands:
        print("\ndig +dnssec - A Record:")
        print(run_command(f"dig {target} A +dnssec"))

    if '4' in selected_commands:
        print("\ndig +answer:")
        print(run_command(f"dig {target} A +nocmd +noall +answer"))

    if '5' in selected_commands:
        print("\nChecking all NS and SOA records for authoritative servers:")
        ns_servers = run_command(f"dig {target} NS +short").splitlines()
        for ns in ns_servers:
            print(f"\nAuthoritative server: {ns}")
            print(run_command(f"dig @{ns} {target} SOA"))

    if '6' in selected_commands:
        print("\ndig +stats:")
        print(run_command(f"dig {target} A +stats"))

    if '7' in selected_commands:
        print("\nhost - A Record:")
        print(run_command(f"host -t A {target}"))
        print("\nhost - All Records:")
        print(run_command(f"host -a {target}"))

    # 8. OS Fingerprinting via DNS
    if '8' in selected_commands:
        try:
            # Run OS Fingerprinting script
            print("\n[OS Fingerprinting] Analyzing captured traffic...")
            os_fingerprint_command = "python3 OS_fingerprinting.py --pcap traffic.pcap --patterns os_patterns.json"
            os_fingerprint_result = subprocess.run(os_fingerprint_command, shell=True, capture_output=True, text=True)
            
            # Print the results of OS Fingerprinting
            print("\n[OS Fingerprinting Results]:")
            print(os_fingerprint_result.stdout)
            
            # Clean up pcap file
            subprocess.run("rm traffic.pcap", shell=True)
        
        except subprocess.CalledProcessError as e:
            print(f"Error in OS Fingerprinting process: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 9. DNS Blacklist & Reputation Check
    if '9' in selected_commands:
        try:
            def dns_lookup(domain):
                resolver = dns.resolver.Resolver()
                result = {}
                try:
                    result['A'] = [str(ip) for ip in resolver.resolve(domain, 'A')]
                    result['NS'] = [str(ns) for ns in resolver.resolve(domain, 'NS')]
                    result['MX'] = [str(mx) for mx in resolver.resolve(domain, 'MX')]
                except Exception as e:
                    print(f"Error in DNS lookup for {domain}: {e}")
                return result

            def enrich_with_whois(ip):
                try:
                    obj = IPWhois(ip)
                    whois_data = obj.lookup_rdap()
                    return {
                        'asn': whois_data.get('asn'),
                        'asn_country': whois_data.get('asn_country_code'),
                        'isp': whois_data['network'].get('name')
                    }
                except Exception as e:
                    print(f"Error fetching Whois info for IP {ip}: {e}")
                    return {}

            def check_virustotal(domain, api_key):
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {"x-apikey": api_key}
                try:
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        analysis_stats = data["data"]["attributes"]["last_analysis_stats"]
                        reputation = data["data"]["attributes"].get("reputation", "N/A")
                        
                        print(f"\nVirusTotal Analysis for {domain}:")
                        print(f"  - Malicious Detections: {analysis_stats['malicious']}")
                        print(f"  - Suspicious Detections: {analysis_stats['suspicious']}")
                        print(f"  - Reputation Score: {reputation}")
                        
                        return analysis_stats["malicious"] > 0
                    else:
                        print(f"Error from VirusTotal API: {response.status_code}")
                        return False
                except Exception as e:
                    print(f"Error checking VirusTotal: {e}")
                    return False

            api_key = "4843bb3dfe7ae15789900987297cc46aa1976d35bb09a108eb6002610a3cc2e1"

            print("\n[DNS Blacklist & Reputation Check]")
            dns_info = dns_lookup(target)
            print(f"DNS Information: {dns_info}")

            if 'A' in dns_info:
                for ip in dns_info['A']:
                    whois_info = enrich_with_whois(ip)
                    print(f"\nWhois Information for IP {ip}: {whois_info}")

            check_virustotal(target, api_key)

        except ImportError as e:
            print(f"Missing dependencies for DNS Blacklist check: {e}")

    # 10. DNS Malicious Domain Monitor
    if '10' in selected_commands:
        try:
            API_KEY = "4843bb3dfe7ae15789900987297cc46aa1976d35bb09a108eb6002610a3cc2e1"
            VT_URL = "https://www.virustotal.com/api/v3/domains/"

            def check_virustotal(domain):
                headers = {"x-apikey": API_KEY}
                response = requests.get(VT_URL + domain, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
                    return malicious_count > 0
                else:
                    print(f"Error checking {domain} on VirusTotal: {response.status_code}")
                    return False

            def log_alert(domain):
                timestamp = datetime.datetime.now()
                print(f"\n{timestamp} ALERT: {domain} is potentially malicious!")

            print("\n[DNS Malicious Domain Monitor]")
            if check_virustotal(target):
                log_alert(target)
            else:
                print(f"No malicious threats detected for {target}")

        except ImportError:
            print("Dependencies missing for Malicious Domain Monitor.")


def nmap_options_menu(target):
    """Display and run selected Nmap script categories."""
    print("\n--- Nmap Script Categories ---")
    for key, value in SCRIPT_CATEGORIES.items():
        print(f"{key}: {value[0]} (Scan Options: {value[2]})")

    selected_keys = input("Enter category keys (e.g., 1,3): ").split(',')
    selected_scripts = []
    scan_options = None

    for key in selected_keys:
        if key.strip() in SCRIPT_CATEGORIES:
            category_name, category_scripts, category_scan_options = SCRIPT_CATEGORIES[key.strip()]
            selected_scripts.extend(category_scripts)
            if not scan_options:
                scan_options = category_scan_options
        else:
            print(f"Warning: Category key '{key.strip()}' not recognized.")

    if selected_scripts:
        script_str = ','.join(selected_scripts)
        command = f'nmap {scan_options} --script {script_str} {target}'
        print(f"Running command: {command}")
        try:
            output = subprocess.check_output(command, shell=True, text=True)
            print(f"Command output:\n{output}")
        except subprocess.CalledProcessError as e:
            print(f'Error: {e.output}')
    else:
        print("No valid scripts selected. Exiting Nmap options.")
        
def traceroute_menu(target):
    """Enhanced traceroute function with MTR scan menu and network diagram plotting."""
    print("\033[1;34m[+] MTR Scan Menu:\033[1;m")
    print("\033[1;34m[1] Specify Port (-p)\033[1;m")
    print("\033[1;34m[2] Show IP and AS Numbers (-b)\033[1;m")
    print("\033[1;34m[3] Show Only Hostnames (-z)\033[1;m")
    print("\033[1;34m[4] Use TCP (--tcp)\033[1;m")
    print("\033[1;34m[5] Use ICMP (--icmp) (default)\033[1;m")
    print("\033[1;34m[6] Use UDP (--udp)\033[1;m")
    print("\033[1;34m[7] Custom Options\033[1;m")

    mtr_choice = input("\033[1;91m[+] Enter your MTR scan choice (comma-separated): \033[1;m")

    # Construct MTR command
    command = "mtr "

    if "1" in mtr_choice:
        port = input("Enter port number: ")
        command += f"-p {port} "
    if "2" in mtr_choice:
        command += "-b "
    if "3" in mtr_choice:
        command += "-z "
    if "4" in mtr_choice:
        command += "--tcp "
    elif "6" in mtr_choice:
        command += "--udp "
    
    # ICMP is default
    command += f"{target}"

    print("\033[34m[~] Running traceroute: \033[0m" + target)
    print("You can get some chai in the meantime ;p")
    time.sleep(1.5)

    # Execute MTR command
    proces = os.popen(command)
    results = str(proces.read())
    print("\033[1;34m" + results + "\nCommand: " + command + "\033[1;m")

    # Network Diagram Plotting
    plot_network_diagram = input("\033[1;91m[+] Do you want to plot the network diagram? (yes/no): \033[1;m").strip().lower()
    if plot_network_diagram == "yes":
        def run_traceroute(target):
            try:
                traceroute_command = ['traceroute', target]
                result = subprocess.run(traceroute_command, capture_output=True, text=True)
                return result.stdout
            except Exception as e:
                print(f"An error occurred while running traceroute: {e}")
                return None

        def extract_ips(traceroute_output):
            if traceroute_output:
                ip_regex = r'\((\d{1,3}(?:\.\d{1,3}){3})\)'
                return re.findall(ip_regex, traceroute_output)
            return []

        def plot_network(ips):
            G = nx.Graph()
            for ip in ips:
                G.add_node(ip)
            for i in range(len(ips) - 1):
                G.add_edge(ips[i], ips[i + 1])
            plt.figure(figsize=(10, 6))
            nx.draw(G, with_labels=True, node_color='lightblue', font_weight='bold')
            plt.title("Network Diagram")
            plt.show()

        traceroute_output = run_traceroute(target)
        ips = extract_ips(traceroute_output)
        if ips:
            print("Found the following IP addresses:")
            print(ips)
            print("Plotting the network diagram...")
            plot_network(ips)
        else:
            print("No IP addresses were found. Please check the target or traceroute output.")
    elif plot_network_diagram == "no":
        print("Skipping network diagram plotting.")

def banner():
    print(r"""\033[1;36m
              ,----. ,      .  ,---.    ,----   ,----.      ,----. .     .  ,----   ,----. .   .
             .        \    /  .     |  .       .     |     .       |     | .       .       |  /
             |         \  /   |     |  |       |     |     |       |     | |       |       | /
             |          \/    |----    |-----  |----       |       |-----| |-----  |       |-.
             |          ||    |     |  |       |    \      |       |     | |       |       |  '
             `-----'    ||    `-----'  `-----' |     \     `-----' .     . `-----' `-----' .   .

\033[1;m""")

def menu():
    print("\033[1;33m[+] 1.   DNS Lookup\033[1;m")
    print("\033[1;33m[+] 2.   Whois Lookup \033[1;m")
    print("\033[1;33m[+] 3.   Nmap Port Scan\033[1;m")
    print("\033[1;33m[+] 4.   Link Grabber\033[1;m")
    print("\033[1;33m[+] 5.   IP Location Finder\033[1;m")
    print("\033[1;33m[+] 6.   Traceroute\033[1;m")
    print("\033[1;33m[x] 7.   Exit\033[1;m\n")

def fun():
    choice = ""
    banner()

    while choice != "7":
        menu()
        choice = input("\033[1;37m[+]\033[1;m \033[1;91mEnter your choice:\033[1;m ")

        if choice == "1":
            try:
                target = input("\033[1;91m[+] Enter Domain or IP Address for DNS Lookup: \033[1;m").lower()
                dns_lookup_menu(target)
            except Exception as e:
                print(f"Error occurred during DNS Lookup: {e}")

        elif choice == "2":
            try:
                target = input("\033[1;91m[+] Enter Domain or IP Address for Whois Lookup: \033[1;m").lower()
                print("Performing Whois Lookup...")
                print(run_command(f"whois {target}"))
            except Exception as e:
                print(f"Error occurred during Whois Lookup: {e}")

        elif choice == "3":
            try:
                target = input("\033[1;91m[+] Enter Domain or IP Address for Nmap Port Scan: \033[1;m").lower()
                nmap_options_menu(target)
            except Exception as e:
                print(f"Error occurred during Nmap Scan: {e}")
                
        elif choice == "4":  # Link Grabber
            try:
                target = input("\033[1;91m[+] Enter Domain: \033[1;m").lower()
                print("\033[37m[~] Scanning Link Grabber: \033[0m\n" + target)
                time.sleep(2)

                if not (target.startswith("http://") or target.startswith("https://")):
                    target = "http://" + target
        
                deq = deque([target])
                pro = set()

                print("Press Enter at any time to stop crawling.")

                try:
                    while deq:
                        # Check for user interruption
                        print("[+] Crawling URL " + "\033[34m" + deq[0] + "\033[0m")
                        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                            input("\n[!] Interruption detected. Press Enter to stop crawling.\n")
                            break

                        url = deq.popleft()
                        pro.add(url)
                        parts = urlsplit(url)
                        base = "{0.scheme}://{0.netloc}".format(parts)

                        try:
                            response = requests.get(url, timeout=5)  # Add a timeout for the request
                            soup = BeautifulSoup(response.text, "lxml")
                            for anchor in soup.find_all("a", href=True):  # Only get anchors with href attribute
                                link = anchor.get("href")
                                if link.startswith("/"):
                                    link = urljoin(base, link)
                                # Normalize links to avoid duplicates
                                link = link.split('#')[0]  # Remove fragment identifiers
                                if link and link not in pro:
                                    deq.append(link)

                        except requests.exceptions.RequestException as e:
                            print(f"[-] Request failed: {e}")
                            continue

                except KeyboardInterrupt:
                    print("\n[-] Process interrupted by user.")
                finally:
                    print("\033[34m[!] Link Grabber process stopped.\033[0m\n")

            except Exception as e:
                print(f"[-] An error occurred: {e}")

        elif choice == "5":  # IP Location Finder
            try:
                target = input("\033[1;91m[+] Enter Domain or IP Address: \033[1;m").lower()
                url = "http://ip-api.com/json/"
                response = urllib_request.urlopen(url + target)
                data = response.read()
                jso = json.loads(data)
                print("\033[37m[~] IP Location Info: \033[0m\n")
                print(f"URL: {target}\nIP: {jso['query']}\nStatus: {jso['status']}")
                print(f"Region: {jso['regionName']}\nCountry: {jso['country']}\nCity: {jso['city']}")
                print(f"ISP: {jso['isp']}\nLat & Lon: {jso['lat']} & {jso['lon']}")
                print(f"Zipcode: {jso['zip']}\nTimeZone: {jso['timezone']}\nAS: {jso['as']}")

            except Exception as e:
                print(f"Error in IP Location Finder: {e}")

        elif choice == "6":  # Traceroute
            try:
                target = input("\033[1;91m[+] Enter the target domain or IP address: \033[1;m").lower()
                traceroute_menu(target)
            except Exception as e:
                print(f"Error in Traceroute: {e}")

        elif choice == "7":
            print("\nExiting... Goodbye!\n")
            break

# Main execution
if __name__ == "__main__":
    fun()
                
        

