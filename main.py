import os, sys, time, subprocess, httpx, pyfiglet
import asyncio, argparse, configparser
from typing import Any, Dict, List, Optional, Tuple, Union
import xml.etree.ElementTree as ET
from colorama import Fore, Style, init
from core import (get_dns_records, get_random_user_agent, print_infos)
from modules import (run_nikto_scan, run_sslscan)

CONFIG_FILE = "config.ini"
API_KEYS: Dict[str, Optional[str]] = {}

def display_banner(text: str, font: str = "small", color: str = Fore.GREEN) -> None:
    try:
        banner = pyfiglet.figlet_format(text, font=font)
        print(color + Style.BRIGHT + banner + Style.RESET_ALL)
    except pyfiglet.FontNotFound:
        print(color + Style.BRIGHT + f"--- {text} ---" + Style.RESET_ALL)

def load_api_keys() -> None:
    global API_KEYS
    if not os.path.exists(CONFIG_FILE):
        print(Fore.RED + f"Error: Configuration file '{CONFIG_FILE}' not found.")
        print(Fore.YELLOW + "Please create it from 'config.ini.example' and add your API keys.")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if 'API_KEYS' not in config:
        print(Fore.RED + f"Error: [API_KEYS] section not found in '{CONFIG_FILE}'.")
        sys.exit(1)

    API_KEYS = {
        "shodan": config.get('API_KEYS', 'shodan', fallback=None),
        "hybrid-analysis": config.get('API_KEYS', 'hybrid-analysis', fallback=None),
        "intelx": config.get('API_KEYS', 'intelx', fallback=None),
        "bing-web-search": config.get('API_KEYS', 'bing-web-search', fallback=None),
        "vulners": config.get('API_KEYS', 'vulners', fallback=None),
        "nist_nvd": config.get('API_KEYS', 'nist_nvd', fallback=None),
    }
    print(Fore.GREEN + "API keys loaded from config.ini." + Style.RESET_ALL)

def _parse_nmap_port(port_node: ET.Element) -> Optional[Dict[str, Any]]:
    state_node = port_node.find("state")
    if state_node is None or state_node.get("state") != "open":
        return None

    service_node = port_node.find("service")
    port_id = port_node.get("portid")

    service_info = {
        'protocol': port_node.get("protocol"),
        'port': int(port_id) if port_id and port_id.isdigit() else port_id,
        'state': state_node.get("state"),
        'service_name': "N/A", 'product': "", 'version': "", 'cpe': "N/A", 'script_results': {}
    }

    if service_node is not None:
        service_info.update({
            'service_name': service_node.get("name", "N/A"),
            'product': service_node.get("product", ""),
            'version': service_node.get("version", ""),
            'cpe': next((c.text for c in service_node.findall("cpe")), "N/A"),
        })

    service_info['full_service_string'] = f"{service_info.get('product','')} {service_info.get('version','')}".strip()

    for script_node in port_node.findall("script"):
        script_id, script_output = script_node.get("id"), script_node.get("output")
        if script_id and script_output: service_info['script_results'][script_id] = script_output

    return service_info

async def run_nmap_scan(ip: str, profile: str, custom_args: str) -> Union[List[Dict[str, Any]], str]:
    nmap_profiles = {
        "light": "-sS -T4 --top-ports 20 --host-timeout 1m",
        "default": "-sS -sV --script=default,vuln --host-timeout 2m",
        "full": "-sS -sV -A -O --script=all --host-timeout 5m",
        "custom": custom_args
    }
    scan_args = nmap_profiles.get(profile, nmap_profiles["default"])
    command = ["nmap", *scan_args.split(), "--reason", "-oX", "-", ip]
    print(Fore.CYAN + f"  [NMAP] Executing: {' '.join(command)}" + Style.RESET_ALL)

    try:
        process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=720)
    except asyncio.TimeoutError:
        try: process.kill()
        except ProcessLookupError: pass
        return f"Nmap scan for {ip} timed out."
    except FileNotFoundError:
        return "Nmap executable not found. Please install it and ensure it's in your PATH."

    if process.returncode != 0: return f"Nmap scan for {ip} failed. Error: {stderr.decode(errors='ignore')[:300]}"
    xml_output = stdout.decode(errors='ignore')
    if not xml_output.strip(): return f"Nmap scan for {ip} produced no output. Stderr: {stderr.decode(errors='ignore')[:300]}"
    try: root = ET.fromstring(xml_output)
    except ET.ParseError as e: return f"Nmap scan for {ip}: Failed to parse XML output. Error: {e}"

    host_node = root.find("host")
    if host_node is None:
        if root.find("runstats/hosts[@up='0']") is not None: return f"Nmap: Host {ip} appears to be down."
        return "Nmap: No host data found in XML output."
    if host_node.find("status").get("state") != "up": return f"Nmap: Host {ip} is not up (Reason: {host_node.find('status').get('reason', 'N/A')})."

    open_ports = [_parse_nmap_port(p) for p in host_node.findall("ports/port")]
    open_ports = [p for p in open_ports if p is not None]
    if not open_ports: return f"Nmap scan for {ip} completed. Host is up, but no open ports were found."
    return open_ports

def search_exploitdb(service_info: str) -> List[str]:
    search_term = service_info.strip()
    if not search_term or service_info == "N/A": return []
    try:
        check_process = subprocess.run(["searchsploit", "-h"], capture_output=True, text=True, check=False, timeout=5)
        if check_process.returncode != 0 and "command not found" in check_process.stderr.lower(): return ["searchsploit command not found."]
        result = subprocess.run(["searchsploit", "--disable-colour", search_term], capture_output=True, text=True, timeout=30, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e: return [f"Error running searchsploit: {e}"]
    if not result.stdout: return []
    exploit_lines = [line for line in result.stdout.splitlines() if "|" in line and not line.startswith("Exploit Title") and not set(line) <= set('-| ')]
    exploits = []
    for line in exploit_lines:
        parts = line.split("|")
        if len(parts) >= 2: exploits.append(f"    [Exploit-DB] {parts[0].strip()} - Path: {parts[1].strip()}")
    return exploits

async def run_dns_and_ip_discovery(domain: str, ns: Optional[str]) -> List[str]:
    print(Fore.CYAN + "\n--- DNS & IP Discovery ---" + Style.RESET_ALL)
    record_types = ["A", "AAAA", "CNAME"]
    dns_results = await get_dns_records(domain, ns, record_types)
    ips = set(dns_results.get("A", []) + dns_results.get("AAAA", []))
    valid_ips = {ip for ip in ips if not ip.startswith("Error:")}
    if not valid_ips and "CNAME" in dns_results and dns_results["CNAME"] and not dns_results["CNAME"][0].startswith("Error:"):
        cname_target = dns_results["CNAME"][0].split(" ")[-1]
        print(Fore.YELLOW + f"No A/AAAA records. Following CNAME to: {cname_target}" + Style.RESET_ALL)
        cname_dns_results = await get_dns_records(cname_target, ns, ["A", "AAAA"])
        cname_ips = set(cname_dns_results.get("A", []) + cname_dns_results.get("AAAA", []))
        valid_ips = {ip for ip in cname_ips if not ip.startswith("Error:")}
    if valid_ips:
        print(Fore.GREEN + "\nResolved IP Addresses:" + Style.RESET_ALL)
        print_infos(sorted(list(valid_ips)), "  ")
    else:
        print(Fore.RED + "\nCould not resolve any valid IP addresses for the target." + Style.RESET_ALL)
    return sorted(list(valid_ips))

async def run_active_scans(ips: List[str], args: argparse.Namespace, output_dir: str) -> None:
    if not ips or args.skip_nmap: return
    print(Fore.CYAN + "\n--- Active Scans ---" + Style.RESET_ALL)
    for ip in ips:
        print(Fore.YELLOW + f"\n--- Starting active scans for IP: {ip} ---" + Style.RESET_ALL)
        nmap_results = await run_nmap_scan(ip, args.nmap_profile, args.nmap_args)
        if isinstance(nmap_results, str):
            print(Fore.RED + f"  [Nmap] {nmap_results}" + Style.RESET_ALL)
            continue
        for port_info in nmap_results:
            port_str, service_str = f"{port_info['port']}/{port_info['protocol']}", f"{port_info['service_name']} {port_info['full_service_string']}"
            print(Fore.GREEN + f"\n  Port {port_str}: {service_str}" + Style.RESET_ALL)
            if port_info['full_service_string']:
                exploits = search_exploitdb(port_info['full_service_string'])
                if exploits:
                    print(Fore.BLUE + "    [Exploit-DB]" + Style.RESET_ALL)
                    print_infos(exploits, "      ")
            is_http = "http" in port_info['service_name'].lower() or port_info['port'] in [80, 443, 8080, 8443]
            if args.nikto and is_http:
                protocol = "https" if "ssl" in port_info['service_name'].lower() or port_info['port'] in [443, 8443] else "http"
                nikto_report = await run_nikto_scan(ip, port_info['port'], protocol, output_dir)
                print(Fore.BLUE + f"    [Nikto] Scan for {ip}:{port_info['port']}" + Style.RESET_ALL); print_infos(nikto_report, "      ")
            is_ssl = "ssl" in port_info['service_name'].lower() or port_info['port'] in [443, 8443, 993, 995]
            if args.sslscan and is_ssl:
                ssl_report = await run_sslscan(ip, port_info['port'], output_dir)
                print(Fore.BLUE + f"    [SSLScan] Scan for {ip}:{port_info['port']}" + Style.RESET_ALL); print_infos(ssl_report, "      ")

def setup_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interrogate: A comprehensive reconnaissance tool.", formatter_class=argparse.RawTextHelpFormatter, epilog=Fore.YELLOW + "Example: python main.py -d example.com --nikto" + Style.RESET_ALL)
    general = parser.add_argument_group('General Options')
    general.add_argument("-d", "--domain", dest="domain_name", required=True, help="The target domain to analyze.")
    general.add_argument("-n", "--name-server", dest="name_server", default=None, help="Specific DNS server for queries (e.g., 8.8.8.8).")
    general.add_argument("-o", "--output", dest="output_dir", default="recon_results", help="Directory to save results.")
    active = parser.add_argument_group('Active Scanning Options')
    active.add_argument("--skip-nmap", action="store_true", help="Skip Nmap and all related active scans.")
    active.add_argument("--nmap-profile", default="default", choices=["light", "default", "full", "custom"], help="Nmap scan profile.")
    active.add_argument("--nmap-args", default="-sS -sV", help="Custom Nmap arguments for the 'custom' profile.")
    active.add_argument("--nikto", action="store_true", help="Run Nikto scans on identified web services.")
    active.add_argument("--sslscan", action="store_true", help="Run SSLScan on identified SSL/TLS services.")
    return parser

async def main() -> None:
    init(autoreset=True)
    start_time = time.time()
    parser = setup_arg_parser()
    if len(sys.argv) == 1: parser.print_help(sys.stderr); sys.exit(1)
    args = parser.parse_args()
    load_api_keys()
    output_dir = os.path.join(args.output_dir, args.domain_name.replace('.', '_') + "_" + time.strftime("%Y%m%d"))
    os.makedirs(output_dir, exist_ok=True)
    print(Fore.GREEN + f"Results will be saved in: {output_dir}" + Style.RESET_ALL)

    display_banner(args.domain_name, font="slant")

    async with httpx.AsyncClient(verify=True, timeout=30, http2=True) as client:
        client.headers.update({"User-Agent": get_random_user_agent()})
        valid_ips = await run_dns_and_ip_discovery(args.domain_name, args.name_server)
        if not valid_ips:
            print(Fore.YELLOW + "No IPs to scan. Exiting IP-dependent modules." + Style.RESET_ALL)
            return
        await run_active_scans(valid_ips, args, output_dir)
    duration = round(time.time() - start_time, 2)
    print(Fore.CYAN + Style.BRIGHT + f"\nReconnaissance finished in {duration} seconds." + Style.RESET_ALL)

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\n" + Fore.RED + "Scan interrupted by user." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"\nAn unexpected error occurred: {e}" + Style.RESET_ALL)
        import traceback
        traceback.print_exc()
        sys.exit(1)
