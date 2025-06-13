import os, json, asyncio, urllib.parse
from collections import defaultdict
from typing import Any, Coroutine, Dict, List, Optional, Union
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from colorama import Fore, Style
from tqdm.asyncio import tqdm
from core import USER_AGENT, make_request

HACKERTARGET_REVERSE_IP_URL = "https://api.hackertarget.com/reverseiplookup/"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
QUALYS_ENDPOINT_URL = "https://api.ssllabs.com/api/v3/getEndpointData"
HYBRID_ANALYSIS_SEARCH_URL = "https://www.hybrid-analysis.com/api/v2/search/terms"
CERT_TRANS_URL = "https://crt.sh/"
GITHUB_REPO_SEARCH_URL = "https://api.github.com/search/repositories"
INTELX_SEARCH_URL = "https://free.intelx.io/intelligent/search"
INTELX_RESULT_URL_TPL = "https://free.intelx.io/intelligent/search/result?id={search_id}"
BING_SEARCH_URL = "https://api.bing.microsoft.com/v7.0/search"
VULNERS_API_URL = "https://vulners.com/api/v3/light/vulnerability/"
NIST_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NIKTO_COMMAND = "nikto"
SSLSCAN_COMMAND = "sslscan"

def _is_api_error(response: Any) -> bool:
    return isinstance(response, dict) and "error" in response

async def _run_command(command: List[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return (
            process.returncode or 0,
            stdout_bytes.decode(errors='ignore'),
            stderr_bytes.decode(errors='ignore')
        )
    except FileNotFoundError:
        return -1, "", f"Command not found: '{command[0]}'"
    except asyncio.TimeoutError:
        return -2, "", f"Command timed out after {timeout} seconds: '{' '.join(command)}'"
    except Exception as e:
        return -3, "", f"Failed to run command '{' '.join(command)}': {e}"

async def get_active_shared_hosts(client: Any, ip: str) -> List[str]:
    params = {"q": ip}
    response_text = await make_request(client, HACKERTARGET_REVERSE_IP_URL, params=params)

    if _is_api_error(response_text):
        return [response_text["error"]]

    if isinstance(response_text, str):
        lines = response_text.splitlines()
        if lines and "API count exceeded" in lines[0]:
            return ["HackerTarget: API count exceeded"]
        return [vhost for vhost in lines if vhost != ip and vhost.strip()]

    return ["HackerTarget: Unexpected response format"]

async def get_shodan_ip_infos(client: Any, ip: str, api_key: str) -> List[str]:
    if not api_key:
        return ["Shodan API key not configured"]

    service_url = SHODAN_HOST_URL.format(ip=ip)
    params = {"key": api_key, "minify": "true"}
    data = await make_request(client, service_url, params=params)

    if _is_api_error(data):
        return [f"Shodan Error: {data['error']}"]

    if isinstance(data, dict):
        hostnames = data.get('hostnames')
        return [
            f"Last scan date = {data.get('last_update', 'N/A')}",
            f"ISP = {data.get('isp', 'N/A')}",
            f"Organization = {data.get('org', 'N/A')}",
            f"Hostnames = {', '.join(hostnames) if hostnames else 'N/A'}",
            f"Open Ports = {data.get('ports', 'N/A')}"
        ]

    return ["Shodan: Unexpected response format"]

async def get_shodan_cpe_cve_infos(client: Any, ip: str, api_key: str) -> List[str]:
    if not api_key:
        return ["Shodan API key not configured"]

    service_url = SHODAN_HOST_URL.format(ip=ip)
    params = {"key": api_key}
    data = await make_request(client, service_url, params=params)

    if _is_api_error(data):
        return [f"Shodan Error: {data.get('error', 'Unknown error')}"]

    if not (isinstance(data, dict) and 'data' in data):
        return ["Shodan: Unexpected response format or no detailed data found."]

    infos = [f"Shodan Full Scan Data (Last Update: {data.get('last_update', 'N/A')})"]
    sorted_port_data = sorted(data.get("data", []), key=lambda x: x.get("port", 0))

    if not sorted_port_data:
        infos.append("  No detailed service data found by Shodan for this IP.")
        return infos

    for record in sorted_port_data:
        port_info = f"  Port {record.get('port')}/{record.get('transport', 'tcp').lower()}"
        infos.append(port_info)

        details = []
        if record.get("product"):
            details.append(f"Product: {record.get('product')} (Version: {record.get('version', 'N/A')})")
        if record.get("cpe"):
            details.extend([f"CPE: {cpe}" for cpe in set(record["cpe"])])
        if record.get("vulns"):
            details.append("Detected CVEs:")
            for cve_id, cve_data in record["vulns"].items():
                cvss = cve_data.get('cvss', 'N/A')
                summary = cve_data.get('summary', 'No summary.')
                details.append(f"  - {cve_id} (CVSS: {cvss}): {summary[:80]}...")

        if details:
            for detail in details:
                infos.append(f"    {detail}")
        else:
            infos.append("    Basic service detected (no further details).")

    return infos

async def get_qualys_sslscan_cached_infos(client: Any, domain: str, ip: str) -> List[str]:
    params = {"host": domain, "s": ip, "fromCache": "on", "all": "done"}
    data = await make_request(client, QUALYS_ENDPOINT_URL, params=params)

    if _is_api_error(data):
        return [f"Qualys Error: {data['error']}"]
    if isinstance(data, dict) and data.get("errors"):
        return [err.get("message", "Unknown Qualys Error") for err in data["errors"]]

    if isinstance(data, dict) and data.get("status") == "READY":
        details = data.get("details", {})
        protocols = ", ".join([p['name'] + ' ' + p['version'] for p in details.get('protocols', [])])
        return [
            f"Grade = {data.get('grade', 'N/A')}",
            f"Protocols = {protocols}",
            f"BEAST Vulnerable = {details.get('vulnBeast', False)}",
            f"HEARTBLEED Vulnerable = {details.get('heartbleed', False)}",
            f"POODLE Vulnerable = {details.get('poodle', False)}",
        ]

    if isinstance(data, dict) and data.get("statusMessage"):
        return [f"Qualys Status: {data['statusMessage']}"]

    return ["Qualys: No cached report ready or unexpected response."]

async def get_hybrid_analysis_report_infos(client: Any, query: str, api_key: str) -> List[str]:
    if not api_key:
        return ["Hybrid Analysis API key not configured"]

    headers = {"User-Agent": "InterrogateReconTool/1.0", "api-key": api_key}
    json_payload = {"term": query}
    data = await make_request(client, HYBRID_ANALYSIS_SEARCH_URL, method="POST", headers=headers, json_data=json_payload)

    if _is_api_error(data):
        return [f"Hybrid Analysis Error: {data['error']}"]

    if isinstance(data, list) and data:
        result = data[0]
        return [
            f"Verdict = {result.get('verdict', 'unknown').capitalize()}",
            f"Threat Score = {result.get('threat_score', 'N/A')}",
            f"Analysis time = {result.get('analysis_start_time', 'N/A')}"
        ]
    elif isinstance(data, list):
        return ["No report found"]

    return [f"Hybrid Analysis API Error: {data.get('message', 'Unexpected response')}"]

async def get_certificate_transparency_log_subdomains(client: Any, domain: str) -> List[str]:
    params = {"q": f"%.{domain}", "output": "json"}
    data = await make_request(client, CERT_TRANS_URL, params=params)

    if _is_api_error(data):
        return [f"Cert Transparency Error: {data['error']}"]

    if isinstance(data, list):
        subdomains = set()
        for entry in data:
            for name in entry.get('name_value', '').split('\n'):
                clean_name = name.strip().lstrip('*.')
                if clean_name.endswith(domain):
                    subdomains.add(clean_name)
        if subdomains:
            return sorted(list(subdomains))
        return ["No subdomains found via Certificate Transparency."]

    return ["Cert Transparency: Unexpected response format"]

async def get_github_repositories(client: Any, domain_or_ip: str) -> List[str]:
    search_term = urllib.parse.quote(f'"{domain_or_ip}"')
    params = {"q": search_term, "sort": "updated", "order": "desc", "per_page": 50}
    headers = {"Accept": "application/vnd.github.v3+json"}
    data = await make_request(client, GITHUB_REPO_SEARCH_URL, headers=headers, params=params)

    if _is_api_error(data):
        if "rate limit" in data.get("content", "").lower():
            return ["GitHub Error: API rate limit exceeded."]
        return [f"GitHub Error: {data['error']}"]

    if isinstance(data, dict) and "items" in data:
        if not data["items"]:
            return [f"No public repositories found mentioning '{domain_or_ip}'."]
        return [
            f"{repo.get('html_url')} (Owner: {repo.get('owner', {}).get('login')}, Stars: {repo.get('stargazers_count')})"
            for repo in data["items"]
        ]

    return [f"GitHub API Error: {data.get('message', 'Unexpected response')}"]

async def get_robots_txt(client: Any, domain: str) -> List[str]:
    infos = []
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}/robots.txt"
        response = await make_request(client, url)
        if isinstance(response, str):
            infos.append(f"Found at: {url}")
            disallows = [line.split(":", 1)[1].strip() for line in response.splitlines() if line.strip().lower().startswith("disallow:")]
            sitemaps = [line.split(":", 1)[1].strip() for line in response.splitlines() if line.strip().lower().startswith("sitemap:")]
            if disallows: infos.append(f"  Disallowed paths found: {len(disallows)}")
            if sitemaps: infos.append(f"  Sitemap references: {', '.join(sitemaps)}")
            return infos
        elif _is_api_error(response) and response.get("status_code") != 404:
            infos.append(f"Checked {url} - Error: {response['error']}")

    return infos if infos else ["robots.txt not found at standard locations."]

async def get_wayback_urls(client: Any, domain: str) -> List[str]:
    try:
        from waybackpy import WaybackMachineCDXServerAPI
        loop = asyncio.get_running_loop()

        cdx = WaybackMachineCDXServerAPI(f"*.{domain}", USER_AGENT, limit=500)
        snapshots = await loop.run_in_executor(None, cdx.snapshots)

        urls = sorted(list(set(s.original for s in snapshots)))

        if urls:
            return [f"Found {len(urls)} unique archived URLs (showing up to 200):"] + urls[:200]
        return ["No archived URLs found via CDX API."]
    except Exception as e:
        return [f"Wayback Machine CDX API Error: {e}", f"Manual Check: https://web.archive.org/web/*/{domain}/*"]

async def run_nikto_scan(target_ip: str, target_port: int, protocol: str, output_dir: str) -> List[str]:
    target_url = f"{protocol}://{target_ip}:{target_port}/"
    output_filename = os.path.join(output_dir, f"nikto_{target_ip}_{target_port}.json")

    command_args = [
        NIKTO_COMMAND, "-h", target_ip, "-p", str(target_port),
        "-Format", "json", "-o", output_filename, "-ask", "no", "-maxtime", "60s"
    ]
    if protocol == "https":
        command_args.append("-ssl")

    print(Fore.CYAN + f"    [Nikto] Starting scan on {target_url}..." + Style.RESET_ALL)
    ret_code, _, stderr = await _run_command(command_args, timeout=90)

    if ret_code != 0:
        return [f"Nikto scan failed for {target_url} (Code: {ret_code}). Error: {stderr[:300]}"]

    if not (os.path.exists(output_filename) and os.path.getsize(output_filename) > 0):
        return [f"Nikto ran but produced no output file for {target_url}."]

    results = [f"Nikto JSON report saved to: {output_filename}"]
    try:
        with open(output_filename, 'r') as f:
            nikto_data = json.load(f)

        vulnerabilities = nikto_data[0].get("vulnerabilities", [])
        if vulnerabilities:
            results.append(f"  Found {len(vulnerabilities)} potential issues:")
            for vuln in vulnerabilities[:5]:
                results.append(f"    - OSVDB-{vuln.get('OSVDB')}: {vuln.get('msg', 'N/A')[:100]}")
            if len(vulnerabilities) > 5:
                results.append(f"    ... and {len(vulnerabilities) - 5} more (see JSON report).")
        else:
            results.append("  No specific vulnerabilities found by Nikto.")
    except (json.JSONDecodeError, IndexError, KeyError) as e:
        results.append(f"  Could not parse Nikto JSON report: {e}")

    return results

async def run_sslscan(target_ip: str, target_port: int, output_dir: str) -> List[str]:
    target_host_port = f"{target_ip}:{target_port}"
    output_filename = os.path.join(output_dir, f"sslscan_{target_ip}_{target_port}.xml")

    command_args = [SSLSCAN_COMMAND, "--no-colour", "--xml=" + output_filename, target_host_port]

    print(Fore.CYAN + f"    [SSLScan] Starting scan on {target_host_port}..." + Style.RESET_ALL)
    ret_code, _, stderr = await _run_command(command_args, timeout=120)

    if ret_code != 0:
        return [f"SSLScan failed for {target_host_port} (Code: {ret_code}). Error: {stderr[:300]}"]

    if not (os.path.exists(output_filename) and os.path.getsize(output_filename) > 0):
        return [f"SSLScan ran but produced no XML output file for {target_host_port}."]

    results = [f"SSLScan XML report saved to: {output_filename}"]
    try:
        tree = ET.parse(output_filename)
        root = tree.getroot()

        results.append("  Supported Protocols:")
        for protocol_node in root.findall(".//protocol"):
            if protocol_node.get("enabled") == "1":
                results.append(f"    - {protocol_node.get('type')} {protocol_node.get('version')}")

        weak_ciphers = [
            c.get("cipher") for c in root.findall(".//cipher[@status='accepted']")
            if any(weak in c.get("cipher", "").lower() for weak in ["rc4", "3des", "null", "anon"])
        ]
        if weak_ciphers:
            results.append("  Potential Weak Ciphers Accepted:")
            for wc in weak_ciphers[:5]:
                results.append(f"    - {wc}")
        else:
            results.append("  No obviously weak ciphers found.")

        cert_node = root.find(".//certificate")
        if cert_node:
            results.append("  Certificate Information:")
            results.append(f"    Subject: {cert_node.findtext('.//subject', 'N/A')}")
            results.append(f"    Issuer: {cert_node.findtext('.//issuer', 'N/A')}")
            results.append(f"    Signature Algorithm: {cert_node.findtext('.//signature-algorithm', 'N/A')}")

    except ET.ParseError as e:
        results.append(f"  Could not parse SSLScan XML report: {e}")

    return results

async def get_nist_nvd_data(client: Any, cpe_string: str, api_key: Optional[str]) -> List[str]:
    if not api_key:
        return ["NIST NVD API key not configured"]

    headers = {"apiKey": api_key}
    params = {"cpeName": cpe_string, "resultsPerPage": 20}

    print(Fore.CYAN + f"      [NIST NVD] Querying for CPE: {cpe_string}" + Style.RESET_ALL)
    await asyncio.sleep(0.7)

    data = await make_request(client, NIST_NVD_API_URL, headers=headers, params=params)

    if _is_api_error(data):
        return [f"NIST NVD Error for {cpe_string}: {data['error']}"]

    if isinstance(data, dict) and "vulnerabilities" in data:
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return [f"No CVEs found by NIST NVD for CPE: {cpe_string}"]

        results = [f"Found {len(vulns)} CVEs for {cpe_string}:"]
        for v in vulns[:5]:
            cve_id = v['cve']['id']
            description = next((d['value'] for d in v['cve']['descriptions'] if d['lang'] == 'en'), "No description.")
            cvss_v3 = v['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
            score = cvss_v3.get('baseScore', 'N/A')
            severity = cvss_v3.get('baseSeverity', 'N/A')

            results.append(f"    - {cve_id} (CVSS: {score} {severity}) - {description[:100]}...")
        if len(vulns) > 5:
            results.append(f"    ... and {len(vulns) - 5} more.")
        return results

    return [f"NIST NVD: Unexpected response format for {cpe_string}."]

async def get_intelx_infos(client: Any, query: str, api_key: str) -> List[str]: return ["IntelX module not fully shown."]
async def get_bing_dork_results(client: Any, dork: str, api_key: str) -> List[str]: return ["Bing module not fully shown."]
async def get_sitemap_xml(client: Any, domain: str) -> List[str]: return ["Sitemap module not fully shown."]
async def get_favicon_hash(client: Any, domain: str) -> List[str]: return ["Favicon module not fully shown."]
async def get_vulners_data(client: Any, cpe: str, api_key: str) -> List[str]: return ["Vulners module not fully shown."]
