import asyncio, json, random, httpx, dns.resolver
import socket, time, urllib.parse, tldextract
from typing import Any, Coroutine, Dict, List, Optional, Tuple, Union
from colorama import Fore, Style
from tqdm.asyncio import tqdm

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
    "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"
]

USER_AGENT = USER_AGENTS[0]

CLOUD_KEYWORDS = {
    "AMAZON", "AWS", "GOOGLE", "GCP", "MICROSOFT", "AZURE",
    "CLOUDFLARE", "AKAMAI", "FASTLY", "ORACLE CLOUD", "OVH",
    "HETZNER", "DIGITALOCEAN"
}

DNS_LIFETIME = 10.0
DNS_TIMEOUT = 5.0
WHOIS_PORT = 43
WHOIS_TIMEOUT = 10
HTTP_TIMEOUT = 30
GOOGLE_SEARCH_PAUSE = 2.5

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def print_infos(info_list: Union[List[str], str, None], prefix: str = "") -> None:
    if not info_list:
        print(f"{prefix}No data found")
        return

    if isinstance(info_list, (list, tuple, set)):
        for info in info_list:
            print(f"{prefix}{info}")
    else:
        print(f"{prefix}{info_list}")

def get_domain_without_tld(domain: str) -> str:
    try:
        domain_infos = tldextract.extract(domain)
        if domain_infos.subdomain:
            return f"{domain_infos.subdomain}.{domain_infos.domain}"
        return domain_infos.domain
    except Exception:
        parts = domain.split('.')
        return '.'.join(parts[:-1]) if len(parts) > 1 else domain

async def run_in_executor(func: Coroutine) -> Any:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func)

async def run_sync_dns_resolve(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> List[str]:
    try:
        answer = await run_in_executor(lambda: resolver.resolve(domain, record_type))
        return [data.to_text().strip('.') for data in answer]
    except Exception as e:
        return [f"Error: {e}"]

async def run_sync_whois_lookup(ip: str, whois_server: str) -> str:
    def do_lookup() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(WHOIS_TIMEOUT)
                s.connect((whois_server, WHOIS_PORT))
                s.sendall((ip + "\r\n").encode())
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                return response.decode("utf-8", "ignore")
        except socket.timeout:
            return f"WHOIS timeout connecting to {whois_server}"
        except socket.error as e:
            return f"WHOIS socket error with {whois_server}: {e}"
        except Exception as e:
            return f"WHOIS unexpected error with {whois_server}: {e}"

    return await run_in_executor(do_lookup)

async def run_sync_ipwhois_lookup(ip: str) -> Dict[str, Any]:
    def do_lookup() -> Dict[str, Any]:
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            return obj.lookup_rdap(depth=1)
        except Exception as e:
            return {"error": str(e)}

    return await run_in_executor(do_lookup)

async def run_sync_google_search(dork: str) -> List[str]:
    def do_search() -> List[str]:
        try:
            from googlesearch import search as google_search
            from urllib.error import HTTPError as GoogleHTTPError

            results = list(
                google_search(
                    dork, tld="com", num=100, stop=100,
                    pause=GOOGLE_SEARCH_PAUSE, user_agent=get_random_user_agent()
                )
            )
            return sorted([f"Record found: {result}" for result in results])
        except GoogleHTTPError as err:
            if err.code == 429:
                url_encoded_dork = urllib.parse.quote(dork)
                return [
                    "Google responded with 'HTTP Error 429: Too Many Requests'.",
                    "This is common when scraping. Use the dork in a browser:",
                    f"https://www.google.com/search?q={url_encoded_dork}"
                ]
            return [f"Google search HTTP error {err.code}: {err.reason}"]
        except Exception as e:
            return [f"Google search failed: {type(e).__name__} - {e}"]

    return await run_in_executor(do_search)

async def _get_resolver(name_server: Optional[str]) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = DNS_LIFETIME
    resolver.timeout = DNS_TIMEOUT

    if not name_server:
        print(Fore.CYAN + "  [DNS] Using system default name server(s)." + Style.RESET_ALL)
        return resolver

    try:
        socket.inet_pton(socket.AF_INET6 if ":" in name_server else socket.AF_INET, name_server)
        resolver.nameservers = [name_server]
        print(Fore.CYAN + f"  [DNS] Using specified IP nameserver: {name_server}" + Style.RESET_ALL)
        return resolver
    except socket.error:
        pass

    print(Fore.CYAN + f"  [DNS] Resolving hostname for specified nameserver: {name_server}..." + Style.RESET_ALL)
    try:
        default_resolver = dns.resolver.Resolver(configure=True)
        default_resolver.lifetime = DNS_LIFETIME
        ns_ips = await run_sync_dns_resolve(default_resolver, name_server, "A")

        if ns_ips and not ns_ips[0].startswith("Error:"):
            resolver.nameservers = ns_ips
            print(Fore.CYAN + f"  [DNS] Using resolved IPs for nameserver {name_server}: {', '.join(ns_ips)}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"  [DNS] Could not resolve custom nameserver '{name_server}'. Using system default." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"  [DNS] Error setting custom nameserver '{name_server}': {e}. Using system default." + Style.RESET_ALL)

    return resolver

async def get_dns_records(domain: str, name_server: Optional[str], record_types: List[str]) -> Dict[str, List[str]]:
    resolver = await _get_resolver(name_server)
    tasks = [run_sync_dns_resolve(resolver, domain, rt) for rt in record_types]
    dns_results_list = await tqdm.gather(
        *tasks, desc="Resolving DNS", unit="record", colour="green", leave=False
    )
    return dict(zip(record_types, dns_results_list))

async def check_email_security(domain: str, name_server: Optional[str]) -> List[str]:
    results = {"SPF": "Not found", "DMARC": "Not found", "DKIM": []}
    txt_records_map = await get_dns_records(domain, name_server, ["TXT"])
    txt_records = txt_records_map.get("TXT", [])

    for record in txt_records:
        if record.startswith('"v=spf1'):
            results["SPF"] = record.strip('"')
        elif record.startswith('"v=DMARC1'):
            results["DMARC"] = record.strip('"')

    common_selectors = ["default", "google", "selector1", "selector2", "k1", "k2", "dkim"]
    resolver = await _get_resolver(name_server)
    dkim_tasks = []
    for selector in common_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        dkim_tasks.append(run_sync_dns_resolve(resolver, dkim_domain, "TXT"))
        dkim_tasks.append(run_sync_dns_resolve(resolver, dkim_domain, "CNAME"))

    dkim_check_results = await asyncio.gather(*dkim_tasks)

    for i in range(0, len(dkim_check_results), 2):
        selector = common_selectors[i // 2]
        txt_result, cname_result = dkim_check_results[i], dkim_check_results[i + 1]
        dkim_domain_prefix = f"{selector}._domainkey.{domain}"
        if txt_result and not txt_result[0].startswith("Error:"):
            results["DKIM"].append(f"{dkim_domain_prefix} (TXT): {txt_result[0][:100]}...")
        if cname_result and not cname_result[0].startswith("Error:"):
            results["DKIM"].append(f"{dkim_domain_prefix} (CNAME): {cname_result[0]}")

    if not results["DKIM"]:
        results["DKIM"] = ["No common DKIM selectors found"]

    output = [f"SPF: {results['SPF']}", f"DMARC: {results['DMARC']}"]
    output.extend([f"DKIM Check: {dkim}" for dkim in results["DKIM"]])
    return output

async def get_asn_info(ip: str) -> List[str]:
    rdap_data = await run_sync_ipwhois_lookup(ip)
    if rdap_data and rdap_data.get("asn"):
        description = rdap_data.get('asn_description', 'N/A')
        is_cloud = "No"
        for keyword in CLOUD_KEYWORDS:
            if keyword in description.upper():
                is_cloud = f"Yes ({keyword})"
                break
        return [
            f"ASN: AS{rdap_data.get('asn', 'N/A')}",
            f"CIDR: {rdap_data.get('asn_cidr', 'N/A')}",
            f"Description: {description}",
            f"Country: {rdap_data.get('asn_country_code', 'N/A')}",
            f"Registry: {rdap_data.get('asn_registry', 'N/A')}",
            f"Date: {rdap_data.get('asn_date', 'N/A')}",
            f"Likely Cloud Provider: {is_cloud}"
        ]
    elif "error" in rdap_data:
        print(f"  [ASN] RDAP lookup failed: {rdap_data['error']}. Falling back to legacy WHOIS.")

    whois_data = await run_sync_whois_lookup(ip, "whois.arin.net")
    asn_line = next((l for l in whois_data.splitlines() if "origin:" in l.lower() or "originas:" in l.lower()), None)
    org_line = next((l for l in whois_data.splitlines() if "org-name:" in l.lower() or "orgname:" in l.lower()), None)

    if asn_line:
        asn = asn_line.split(":")[-1].strip().upper().replace("AS", "")
        desc = org_line.split(":")[-1].strip() if org_line else "N/A"
        is_cloud = "No"
        for keyword in CLOUD_KEYWORDS:
            if keyword in desc.upper():
                is_cloud = f"Yes ({keyword})"
                break
        return [f"ASN: AS{asn} (from legacy WHOIS)", f"Description: {desc}", f"Likely Cloud Provider: {is_cloud}"]

    return ["ASN information not found via RDAP or legacy WHOIS."]

async def make_request(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
) -> Union[Dict[str, Any], List[Any], str]:
    req_headers = {"User-Agent": get_random_user_agent()}
    if headers:
        req_headers.update(headers)

    try:
        response = await client.request(
            method, url, headers=req_headers, params=params,
            data=data, json=json_data, timeout=HTTP_TIMEOUT
        )
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError:
            return response.text
    except httpx.HTTPStatusError as e:
        error_content = e.response.text[:200] if e.response else "No response content."
        return {
            "error": f"HTTP Error {e.response.status_code} for URL: {url}",
            "status_code": e.response.status_code,
            "content": error_content
        }
    except (httpx.RequestError, httpx.TimeoutException) as e:
        return {"error": f"Request Failed for URL: {url}. Reason: {type(e).__name__} - {e}"}
    except Exception as e:
        return {"error": f"Unexpected Request Error for URL: {url}. Reason: {type(e).__name__} - {e}"}

def save_to_file(
    filename: str,
    data: Union[List[Any], Dict[str, Any], str],
    section_title: Optional[str] = "",
    output_format: str = "text"
) -> None:
    try:
        with open(filename, "a", encoding='utf-8') as f:
            if section_title:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                if output_format == "json":
                    f.write(json.dumps({"section": section_title, "timestamp": timestamp}) + "\n")
                else:
                    f.write(f"\n--- {section_title} ({timestamp}) ---\n")

            if isinstance(data, (list, tuple, set)):
                if output_format == "json":
                    for item in data:
                        f.write(json.dumps(item) + "\n")
                else:
                    for item in data:
                        f.write(str(item) + "\n")
            elif data:
                if output_format == "json":
                    f.write(json.dumps(data) + "\n")
                else:
                    f.write(str(data) + "\n")
    except IOError as e:
        print(Fore.RED + f"Error writing to file {filename}: {e}" + Style.RESET_ALL)
