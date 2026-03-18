"""
ad_discovery.py — Credentialed Active Directory enrichment via YW Discovery Proxy.

Phase 24 of the YW network scanner.

The SE runs YW-DiscoveryProxy.ps1 on a Domain Controller as Domain Admin before
the scan starts.  That script writes a self-expiring DNS TXT record:

    _yw-discovery.<domain>   TXT   "ywp-v1|token=<TOKEN>|port=<PORT>"

The Pi finds this record automatically (no manual key entry) and queries:

    /computers       All AD computer objects (name, OS, OU, last logon, …)
    /users           All AD user objects (name, email, title, groups, …)
    /groups          Privileged group memberships (Domain Admins, etc.)
    /password-policy Domain password and lockout policy
    /dhcp            Full DHCP lease table  (IP ↔ hostname ground truth)
    /dns             DNS zone records
    /gpos            Group Policy objects
    /hardware        CIM hardware inventory per server
                     (CPU, RAM, disks, serial number, NIC, BIOS, uptime)
    /domain          Domain & forest info (functional level, DC list, sites, FSMO roles)
    /trusts          AD trust relationships
    /services        Non-standard auto-start services on servers
    /shares          SMB shares per server
    /local-admins    Local Administrators group per server
    /bitlocker       BitLocker encryption status per server
    /done            Signal proxy to shut down cleanly

merge_ad_into_hosts() then enriches every device in the Pi's hosts list with:
    - Authoritative hostname (from AD computer name or DHCP)
    - Exact OS string
    - Organisational Unit (OU)
    - Last logon date
    - Server hardware details (model, CPU, RAM, disks, serial)
    - Whether the computer account is enabled / stale

scan_results["ad_enrichment"] receives a summary with security findings:
    stale accounts, excessive Domain Admins, weak password policy, Kerberoastable
    service accounts, accounts with non-expiring passwords, etc.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

_PROXY_PORT_DEFAULT = 8734
_TXT_LABEL          = "_yw-discovery"

# ── Domain / DC discovery ──────────────────────────────────────────────────────

def _domain_candidates(recon: dict, dhcp_results: dict) -> list[str]:
    """
    Collect candidate AD domain names from scan data.
    Includes internal .local / .lan domains (common in AD environments).
    """
    seen   = set()
    result = []

    def _add(d: str) -> None:
        d = d.strip().lower().rstrip(".")
        if d and d not in seen and len(d) > 3:
            seen.add(d)
            result.append(d)

    # DHCP domain name is the most direct indicator of the AD domain
    for srv in (dhcp_results or {}).get("dhcp_servers", []):
        dn = (srv.get("domain_name") or "").strip()
        if dn:
            _add(dn)

    # Recon DNS search domains
    for key in ("search_domain", "domain", "dns_domain"):
        _add(recon.get(key, ""))

    # /etc/resolv.conf search / domain lines (Pi's own resolver config)
    try:
        with open("/etc/resolv.conf", "r") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(("search ", "domain ")):
                    for tok in line.split()[1:]:
                        _add(tok)
    except Exception:
        pass

    return result


def _find_dc_ips(hosts: list) -> list[str]:
    """
    Identify domain controller IPs from the hosts list.
    Kerberos (88) + LDAP (389) together is the definitive DC signature.
    Also accept LDAP + DNS (53) as a secondary heuristic.
    """
    dcs = []
    for host in hosts:
        ip = host.get("ip")
        if not ip:
            continue

        # Strong signal: Phase 4 already confirmed this is a DC via LDAP probe
        if host.get("is_domain_controller"):
            if ip not in dcs:
                dcs.append(ip)
            continue

        # open_ports is a flat list[int] in the scanner (not a list of dicts)
        open_ports = set(host.get("open_ports", []))
        if (88 in open_ports and 389 in open_ports) or \
           (389 in open_ports and 53 in open_ports and 636 in open_ports) or \
           (389 in open_ports and 445 in open_ports and 135 in open_ports):
            dcs.append(ip)

    # Fallback: Phase 4 may have probed LDAP outside the nmap port list,
    # so 389 never appears in open_ports.  Quick TCP probe on all remaining
    # hosts to catch DCs the port list missed.
    if not dcs:
        checked = set()
        for host in hosts:
            ip = host.get("ip", "")
            if not ip or ip in checked:
                continue
            checked.add(ip)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((ip, 389)) == 0:
                    logger.debug(f"[Phase 24] TCP fallback: port 389 open on {ip}")
                    dcs.append(ip)
                s.close()
            except Exception:
                pass

    return dcs


def _query_txt(dc_ip: str, domain: str) -> Optional[str]:
    """
    Query _yw-discovery.<domain> TXT from dc_ip's DNS server.
    Returns the raw TXT string if found, else None.
    """
    record = f"{_TXT_LABEL}.{domain}"
    # Fully-qualified with trailing dot so resolvers don't append search domains
    record_fqdn = f"{record}."

    # dnspython targeting the DC directly (most reliable)
    try:
        import dns.resolver  # type: ignore
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [dc_ip]
        res.timeout     = 5
        res.lifetime    = 8
        try:
            for rdata in res.resolve(record_fqdn, "TXT"):
                for chunk in rdata.strings:
                    txt = chunk.decode("utf-8", errors="ignore")
                    if txt.startswith("ywp-v1|"):
                        logger.info(f"[Phase 24]   dnspython targeted: found TXT at {record} via {dc_ip}")
                        return txt
        except Exception as e:
            logger.debug(f"[Phase 24]   dnspython targeted {dc_ip} for {record}: {e}")

        # Also try without trailing dot in case zone delegation differs
        try:
            for rdata in res.resolve(record, "TXT"):
                for chunk in rdata.strings:
                    txt = chunk.decode("utf-8", errors="ignore")
                    if txt.startswith("ywp-v1|"):
                        logger.info(f"[Phase 24]   dnspython targeted (no dot): found TXT at {record} via {dc_ip}")
                        return txt
        except Exception:
            pass
    except ImportError:
        logger.debug("[Phase 24]   dnspython not available")

    # dnspython using system resolver (Pi may already use DC as its DNS)
    try:
        import dns.resolver  # type: ignore
        sys_res = dns.resolver.Resolver(configure=True)
        sys_res.timeout  = 5
        sys_res.lifetime = 8
        try:
            for rdata in sys_res.resolve(record_fqdn, "TXT"):
                for chunk in rdata.strings:
                    txt = chunk.decode("utf-8", errors="ignore")
                    if txt.startswith("ywp-v1|"):
                        logger.info(f"[Phase 24]   dnspython system resolver: found TXT at {record}")
                        return txt
        except Exception as e:
            logger.debug(f"[Phase 24]   dnspython system resolver for {record}: {e}")
    except Exception:
        pass

    # Fallback: dig (more reliable output format than nslookup on Linux)
    try:
        import subprocess
        r = subprocess.run(
            ["dig", f"@{dc_ip}", record, "TXT", "+short", "+timeout=5", "+tries=2"],
            capture_output=True, text=True, timeout=12,
        )
        for line in r.stdout.splitlines():
            m = re.search(r'ywp-v1\|[^\s"]+', line)
            if m:
                logger.info(f"[Phase 24]   dig: found TXT at {record} via {dc_ip}")
                return m.group(0)
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug(f"[Phase 24]   dig fallback failed: {e}")

    # Fallback: nslookup
    try:
        import subprocess
        r = subprocess.run(
            ["nslookup", "-type=TXT", record, dc_ip],
            capture_output=True, text=True, timeout=8,
        )
        combined = r.stdout + "\n" + r.stderr
        for line in combined.splitlines():
            m = re.search(r'ywp-v1\|[^\s"]+', line)
            if m:
                logger.info(f"[Phase 24]   nslookup: found TXT at {record} via {dc_ip}")
                return m.group(0)
    except Exception as e:
        logger.debug(f"[Phase 24]   nslookup fallback failed: {e}")

    logger.info(f"[Phase 24]   TXT not found at {_TXT_LABEL}.{domain} via {dc_ip}")
    return None


def _parse_txt(txt: str) -> Optional[tuple[str, int]]:
    """Parse 'ywp-v1|token=TOKEN|port=PORT' → (token, port)."""
    parts = dict(seg.split("=", 1) for seg in txt.split("|") if "=" in seg)
    token = parts.get("token", "")
    try:
        port = int(parts.get("port", _PROXY_PORT_DEFAULT))
    except ValueError:
        port = _PROXY_PORT_DEFAULT
    return (token, port) if token else None


def _get_domain_via_ldap_rootdse(dc_ip: str) -> Optional[str]:
    """
    Anonymous LDAP rootDSE query to get defaultNamingContext → domain name.
    Fallback when DHCP domain is unavailable.
    Uses ldap3 (already in requirements.txt).
    """
    try:
        from ldap3 import Server, Connection, ALL, ANONYMOUS  # type: ignore
        srv = Server(dc_ip, port=389, use_ssl=False, get_info=ALL, connect_timeout=4)
        conn = Connection(srv, authentication=ANONYMOUS)
        if conn.bind():
            dnc = srv.info.other.get("defaultNamingContext", [""])
            if isinstance(dnc, list):
                dnc = dnc[0] if dnc else ""
            # "DC=contoso,DC=local" → "contoso.local"
            parts = re.findall(r"DC=([^,]+)", str(dnc), re.IGNORECASE)
            if parts:
                return ".".join(parts).lower()
    except Exception:
        pass
    return None


# ── Proxy location ─────────────────────────────────────────────────────────────

def find_ad_proxy(
    hosts: list,
    recon: dict,
    dhcp_results: dict,
    config: dict,
) -> Optional[tuple[str, int, str]]:
    """
    Scan DC candidates for a live YW Discovery Proxy.
    Returns (dc_ip, port, token) or None.
    """
    dc_ips = _find_dc_ips(hosts)

    # Also pull DCs that Phase 4 already identified (may have used its own
    # detection logic with a different port requirement).
    for key in ("dc_ip", "domain_controller", "ldap_dc_ip"):
        recon_dc = (recon or {}).get(key, "")
        if recon_dc and recon_dc not in dc_ips:
            logger.debug(f"[Phase 24] Adding recon-discovered DC {recon_dc} (from recon['{key}'])")
            dc_ips.append(recon_dc)

    # Phase 4 may store a list of DCs
    for dc_entry in (recon or {}).get("domain_controllers", []):
        ip = dc_entry if isinstance(dc_entry, str) else dc_entry.get("ip", "")
        if ip and ip not in dc_ips:
            logger.debug(f"[Phase 24] Adding recon-discovered DC {ip} (from recon['domain_controllers'])")
            dc_ips.append(ip)

    # When the Pi uses the DC as its DNS resolver (common AD setup), port scanning
    # may miss Kerberos/LDAP ports due to Windows firewall rules.  Add any internal
    # DNS server IPs as fallback DC candidates — if no proxy TXT is found there the
    # loop simply continues.
    for dns_ip in (recon or {}).get("dns_servers", []):
        if dns_ip and dns_ip not in dc_ips:
            try:
                if ipaddress.ip_address(dns_ip).is_private:
                    logger.debug(
                        f"[Phase 24] Adding internal DNS server {dns_ip} as fallback DC candidate"
                    )
                    dc_ips.append(dns_ip)
            except ValueError:
                pass

    if not dc_ips:
        logger.debug("[Phase 24] No DC candidates found in hosts or recon data.")
        return None

    domains = _domain_candidates(recon, dhcp_results)
    logger.info(
        f"[Phase 24] Checking {len(dc_ips)} DC candidate(s) for YW proxy.  "
        f"Domains to try: {domains or '(will query rootDSE)'}"
    )

    for dc_ip in dc_ips:
        # Build domain list for this DC: known domains PLUS rootDSE
        # Always try rootDSE — DHCP/recon domains may not match the zone
        # where the TXT record was actually created.
        dc_domains = list(domains)
        rdse_domain = _get_domain_via_ldap_rootdse(dc_ip)
        if rdse_domain:
            logger.debug(f"[Phase 24]   rootDSE on {dc_ip} → {rdse_domain}")
            if rdse_domain not in dc_domains:
                dc_domains.insert(0, rdse_domain)   # highest confidence → first

        if not dc_domains:
            logger.debug(f"[Phase 24]   {dc_ip}: no domain candidates at all, skipping")
            continue

        logger.debug(f"[Phase 24]   {dc_ip}: trying domains {dc_domains}")

        for domain in dc_domains:
            logger.info(f"[Phase 24]   Trying {dc_ip} × domain '{domain}' ...")
            txt = _query_txt(dc_ip, domain)
            if not txt:
                logger.debug(f"[Phase 24]   {dc_ip}: no TXT at {_TXT_LABEL}.{domain}")
                continue

            parsed = _parse_txt(txt)
            if not parsed:
                logger.warning(f"[Phase 24]   {dc_ip}: malformed TXT: {txt}")
                continue

            token, port = parsed

            # Confirm proxy is alive
            try:
                import requests as _req  # type: ignore
                resp = _req.get(
                    f"http://{dc_ip}:{port}/ping",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30,
                )
                if resp.status_code == 200:
                    info = resp.json()
                    logger.info(
                        f"[Phase 24]   Proxy confirmed at {dc_ip}:{port}  "
                        f"domain={info.get('domain_name','?')}  "
                        f"DCs={info.get('domain_controller_count','?')}"
                    )
                    return dc_ip, port, token
                else:
                    logger.debug(
                        f"[Phase 24]   {dc_ip}:{port} ping returned HTTP {resp.status_code}"
                    )
            except Exception as e:
                logger.info(f"[Phase 24]   {dc_ip}:{port} /ping failed: {e}")

    logger.info(
        f"[Phase 24] Exhausted all {len(dc_ips)} DC(s) × domain combinations — "
        f"no proxy found.  DC IPs tried: {dc_ips}"
    )
    return None


# ── Proxy queries ──────────────────────────────────────────────────────────────

def _get(dc_ip: str, port: int, token: str,
         endpoint: str, timeout: int = 120) -> Optional[dict | list]:
    """Authenticated GET to a proxy endpoint.

    Uses a 5-second connect timeout separate from the per-endpoint read
    timeout so a hung proxy doesn't block the full timeout on each of the
    8 sequential queries (which could total 11+ minutes).
    """
    try:
        import requests as _req  # type: ignore
        resp = _req.get(
            f"http://{dc_ip}:{port}{endpoint}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=(5, timeout),   # (connect_timeout, read_timeout)
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning(f"[Phase 24] {endpoint} → HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"[Phase 24] {endpoint} failed: {e}")
    return None


def _signal_done(dc_ip: str, port: int, token: str) -> None:
    """Tell the proxy the scan is complete so it can clean up and exit."""
    try:
        import requests as _req  # type: ignore
        resp = _req.post(
            f"http://{dc_ip}:{port}/done",
            headers={"Authorization": f"Bearer {token}"},
            timeout=8,
        )
        logger.info(f"[Phase 24] Proxy signaled /done — HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"[Phase 24] Failed to signal /done to proxy at {dc_ip}:{port}: {e}")


# ── Server identification ──────────────────────────────────────────────────────

def _identify_server_names(computers: list, hosts: list) -> list[str]:
    """
    Return short AD computer names that are likely servers.
    Sources: AD OperatingSystem field + Pi's own port-based server detection.
    """
    server_names: set[str] = set()

    # From AD: OS contains "Server"
    for c in computers:
        if "server" in (c.get("OperatingSystem") or "").lower():
            name = (c.get("Name") or
                    (c.get("DNSHostName") or "").split(".")[0])
            if name:
                server_names.add(name.upper())

    # From Pi's port scan: multiple server-class ports open
    server_ports = {135, 445, 3389, 5985, 5986}   # RPC, SMB, RDP, WinRM
    for host in hosts:
        open_ports = {p["port"] for p in host.get("ports", [])
                      if p.get("state") == "open"}
        if len(server_ports & open_ports) >= 3:
            hn = (host.get("hostname") or "").split(".")[0].upper()
            if hn:
                server_names.add(hn)

    return sorted(server_names)


# ── Data collection orchestration ─────────────────────────────────────────────

def collect_ad_data(dc_ip: str, port: int, token: str, hosts: list) -> dict:
    """Run all proxy endpoints and return the full collected data dict.

    Fail-fast: if /computers returns nothing the proxy has likely stalled or
    died after the initial /ping health-check.  Skip remaining queries rather
    than blocking for minutes on endpoints that will never respond.
    """

    logger.info("[Phase 24] /computers ...")
    computers_raw = _get(dc_ip, port, token, "/computers", timeout=90)
    if computers_raw is None:
        logger.warning(
            "[Phase 24] /computers returned no data — proxy appears to have stalled. "
            "Skipping remaining AD queries and signalling /done."
        )
        _signal_done(dc_ip, port, token)
        return {
            "computers": [], "users": [], "groups": {},
            "password_policy": {}, "dhcp": {}, "dns": {}, "gpos": {}, "hardware": {},
        }
    computers = computers_raw or []

    logger.info("[Phase 24] /users ...")
    users       = _get(dc_ip, port, token, "/users",           timeout=120) or []

    logger.info("[Phase 24] /groups ...")
    groups      = _get(dc_ip, port, token, "/groups",          timeout=30)  or {}

    logger.info("[Phase 24] /password-policy ...")
    pwd_policy  = _get(dc_ip, port, token, "/password-policy", timeout=15)  or {}

    logger.info("[Phase 24] /dhcp ...")
    dhcp        = _get(dc_ip, port, token, "/dhcp",            timeout=30)  or {}

    logger.info("[Phase 24] /dns ...")
    dns         = _get(dc_ip, port, token, "/dns",             timeout=60)  or {}

    logger.info("[Phase 24] /gpos ...")
    gpos        = _get(dc_ip, port, token, "/gpos",            timeout=15)  or {}

    logger.info("[Phase 24] /domain ...")
    domain_info = _get(dc_ip, port, token, "/domain",           timeout=20)  or {}

    logger.info("[Phase 24] /trusts ...")
    trusts      = _get(dc_ip, port, token, "/trusts",            timeout=15)  or {}

    # Per-server queries: hardware, services, shares, local-admins, bitlocker
    server_names = _identify_server_names(computers, hosts)
    hardware:     dict[str, dict] = {}
    services:     dict[str, dict] = {}
    shares:       dict[str, dict] = {}
    local_admins: dict[str, dict] = {}
    bitlocker:    dict[str, dict] = {}

    if server_names:
        targets = ",".join(server_names)
        logger.info(f"[Phase 24] /hardware for {len(server_names)} server(s): {targets}")
        hw_resp = _get(dc_ip, port, token, f"/hardware?targets={targets}", timeout=300)
        if hw_resp:
            for entry in hw_resp.get("servers", []):
                key = (entry.get("computer_name") or "").upper()
                if key:
                    hardware[key] = entry

        logger.info(f"[Phase 24] /services for {len(server_names)} server(s) ...")
        svc_resp = _get(dc_ip, port, token, f"/services?targets={targets}", timeout=120)
        if svc_resp:
            for entry in svc_resp.get("servers", []):
                key = (entry.get("computer_name") or "").upper()
                if key:
                    services[key] = entry

        logger.info(f"[Phase 24] /shares for {len(server_names)} server(s) ...")
        sh_resp = _get(dc_ip, port, token, f"/shares?targets={targets}", timeout=60)
        if sh_resp:
            for entry in sh_resp.get("servers", []):
                key = (entry.get("computer_name") or "").upper()
                if key:
                    shares[key] = entry

        logger.info(f"[Phase 24] /local-admins for {len(server_names)} server(s) ...")
        la_resp = _get(dc_ip, port, token, f"/local-admins?targets={targets}", timeout=60)
        if la_resp:
            for entry in la_resp.get("servers", []):
                key = (entry.get("computer_name") or "").upper()
                if key:
                    local_admins[key] = entry

        logger.info(f"[Phase 24] /bitlocker for {len(server_names)} server(s) ...")
        bl_resp = _get(dc_ip, port, token, f"/bitlocker?targets={targets}", timeout=60)
        if bl_resp:
            for entry in bl_resp.get("servers", []):
                key = (entry.get("computer_name") or "").upper()
                if key:
                    bitlocker[key] = entry

    _signal_done(dc_ip, port, token)

    return {
        "computers":       computers,
        "users":           users,
        "groups":          groups,
        "password_policy": pwd_policy,
        "dhcp":            dhcp,
        "dns":             dns,
        "gpos":            gpos,
        "hardware":        hardware,
        "domain_info":     domain_info,
        "trusts":          trusts,
        "services":        services,
        "shares":          shares,
        "local_admins":    local_admins,
        "bitlocker":       bitlocker,
    }


# ── Host enrichment ────────────────────────────────────────────────────────────

def _dn_to_ou(dn: str) -> str:
    """'OU=Servers,OU=Corp,DC=…' → 'Servers/Corp'"""
    parts = [p[3:] for p in dn.split(",") if p.strip().upper().startswith("OU=")]
    return "/".join(parts) if parts else ""


def merge_ad_into_hosts(hosts: list, ad_data: dict) -> None:
    """
    Enrich host dicts in-place with AD data.

    Matching priority (highest confidence first):
      1. DHCP lease table  (IP → computer short name)
      2. AD computer IPv4Address attribute
      3. Existing Pi hostname matches AD computer Name
    """
    computers = ad_data.get("computers", [])
    dhcp      = ad_data.get("dhcp",      {})
    hardware  = ad_data.get("hardware",  {})

    # Build DHCP: ip → short name
    dhcp_by_ip: dict[str, str] = {}
    if dhcp.get("available"):
        for lease in dhcp.get("leases", []):
            ip = (lease.get("ip") or "").strip()
            hn = (lease.get("hostname") or "").strip().split(".")[0].upper()
            if ip and hn:
                dhcp_by_ip[ip] = hn

    # Build AD lookups: name → object, ip → object
    ad_by_name: dict[str, dict] = {}
    ad_by_ip:   dict[str, dict] = {}
    for c in computers:
        name = (c.get("Name") or "").upper()
        if name:
            ad_by_name[name] = c
        ip4 = (c.get("IPv4Address") or "").strip()
        if ip4:
            ad_by_ip[ip4] = c

    for host in hosts:
        host_ip = host.get("ip", "")

        # Try each matching strategy in order
        ad_computer = (
            ad_by_name.get(dhcp_by_ip.get(host_ip, "")) or
            ad_by_ip.get(host_ip) or
            ad_by_name.get((host.get("hostname") or "").split(".")[0].upper())
        )

        if not ad_computer:
            continue

        short_name = ad_computer.get("Name", "")
        dns_name   = ad_computer.get("DNSHostName", "")

        # Authoritative hostname from AD
        host["hostname"] = dns_name or short_name or host.get("hostname", "")

        host["ad_computer"] = {
            "name":         short_name,
            "dns_hostname": dns_name,
            "os":           ad_computer.get("OperatingSystem", ""),
            "os_version":   ad_computer.get("OperatingSystemVersion", ""),
            "ou":           _dn_to_ou(ad_computer.get("DistinguishedName", "")),
            "description":  ad_computer.get("Description", ""),
            "enabled":      ad_computer.get("Enabled", True),
            "last_logon":   ad_computer.get("LastLogonDate", ""),
            "when_created": ad_computer.get("WhenCreated", ""),
            "spns":         ad_computer.get("ServicePrincipalNames") or [],
        }

        # Hardware from CIM proxy
        hw_key = short_name.upper()
        if hw_key in hardware:
            host["hardware"] = hardware[hw_key]

        # Upgrade OS string if Pi didn't already have one
        ad_os = ad_computer.get("OperatingSystem", "")
        if ad_os and not host.get("os"):
            host["os"] = ad_os


# ── Security analysis ──────────────────────────────────────────────────────────

def _parse_dt(value) -> Optional[datetime]:
    """Parse an AD date string to a UTC-aware datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def build_ad_summary(ad_data: dict) -> dict:
    """
    Derive counts and security findings from raw AD data.
    Returns the ad_enrichment dict that is stored in scan_results.
    """
    computers    = ad_data.get("computers",    [])
    users        = ad_data.get("users",        [])
    groups       = ad_data.get("groups",       {})
    pwd_policy   = ad_data.get("password_policy", {})
    hardware     = ad_data.get("hardware",     {})
    gpos         = ad_data.get("gpos",         {})
    domain_info  = ad_data.get("domain_info",  {})
    trusts       = ad_data.get("trusts",       {})
    services     = ad_data.get("services",     {})
    shares       = ad_data.get("shares",       {})
    local_admins = ad_data.get("local_admins", {})
    bitlocker    = ad_data.get("bitlocker",    {})

    now           = datetime.now(timezone.utc)
    stale_cutoff  = now - timedelta(days=90)

    # ── User analysis ──────────────────────────────────────────────────────────
    enabled_users     = [u for u in users if u.get("Enabled")]
    stale_users       = []
    never_logged_in   = []
    pwd_never_expires = []

    for u in enabled_users:
        ll = _parse_dt(u.get("LastLogonDate"))
        if ll:
            if ll < stale_cutoff:
                stale_users.append(u.get("SamAccountName", ""))
        else:
            never_logged_in.append(u.get("SamAccountName", ""))

        if u.get("PasswordNeverExpires"):
            pwd_never_expires.append(u.get("SamAccountName", ""))

    # ── Computer analysis ──────────────────────────────────────────────────────
    enabled_computers = [c for c in computers if c.get("Enabled", True)]
    stale_computers   = []
    server_names_list = []

    for c in enabled_computers:
        if "server" in (c.get("OperatingSystem") or "").lower():
            server_names_list.append(c.get("Name", ""))

        ll = _parse_dt(c.get("LastLogonDate"))
        if ll and ll < stale_cutoff:
            stale_computers.append(c.get("Name", ""))

    # ── Privileged accounts ────────────────────────────────────────────────────
    def _names_from_group(grp_name: str) -> list[str]:
        return [
            m.get("SamAccountName") or m.get("Name", "")
            for m in groups.get(grp_name, [])
        ]

    domain_admins    = _names_from_group("Domain Admins")
    enterprise_admins = _names_from_group("Enterprise Admins")

    # Service accounts: enabled users with SPNs (excluding krbtgt)
    service_accounts = [
        u.get("SamAccountName", "")
        for u in users
        if u.get("Enabled") and
           u.get("ServicePrincipalNames") and
           not (u.get("SamAccountName") or "").lower().startswith("krbtgt")
    ]

    # ── Security findings ──────────────────────────────────────────────────────
    findings = []

    pw_len = pwd_policy.get("min_password_length", 99)
    if isinstance(pw_len, (int, float)) and pw_len < 12:
        findings.append({
            "severity": "medium",
            "title":    "Weak password length requirement",
            "detail":   (
                f"Domain policy requires only {int(pw_len)} characters. "
                "NIST SP 800-63B recommends a minimum of 15 characters."
            ),
        })

    if not pwd_policy.get("complexity_enabled", True):
        findings.append({
            "severity": "high",
            "title":    "Password complexity not enforced",
            "detail":   "Domain password policy does not require complex passwords.",
        })

    lockout = pwd_policy.get("lockout_threshold", 0)
    if isinstance(lockout, (int, float)) and lockout == 0:
        findings.append({
            "severity": "high",
            "title":    "No account lockout policy",
            "detail":   "Accounts are never locked after failed login attempts, "
                        "enabling unlimited brute-force attempts.",
        })

    if len(domain_admins) > 5:
        findings.append({
            "severity": "medium",
            "title":    f"Excessive Domain Admin accounts ({len(domain_admins)})",
            "detail":   (
                f"{', '.join(domain_admins[:8])}"
                f"{'...' if len(domain_admins) > 8 else ''}. "
                "Best practice is ≤3 named Domain Admin accounts plus a break-glass account."
            ),
        })

    if stale_users:
        findings.append({
            "severity": "medium",
            "title":    f"{len(stale_users)} stale enabled user account(s) (inactive >90 days)",
            "detail":   (
                f"{', '.join(stale_users[:6])}"
                f"{'...' if len(stale_users) > 6 else ''}. "
                "Dormant enabled accounts extend the attack surface."
            ),
        })

    if service_accounts:
        findings.append({
            "severity": "info",
            "title":    f"{len(service_accounts)} Kerberoastable service account(s)",
            "detail":   (
                f"Accounts with registered SPNs: {', '.join(service_accounts[:5])}. "
                "Any domain user can request TGS tickets for these accounts and "
                "attempt offline password cracking."
            ),
        })

    if pwd_never_expires:
        findings.append({
            "severity": "low",
            "title":    f"{len(pwd_never_expires)} account(s) with password set to never expire",
            "detail":   (
                f"{', '.join(pwd_never_expires[:6])}"
                f"{'...' if len(pwd_never_expires) > 6 else ''}."
            ),
        })

    if stale_computers:
        findings.append({
            "severity": "low",
            "title":    f"{len(stale_computers)} stale computer account(s) (inactive >90 days)",
            "detail":   (
                f"{', '.join(stale_computers[:6])}"
                f"{'...' if len(stale_computers) > 6 else ''}. "
                "May indicate decommissioned machines still enabled in AD."
            ),
        })

    if never_logged_in:
        findings.append({
            "severity": "info",
            "title":    f"{len(never_logged_in)} user account(s) that have never logged in",
            "detail":   (
                f"{', '.join(never_logged_in[:6])}"
                f"{'...' if len(never_logged_in) > 6 else ''}."
            ),
        })

    # ── BitLocker findings ─────────────────────────────────────────────────────
    unencrypted_servers = []
    for srv_name, bl_entry in bitlocker.items():
        if bl_entry.get("accessible") and bl_entry.get("unencrypted_count", 0) > 0:
            unencrypted_servers.append(srv_name)
    if unencrypted_servers:
        findings.append({
            "severity": "high",
            "title":    f"{len(unencrypted_servers)} server(s) with unencrypted volume(s)",
            "detail":   (
                f"{', '.join(unencrypted_servers[:6])}"
                f"{'...' if len(unencrypted_servers) > 6 else ''}. "
                "Server drives should be encrypted with BitLocker to protect data at rest."
            ),
        })

    # ── Unusual local admin findings ───────────────────────────────────────────
    external_local_admins: list[str] = []
    for srv_name, la_entry in local_admins.items():
        if not la_entry.get("accessible"):
            continue
        for m in la_entry.get("members", []):
            src = (m.get("principal_source") or "").lower()
            cls = (m.get("object_class") or "").lower()
            nm  = (m.get("name") or "")
            # Flag local accounts and domain accounts that aren't built-in Admin
            if src == "local" and "administrator" not in nm.lower():
                external_local_admins.append(f"{srv_name}\\{nm}")
    if external_local_admins:
        findings.append({
            "severity": "medium",
            "title":    f"{len(external_local_admins)} unexpected local admin account(s) on server(s)",
            "detail":   (
                f"{', '.join(external_local_admins[:6])}"
                f"{'...' if len(external_local_admins) > 6 else ''}. "
                "Non-standard local admin accounts increase lateral movement risk."
            ),
        })

    # ── Trust findings ─────────────────────────────────────────────────────────
    trust_list = trusts.get("trusts", []) if isinstance(trusts, dict) else []
    if trust_list:
        # Any external / non-intra-forest trust is worth flagging
        external_trusts = [t for t in trust_list if not t.get("IntraForest")]
        if external_trusts:
            trust_names = [t.get("Name", "") for t in external_trusts]
            findings.append({
                "severity": "info",
                "title":    f"{len(external_trusts)} external AD trust relationship(s)",
                "detail":   (
                    f"{', '.join(trust_names[:4])}"
                    f"{'...' if len(trust_names) > 4 else ''}. "
                    "External trusts expand the authentication boundary — review periodically."
                ),
            })

    return {
        "available":            True,
        "computer_count":       len(computers),
        "user_count":           len(users),
        "enabled_user_count":   len(enabled_users),
        "server_count":         len(server_names_list),
        "server_names":         server_names_list,
        "domain_admin_count":   len(domain_admins),
        "domain_admins":        domain_admins,
        "enterprise_admins":    enterprise_admins,
        "stale_users":          stale_users,
        "stale_computers":      stale_computers,
        "never_logged_in":      never_logged_in,
        "service_accounts":     service_accounts,
        "password_never_expires": pwd_never_expires,
        "password_policy":      pwd_policy,
        "privileged_groups":    {
            grp: [m.get("SamAccountName") or m.get("Name", "") for m in members]
            for grp, members in groups.items()
        },
        "hardware":             hardware,        # keyed by COMPUTER_NAME.upper()
        "gpos":                 gpos.get("gpos", []) if isinstance(gpos, dict) else [],
        "security_findings":    findings,
        "dhcp_leases":          (ad_data.get("dhcp") or {}).get("leases", []),
        "dns_zones":            (ad_data.get("dns")  or {}).get("zones",  []),
        "domain_info":          domain_info,
        "trusts":               trust_list,
        "services":             services,        # keyed by COMPUTER_NAME.upper()
        "shares":               shares,          # keyed by COMPUTER_NAME.upper()
        "local_admins":         local_admins,    # keyed by COMPUTER_NAME.upper()
        "bitlocker":            bitlocker,       # keyed by COMPUTER_NAME.upper()
        # Full lists for report page generation
        "computers":            computers,
        "users":                users,
    }


# ── Phase 24 orchestration ─────────────────────────────────────────────────────

def run_ad_enrichment(
    hosts:        list,
    recon:        dict,
    dhcp_results: dict,
    config:       dict,
) -> dict:
    """
    Phase 24: Credentialed Active Directory enrichment via YW Discovery Proxy.

    Mutates host records in-place (hostname, os, ad_computer, hardware fields).
    Returns ad_enrichment summary dict; returns {"available": False} if no proxy found.
    """
    proxy = find_ad_proxy(hosts, recon, dhcp_results, config)
    if proxy is None:
        logger.info("[Phase 24] No YW Discovery Proxy found — skipping AD enrichment.")
        return {"available": False}

    dc_ip, port, token = proxy

    try:
        ad_data = collect_ad_data(dc_ip, port, token, hosts)
        merge_ad_into_hosts(hosts, ad_data)
        summary = build_ad_summary(ad_data)

        logger.info(
            f"[Phase 24] AD enrichment complete — "
            f"{summary.get('computer_count', 0)} computers, "
            f"{summary.get('user_count', 0)} users, "
            f"{len(summary.get('security_findings', []))} findings, "
            f"{len(ad_data.get('hardware', {}))} hardware records"
        )
        return summary

    except Exception as e:
        logger.error(f"[Phase 24] AD enrichment failed: {e}", exc_info=True)
        return {"available": False, "error": str(e)}
