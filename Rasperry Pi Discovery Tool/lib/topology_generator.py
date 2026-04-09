#!/usr/bin/env python3
"""
lib/topology_generator.py
Yeyland Wutani Network Discovery Pi

Generates a self-contained D3.js HTML topology map from network discovery
scan results. Adapted from the Network Topology Agent v4 approach, driven
by ARP/IP-scan data rather than switch MAC tables.

Without MAC tables we cannot determine per-port connections, so topology is
inferred from:
  - recon['default_gateway'] IP → root gateway node
  - hosts with category 'Network Switch' → intermediate switch nodes
  - /24 subnet proximity → device-to-switch assignment heuristic
  - category → D3 cluster type and color

Entry point:
  build_topology_html(scan_results: dict, config: dict) -> str
"""

import ipaddress
import json
from datetime import datetime

# ── Classification ─────────────────────────────────────────────────────────

# Categories that become intermediate switch nodes (not device clusters)
_NODE_CATEGORIES = {"Firewall", "Network Switch", "Network Infrastructure"}

# Map scan category → D3 cluster type
_CATEGORY_TO_CLUSTER = {
    "VoIP Phone":             "voip",
    "Wireless Access Point":  "ap",
    "Hypervisor":             "vm",
    "Virtual Machine":        "vm",
    "Windows Server":         "server",
    "Linux/Unix Server":      "server",
    "Database Server":        "server",
    "Domain Controller":      "server",
    "NAS / Storage":          "server",
    "Server":                 "server",
    "Windows Workstation":    "ep",
    "Windows Device":         "ep",
    "Apple Device":           "ep",
    "Linux/Unix Device":      "ep",
    "Raspberry Pi":           "ep",
    "Printer":                "ep",
    "UPS / Power Device":     "net",
    "IP Camera / NVR":        "net",
    "IoT Device":             "net",
    "Network Infrastructure": "net",
    "Unknown Device":         "unk",
    "Unknown":                "unk",
    "":                       "unk",
}

# Cluster display labels
_CLUSTER_LABELS = {
    "voip":   "VOIP",
    "ap":     "ACCESS PTS",
    "vm":     "VIRTUAL",
    "server": "SERVERS",
    "ep":     "ENDPOINTS",
    "net":    "NETWORK",
    "unk":    "UNKNOWN",
}

# Summary card category buckets
_SERVER_CATS = {"Windows Server", "Linux/Unix Server", "Database Server",
                "Domain Controller", "NAS / Storage", "Server", "Hypervisor"}
_ENDPOINT_CATS = {"Windows Workstation", "Windows Device", "Apple Device",
                  "Linux/Unix Device", "Raspberry Pi", "Printer", "Virtual Machine"}
_VOIP_CATS = {"VoIP Phone"}
_AP_CATS = {"Wireless Access Point"}
_SWITCH_CATS = {"Network Switch", "Network Infrastructure"}


def _classify(host: dict) -> str:
    cat = host.get("category", "")
    return _CATEGORY_TO_CLUSTER.get(cat, "unk")


def _host_label(host: dict) -> str:
    """Display label for a device in a cluster tooltip (port|host format)."""
    ip = host.get("ip", "")
    hn = (host.get("hostname") or "").strip()
    if hn and hn not in ("N/A", ""):
        hn = hn.split(".")[0]   # strip domain suffix
        return f"{ip}|{hn}"
    vendor = (host.get("vendor") or "").strip()
    if vendor and vendor != "Unknown":
        return f"{ip}|{vendor[:22]}"
    return f"{ip}|"


def _switch_display_name(host: dict) -> str:
    """Best display name for a switch node."""
    hn = (host.get("hostname") or "").strip()
    if hn and hn not in ("N/A", ""):
        return hn.split(".")[0]
    vendor = (host.get("vendor") or "").strip()
    if vendor and vendor not in ("Unknown", ""):
        short_vendor = vendor.split(",")[0].split(" Inc")[0].strip()[:20]
        return f"{short_vendor} ({host['ip']})"
    return host.get("ip", "Unknown Switch")


def _net24(ip: str) -> str:
    """Return the /24 network string for an IP (e.g. '10.0.1.0/24')."""
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except ValueError:
        return ""


def _build_clusters(device_hosts: list) -> list:
    """Group a host list into D3 cluster dicts, sorted by type."""
    by_type: dict = {}
    for h in device_hosts:
        ctype = _classify(h)
        by_type.setdefault(ctype, []).append(h)

    # Ordering: voip, ap, server, vm, ep, net, unk
    order = ["voip", "ap", "server", "vm", "ep", "net", "unk"]
    clusters = []
    for ctype in order:
        if ctype not in by_type:
            continue
        items = by_type[ctype]
        clusters.append({
            "type": ctype,
            "count": len(items),
            "devices": [_host_label(h) for h in items],
        })
    return clusters


def _distribute_devices(device_hosts: list, switches: list) -> dict:
    """
    Assign device hosts to switches using /24 subnet proximity.

    Returns dict: switch_ip → [hosts]  plus  '_gateway' → [hosts]
    for devices that don't map to any switch's /24.

    When multiple switches share the same /24, devices are round-robined
    across them.
    """
    if not switches:
        return {"_gateway": device_hosts}

    # Map /24 → [switches in that /24]
    net24_to_switches: dict = {}
    for sw in switches:
        n = _net24(sw["ip"])
        if n:
            net24_to_switches.setdefault(n, []).append(sw)

    # Round-robin counters per /24
    rr: dict = {n: 0 for n in net24_to_switches}

    result: dict = {sw["ip"]: [] for sw in switches}
    result["_gateway"] = []

    for d in device_hosts:
        n = _net24(d["ip"])
        if n in net24_to_switches:
            sw_list = net24_to_switches[n]
            idx = rr[n] % len(sw_list)
            rr[n] += 1
            result[sw_list[idx]["ip"]].append(d)
        elif len(switches) == 1:
            # Single switch: claim all devices regardless of subnet
            result[switches[0]["ip"]].append(d)
        else:
            result["_gateway"].append(d)

    return result


def _infer_topology_tree(hosts: list, recon: dict, config: dict) -> dict:
    """Build the D3 hierarchy dict from scan data."""
    gw_ip = recon.get("default_gateway", "")
    subnets = recon.get("subnets", []) or []
    pub_info = recon.get("public_ip_info", {}) or {}
    pub_ip = pub_info.get("public_ip", "") or ""
    isp = pub_info.get("isp", "")

    # --- Identify gateway host ---
    gw_host = next((h for h in hosts if h.get("ip") == gw_ip), None)

    gw_name = "Gateway"
    gw_type = "firewall"
    if gw_host:
        cat = gw_host.get("category", "")
        vendor = (gw_host.get("vendor") or "").strip()
        hn = (gw_host.get("hostname") or "").strip()
        if hn and hn not in ("N/A", ""):
            gw_name = hn.split(".")[0]
        elif vendor and vendor not in ("Unknown", ""):
            gw_name = vendor.split(",")[0].split(" Inc")[0].strip()[:28]
        if cat == "Firewall":
            gw_type = "firewall"
        elif cat in ("Network Infrastructure", "Network Switch"):
            gw_type = "core"

    # --- Partition hosts ---
    switch_hosts = [
        h for h in hosts
        if h.get("ip") != gw_ip
        and h.get("category") in ("Network Switch", "Network Infrastructure")
    ]
    device_hosts = [
        h for h in hosts
        if h.get("ip") != gw_ip
        and h.get("category") not in _NODE_CATEGORIES
    ]

    # --- Determine switch display types ---
    # Lowest-IP switch = core, others = access (crude but reasonable without topology data)
    sorted_switches = sorted(switch_hosts, key=lambda h: _ip_sort_key(h.get("ip", "")))
    for i, sw in enumerate(sorted_switches):
        sw["_node_type"] = "core" if i == 0 and len(sorted_switches) > 1 else "access"

    # --- Distribute devices to switches ---
    device_map = _distribute_devices(device_hosts, sorted_switches)

    # --- Build switch subtree nodes ---
    switch_nodes = []
    for sw in sorted_switches:
        sw_ip = sw.get("ip", "")
        sw_devices = device_map.get(sw_ip, [])
        sw_node = {
            "name": _switch_display_name(sw),
            "type": sw.get("_node_type", "access"),
            "ip": sw_ip,
            "clusters": _build_clusters(sw_devices),
            "children": [],
        }
        switch_nodes.append(sw_node)

    # Devices not claimed by any switch → go directly under gateway
    gateway_devices = device_map.get("_gateway", [])

    # --- Build gateway node ---
    gw_node = {
        "name": gw_name,
        "type": gw_type,
        "ip": gw_ip,
        "clusters": _build_clusters(gateway_devices),
        "children": switch_nodes,
    }

    # --- Build Internet root node ---
    internet_label = f"Internet ({isp})" if isp else "Internet"
    return {
        "name": internet_label,
        "type": "internet",
        "ip": pub_ip,
        "children": [gw_node],
    }


def _ip_sort_key(ip: str):
    """Sortable tuple for an IPv4 string."""
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (255, 255, 255, 255)


def _build_summary_cards(hosts: list, scan_results: dict) -> str:
    """Return HTML string for the .cards div contents."""
    total = len(hosts)
    switches = sum(1 for h in hosts if h.get("category") in _SWITCH_CATS)
    aps = sum(1 for h in hosts if h.get("category") in _AP_CATS)
    voip = sum(1 for h in hosts if h.get("category") in _VOIP_CATS)
    servers = sum(1 for h in hosts if h.get("category") in _SERVER_CATS)
    endpoints = sum(1 for h in hosts if h.get("category") in _ENDPOINT_CATS)
    unknown = sum(1 for h in hosts if h.get("category") in ("Unknown Device", "Unknown", ""))

    subnets_scanned = scan_results.get("summary", {}).get("subnets_scanned", [])
    subnet_count = len(subnets_scanned)

    cards = [
        (total,    "Total Hosts"),
        (switches, "Switches"),
        (subnet_count, "Subnets"),
        (voip,     "VoIP Phones"),
        (aps,      "Access Points"),
        (servers,  "Servers"),
        (endpoints,"Endpoints"),
        (unknown,  "Unknown"),
    ]

    html_parts = []
    for num, label in cards:
        html_parts.append(
            f'<div class="card"><div class="num">{num}</div>'
            f'<div class="lbl">{label}</div></div>'
        )
    return "\n".join(html_parts)


# ── HTML Template ──────────────────────────────────────────────────────────

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{SITE} &mdash; Network Topology</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f9;color:#222;font-size:14px}
header{background:linear-gradient(135deg,#0f3460,#1a4a7a);color:#fff;padding:20px 24px}
.hi{display:flex;align-items:center;gap:16px}
.ht h1{font-size:22px;font-weight:700;margin:0}
.ht p{font-size:13px;opacity:.8;margin-top:4px}
.main{max-width:1800px;margin:0 auto;padding:24px 16px}
h2{font-size:18px;color:#1a1a2e;border-left:4px solid #0f3460;padding-left:10px;margin:28px 0 14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.card{background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.08)}
.num{font-size:28px;font-weight:700;color:#0f3460}
.lbl{font-size:12px;color:#666;margin-top:4px}
#topo-wrap{background:#0f172a;border-radius:8px;overflow:auto;margin-bottom:16px}
.svg-key{display:flex;flex-wrap:wrap;gap:16px;margin-top:10px;font-size:12px;color:#555}
.svg-key span{display:flex;align-items:center;gap:6px}
.svg-key i{display:inline-block;width:12px;height:12px;border-radius:2px;flex-shrink:0}
.svg-key .circle{border-radius:50%}
#modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
#modal-overlay.open{display:flex}
#modal-box{background:#1e293b;border-radius:10px;padding:0;min-width:360px;max-width:600px;max-height:80vh;overflow:hidden;display:flex;flex-direction:column}
#modal-header{background:#0f172a;padding:14px 18px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #334155}
#modal-title{color:#e2e8f0;font-weight:700;font-size:14px}
#modal-close{background:none;border:none;color:#94a3b8;cursor:pointer;font-size:20px}
#modal-body{overflow-y:auto;padding:4px 0;max-height:60vh}
#modal-body table{width:100%;border-collapse:collapse;font-size:13px}
#modal-body th{text-align:left;padding:6px 12px;color:#94a3b8;border-bottom:1px solid #334155}
#modal-body td{padding:6px 12px;border-bottom:1px solid #1e293b;color:#e2e8f0}
#modal-body td:first-child{color:#67e8f9;font-family:monospace}
.note{font-size:12px;color:#94a3b8;margin-top:6px;font-style:italic}
footer{background:#1a1a2e;color:#aab;text-align:center;padding:16px;font-size:12px;margin-top:32px}
</style>
</head>
<body>
<header>
  <div class="hi">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 86 86" width="44" height="44" style="flex-shrink:0">
      <path d="M0,0h86v86H0V0z" fill="#00A0D9"/>
      <path d="M59,21.1c0,0,6.5,4.4,6.3,10.3c0,0,0.4,7.6-11.9,12.7c0,0,19,6.9,25.5-7.9c0,0,5.7-16.8-11-18.3c0,0-3.2-0.4-7.8,1.5l-2-0.6C34.4,13,27.5,41,27.5,41C20.3,65,6.2,66.9,6.2,66.9c11.6,3.1,18.1,0.7,18.1,0.7C41.1,63.1,44.1,41,44.1,41c2.6-13.5,11.3-18.1,11.3-18.1S58.3,21,59,21.1z" fill="#FFFFFF"/>
    </svg>
    <div class="ht">
      <h1>{SITE} &mdash; Network Topology</h1>
      <p>{SOURCES} | Generated: {TIMESTAMP}</p>
    </div>
  </div>
</header>
<div class="main">
<section id="summary">
<h2>Summary</h2>
<div class="cards">
{SUMMARY_CARDS}
</div>
</section>
<section id="topology">
<h2>Topology Map <small style="font-weight:400;font-size:13px;color:#64748b;margin-left:8px">Click any bubble to inspect devices</small></h2>
<p class="note">Topology inferred from ARP/IP scan data. Switch&ndash;device links are subnet-based approximations &mdash; not physical port mappings.</p>
<br>
<div id="topo-wrap"></div>
<div class="svg-key">
  <span><i style="background:#374151"></i>Infrastructure</span>
  <span><i style="background:#0e7490"></i>Core Switch</span>
  <span><i style="background:#06b6d4"></i>Access Switch</span>
  <span><i class="circle" style="background:#16a34a"></i>VoIP</span>
  <span><i class="circle" style="background:#0891b2"></i>Access Points</span>
  <span><i class="circle" style="background:#0369a1"></i>Servers</span>
  <span><i class="circle" style="background:#6366f1"></i>Virtual</span>
  <span><i class="circle" style="background:#2563eb"></i>Endpoints</span>
  <span><i class="circle" style="background:#7c3aed"></i>Network</span>
  <span><i class="circle" style="background:#6b7280"></i>Unknown</span>
</div>
</section>
</div>
<div id="modal-overlay">
  <div id="modal-box">
    <div id="modal-header">
      <span id="modal-title">Devices</span>
      <button id="modal-close">&times;</button>
    </div>
    <div id="modal-body"></div>
  </div>
</div>
<footer>Generated: {TIMESTAMP} | {SITE} Network Topology</footer>

<script>
const topoData = {TOPO_JSON};

const clusterColors = {
  voip:'#16a34a',ap:'#0891b2',server:'#0369a1',vm:'#6366f1',
  ep:'#2563eb',net:'#7c3aed',unk:'#6b7280'
};
const nodeColors = {
  internet:'#374151',firewall:'#374151',core:'#0e7490',
  distribution:'#0891b2',access:'#06b6d4'
};

const wrap = document.getElementById('topo-wrap');
const root = d3.hierarchy(topoData);
const leafCount = root.leaves().length;
const treeDepth = root.height;

const treeLayout = d3.tree()
  .nodeSize([200, 185])
  .separation((a,b) => {
    const aClusters = (a.data.clusters||[]).length;
    const bClusters = (b.data.clusters||[]).length;
    const clusterExtra = Math.max(aClusters, bClusters) * 0.25;
    return (a.parent===b.parent ? 1.1 : 1.5) + clusterExtra;
  });
treeLayout(root);

let minX=Infinity,maxX=-Infinity,minY=Infinity,maxY=-Infinity;
root.each(d=>{minX=Math.min(minX,d.x);maxX=Math.max(maxX,d.x);minY=Math.min(minY,d.y);maxY=Math.max(maxY,d.y);});

const clusterPad = 220;
const svgW = Math.max(1400, leafCount*200, maxX-minX+clusterPad*2);
const svgH = Math.max(900, (treeDepth+2)*175, maxY-minY+380);
const offsetX = -minX + clusterPad;
const offsetY = -minY + 60;

const svg = d3.select('#topo-wrap').append('svg')
  .attr('width',svgW).attr('height',svgH)
  .style('background','#0f172a').style('display','block');
const g = svg.append('g').attr('transform',`translate(${offsetX},${offsetY})`);

// EMIT ORDER: 1) lines, 2) rects, 3) clusters, 4) text

// 1a. Switch-to-switch lines
g.selectAll('.sw-link')
  .data(root.links())
  .join('line').attr('class','sw-link')
  .attr('x1',d=>d.source.x).attr('y1',d=>d.source.y+23)
  .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y-23)
  .attr('stroke','#4b5563').attr('stroke-width',2);

// 1b. Port labels on switch links (20% and 80% positions)
root.links().forEach(l=>{
  const x1=l.source.x,y1=l.source.y+23,x2=l.target.x,y2=l.target.y-23;
  if(l.target.data.port_from_parent){
    g.append('text').attr('x',x1+0.2*(x2-x1)).attr('y',y1+0.2*(y2-y1)-6)
      .attr('text-anchor','middle').attr('font-size','9').attr('fill','#64748b')
      .text(l.target.data.port_from_parent);
  }
  if(l.target.data.port_to_parent){
    g.append('text').attr('x',x1+0.8*(x2-x1)).attr('y',y1+0.8*(y2-y1)-6)
      .attr('text-anchor','middle').attr('font-size','9').attr('fill','#64748b')
      .text(l.target.data.port_to_parent);
  }
});

// 1c. Cluster connector lines
root.descendants().forEach(d=>{
  if(!d.data.clusters||!d.data.clusters.length) return;
  const hasChildren = d.children && d.children.length;
  const total = d.data.clusters.length;
  const nodeW = Math.max(200, (d.data.name||'').length*7+24);

  d.data.clusters.forEach((cl,i)=>{
    let cx,cy;
    if(hasChildren){
      cx = d.x + nodeW/2 + 36 + i*64;
      cy = d.y;
      g.append('line')
        .attr('x1',d.x+nodeW/2).attr('y1',d.y)
        .attr('x2',cx-28).attr('y2',cy)
        .attr('stroke','#334155').attr('stroke-width',1.5).attr('stroke-dasharray','5,4');
    } else {
      cx = d.x - (total*64/2) + i*64 + 32;
      cy = d.y + 110;
      g.append('line')
        .attr('x1',d.x).attr('y1',d.y+23)
        .attr('x2',cx).attr('y2',cy-28)
        .attr('stroke','#334155').attr('stroke-width',1.5).attr('stroke-dasharray','5,4');
    }
    cl._cx = cx; cl._cy = cy;
  });
});

// 2. Switch rects
root.descendants().forEach(d=>{
  const nodeW = Math.max(200, (d.data.name||'').length*7+24);
  g.append('rect')
    .attr('x',d.x-nodeW/2).attr('y',d.y-23).attr('width',nodeW).attr('height',46).attr('rx',6)
    .attr('fill',nodeColors[d.data.type]||'#374151')
    .attr('stroke','#1e3a4a').attr('stroke-width',1.5);
});

// 3. Cluster circles
root.descendants().forEach(d=>{
  if(!d.data.clusters||!d.data.clusters.length) return;
  d.data.clusters.forEach(cl=>{
    if(cl._cx===undefined) return;
    const circle = g.append('circle')
      .attr('cx',cl._cx).attr('cy',cl._cy).attr('r',28)
      .attr('fill',clusterColors[cl.type]||'#6b7280')
      .attr('opacity',0.92).attr('stroke','#1e293b').attr('stroke-width',1.5)
      .style('cursor','pointer');
    circle.on('click',()=>{
      const label = cl.type.toUpperCase().replace('-',' ');
      document.getElementById('modal-title').textContent=`${label} Devices (${cl.count})`;
      const rows=(cl.devices||[]).map(dev=>{
        const[port,...rest]=dev.split('|');
        return`<tr><td>${port}</td><td>${rest.join('|')}</td></tr>`;
      }).join('');
      document.getElementById('modal-body').innerHTML=
        `<table><tr><th>IP</th><th>Hostname / Vendor</th></tr>${rows}</table>`;
      document.getElementById('modal-overlay').classList.add('open');
    });
  });
});

// 4. All text labels (rendered last — always on top)
root.descendants().forEach(d=>{
  g.append('text').attr('x',d.x).attr('y',d.y-5)
    .attr('text-anchor','middle').attr('font-size','11').attr('fill','#fff').attr('font-weight','700')
    .attr('pointer-events','none').text(d.data.name||'');
  g.append('text').attr('x',d.x).attr('y',d.y+11)
    .attr('text-anchor','middle').attr('font-size','10').attr('fill','#cbd5e1')
    .attr('pointer-events','none').text(d.data.ip||'');
});

root.descendants().forEach(d=>{
  if(!d.data.clusters||!d.data.clusters.length) return;
  d.data.clusters.forEach(cl=>{
    if(cl._cx===undefined) return;
    g.append('text').attr('x',cl._cx).attr('y',cl._cy+5)
      .attr('text-anchor','middle').attr('font-size','13').attr('fill','#fff').attr('font-weight','700')
      .attr('pointer-events','none').text(cl.count);
    g.append('text').attr('x',cl._cx).attr('y',cl._cy+46)
      .attr('text-anchor','middle').attr('font-size','10').attr('fill','#94a3b8')
      .attr('pointer-events','none').text(cl.type.toUpperCase().replace('-',' '));
  });
});

document.getElementById('modal-close').onclick=()=>
  document.getElementById('modal-overlay').classList.remove('open');
document.getElementById('modal-overlay').onclick=e=>{
  if(e.target===document.getElementById('modal-overlay'))
    document.getElementById('modal-overlay').classList.remove('open');
};

// Auto-center the diagram horizontally on load
requestAnimationFrame(()=>{
  const wrapEl=document.getElementById('topo-wrap');
  // Center on the midpoint of the D3 node spread (plus clusterPad offset)
  const treeMidX = (minX + maxX) / 2 + offsetX;
  wrapEl.scrollLeft = Math.max(0, treeMidX - wrapEl.clientWidth / 2);
});
</script>
</body>
</html>"""


# ── Main entry point ───────────────────────────────────────────────────────

def build_topology_html(scan_results: dict, config: dict) -> str:
    """
    Generate a self-contained D3.js HTML topology map from scan results.

    Args:
        scan_results: Full scan results dict from network-scanner.py
        config:       config.json dict

    Returns:
        HTML string (self-contained, no external dependencies except D3 CDN)
    """
    hosts = scan_results.get("hosts", [])
    recon = scan_results.get("reconnaissance", {}) or {}
    rep_cfg = config.get("reporting", {})

    # Site/client name
    site = rep_cfg.get("client_name", "").strip()
    if not site:
        # Try to infer from DHCP domain or OSINT WHOIS
        dhcp = scan_results.get("dhcp_analysis", {}) or {}
        domain = dhcp.get("domain", "") or ""
        if domain:
            site = domain.rstrip(".").split(".")[0].replace("-", " ").title()
    if not site:
        osint = scan_results.get("osint", {}) or {}
        whois_owner = osint.get("whois_owner", "") or ""
        if whois_owner:
            site = whois_owner[:40]
    if not site:
        site = "Network Assessment"

    # Sources line
    scan_ts = scan_results.get("scan_start", scan_results.get("timestamp", ""))
    if scan_ts:
        try:
            dt = datetime.fromisoformat(scan_ts[:19])
            scan_date = dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            scan_date = scan_ts[:16]
        sources = f"Scan: {scan_date}"
    else:
        sources = "Network Discovery Scan"

    total = len(hosts)
    subnets = recon.get("subnets", []) or []
    subnet_str = ", ".join(subnets) if subnets else "unknown"
    sources = f"{total} hosts · {subnet_str}"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Build tree and cards
    topo_tree = _infer_topology_tree(hosts, recon, config)
    topo_json = json.dumps(topo_tree, indent=2)
    summary_cards = _build_summary_cards(hosts, scan_results)

    html = _HTML_TEMPLATE
    html = html.replace("{SITE}", _html_escape(site))
    html = html.replace("{SOURCES}", _html_escape(sources))
    html = html.replace("{TIMESTAMP}", timestamp)
    html = html.replace("{SUMMARY_CARDS}", summary_cards)
    html = html.replace("{TOPO_JSON}", topo_json)

    return html


def _html_escape(s: str) -> str:
    return (s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
