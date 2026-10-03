#!/usr/bin/env python3
"""
VPN Gate + 全球高可用节点检测流水线 
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote
import requests

for _stream in (sys.stdout, sys.stderr):
try:
_stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
pass

REPO_DIR = os.path.dirname(os.path.abspath(file))
VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
"VPNGATE_MIRROR",
"https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)

外部补充源: 专项拉取美国及全球节点

EXTRA_SOURCES = [
s.strip() for s in os.environ.get(
"EXTRA_SOURCES",
"https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt,"
"https://raw.githubusercontent.com/LonUp/v2ray-worker/main/nodes.txt"
).split(",") if s.strip()
]

WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://yu.memory44.ccwu.cc/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "45"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

精选 Cloudflare 优质入口列表

DEFAULT_EDGE = (
"auto.dolby.dpdns.org:2096,p.etime.vip:8443,securecircle.com:8443,stores.staples.com:2087,"
"cdn.sketch.com:2083,nodejs.org:443,mogas.com:2053,www.visa.com.hk:8443,investor.apple.com:8443,"
"www.speedtest.net:443,pure.coupert.com:8443,hostinger.com:8443,digitalocean.com:2087,www.epicgames.com:2087"
)
EDGE_HOSTS = [h.strip() for h in os.environ.get("EDGE_HOSTS", DEFAULT_EDGE).split(",") if h.strip()]

DATA_CENTER_KEYWORDS = [
"GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
"AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
"HURRICANE", "TENCENT", "ALIBABA", "CHOOPA", "SERVER"
]
RESIDENTIAL_KEYWORDS = [
"NTT", "KDDI", "DOCOMO", "SOFTBANK", "J:COM", "OCN", "BIGLOBE", "IIJ",
"AT&T", "COMCAST", "XFINITY", "VERIZON", "CHARTER", "SPECTRUM", "CENTURYLINK",
"FRONTIER", "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM"
]

COUNTRY_ZH = {
"JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
"RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
"GB": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港", "CN": "中国",
"AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士", "IT": "意大利",
"ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西", "MY": "马来西亚",
}

_section = None

def log(section, msg=""):
global _section
if section != _section:
print(f"========== {section} ==========")
_section = section
if msg:
print(msg, flush=True)

def die(msg):
log("FATAL", f"[失败] {msg}")
sys.exit(1)

def parse_csv(text):
lines = [ln for ln in text.splitlines() if ln.strip()]
header_idx = next((i for i, ln in enumerate(lines) if ln.lstrip("#").startswith("HostName")), None)
if header_idx is None:
return []
header = [h.strip().lstrip("*").lower() for h in lines[header_idx].lstrip("#").split(",")]
idx = {col: header.index(col) for col in ("hostname", "ip", "countrylong", "countryshort") if col in header}
b64_idx = next((i for i, h in enumerate(header) if "base64" in h), len(header) - 1)

pos = {
    "h": idx.get("hostname", 0), "ip": idx.get("ip", 1),
    "cl": idx.get("countrylong", 5), "cs": idx.get("countryshort", 6), "b64": b64_idx
}
rows = []
for ln in lines[header_idx + 1:]:
    try:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) >= 7 and fields[pos["h"]].strip() and fields[pos["ip"]].strip():
            rows.append({
                "host": fields[pos["h"]].strip(), "ip": fields[pos["ip"]].strip(),
                "country_long": fields[pos["cl"]].strip(), "country_short": fields[pos["cs"]].strip(),
                "config_b64": fields[pos["b64"]].strip(),
            })
    except Exception:
        continue
return rows


def parse_mirror_json(data):
servers = []
items = data if isinstance(data, list) else [data]
for item in items:
if isinstance(item, dict):
servers.extend(item.get("servers", [item]) if isinstance(item.get("servers"), list) else [item])
rows = []
for s in servers:
h, ip = str(s.get("hostname") or s.get("host") or "").strip(), str(s.get("ip") or "").strip()
if h and ip:
rows.append({
"host": h, "ip": ip,
"country_long": str(s.get("countrylong") or s.get("country_long") or "").strip(),
"country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
"config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
})
return rows

_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
nodes = []
for r in rows:
cfg = ""
if r.get("config_b64"):
try:
cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
except Exception:
pass
if not _PROTO_TCP_RE.search(cfg):
continue
m = _REMOTE_RE.search(cfg)
if not m:
continue
port = int(m.group(1))
if 1 <= port <= 65535:
host = r["host"]
if not host.endswith(".opengw.net") and not re.match(r"^\d+.\d+.\d+.\d+$", host):
host = f"{host}.opengw.net"
nodes.append({
"host": host, "port": port, "ip": r.get("ip", ""),
"country": r.get("country_long", "未知"),
"country_code": (r.get("country_short") or "US").upper(),
})
return nodes

def fetch_vpngate():
try:
log("VPN GATE", f"请求官方 API: {VPNGATE_API}")
resp = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
resp.raise_for_status()
rows = parse_csv(resp.text)
if rows:
return rows, "vpngate.net/api/iphone"
except Exception as exc:
log("VPN GATE", f"官方 API 失败: {exc}")

try:
    log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
    resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
    resp.raise_for_status()
    rows = parse_mirror_json(resp.json())
    if rows:
        return rows, "github-mirror"
except Exception as exc:
    log("VPN GATE", f"回退镜像失败: {exc}")
return [], "none"


def fetch_extra_nodes():
extra_nodes = []
for src in EXTRA_SOURCES:
try:
r = requests.get(src, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
if r.status_code != 200:
continue
txt = r.text
if not any(k in txt for k in [":", "@", "#"]):
try:
txt = base64.b64decode(txt.strip()).decode("utf-8", "ignore")
except Exception:
pass
for line in txt.splitlines():
line = line.strip()
m = re.search(r"sstp://(?:[^@]+@)?([^:/]+):(\d+)", line) or re.search(r"([a-zA-Z0-9-]+.opengw.net):(\d+)", line)
if m:
extra_nodes.append({
"host": m.group(1), "port": int(m.group(2)),
"ip": "", "country": "美国", "country_code": "US"
})
except Exception:
continue
log("EXTRA SOURCES", f"外部源扩充了 {len(extra_nodes)} 个节点")
return extra_nodes

def dedupe(nodes):
seen = set()
out = []
for n in nodes:
key = (n["host"].lower(), int(n["port"]), "sstp")
if key not in seen:
seen.add(key)
out.append(n)
return out

def classify_network(host, exit_org, is_dc=None):
if is_dc is True: return "datacenter"
if is_dc is False: return "residential"
org = (exit_org or "").upper()
if org:
if any(k in org for k in DATA_CENTER_KEYWORDS): return "datacenter"
if any(k in org for k in RESIDENTIAL_KEYWORDS): return "residential"
h = host.lower()
if h.startswith("public-vpn"): return "datacenter"
if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h): return "residential"
return "unknown"

def check_one(node, session):
url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
out = dict(node)
out.update({
"protocol": "sstp", "link": f"sstp://vpn:vpn@{node['host']}:{node['port']}",
"status": "failed", "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
"exit": None, "residential": "unknown"
})
try:
r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
if r.status_code != 200:
out["error"] = f"HTTP {r.status_code}"
out["worker_error"] = True
return out
j = r.json()
ok = bool(j.get("success"))
out["success"] = ok
out["status"] = "success" if ok else "failed"
out["latency_ms"] = j.get("responseTime")
out["colo"] = j.get("colo")
out["error"] = None if ok else (j.get("error") or "check failed")

    exit_info = j.get("exit") or {}
    if exit_info:
        asn = exit_info.get("asn") or {}
        org = asn.get("org") or asn.get("name") or ""
        cc = (exit_info.get("country_code") or "").upper()
        if cc:
            out["country_code"] = cc
            out["country"] = COUNTRY_ZH.get(cc, exit_info.get("country", out["country"]))
        out["exit"] = {
            "ip": exit_info.get("ip"), "country": exit_info.get("country"),
            "country_code": cc, "city": exit_info.get("city"), "org": org,
            "is_datacenter": exit_info.get("is_datacenter")
        }
        out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
    else:
        out["residential"] = classify_network(out["host"], None, None)
    return out
except Exception as exc:
    out["error"] = f"{type(exc).__name__}: {exc}"
    out["worker_error"] = True
    return out


def check_all(nodes, session):
results = []
with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
futures = [pool.submit(check_one, n, session) for n in nodes]
for fut in as_completed(futures):
results.append(fut.result())
return results

def build_outputs(results, raw_count, sstp_count, source):
available = [r for r in results if r.get("success")]
countries = {}
for n in available:
c = n.get("country") or "未知"
countries.setdefault(c, {"code": n.get("country_code") or "?", "nodes": []})["nodes"].append(n)

stats = {
    "raw_nodes": raw_count, "sstp_nodes": sstp_count, "checked": len(results),
    "success": len(available), "failed": len(results) - len(available),
    "countries": len(countries),
    "residential_est": sum(1 for n in available if n.get("residential") == "residential"),
    "datacenter_est": sum(1 for n in available if n.get("residential") == "datacenter"),
}
by_country = {}
for name, grp in countries.items():
    grp["count"] = len(grp["nodes"])
    grp["residential"] = sum(1 for n in grp["nodes"] if n.get("residential") == "residential")
    grp["datacenter"] = sum(1 for n in grp["nodes"] if n.get("residential") == "datacenter")
    grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
    by_country[name] = grp

return {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    "source": source, "worker": WORKER_CHECK_URL, "stats": stats,
    "countries": by_country, "available": available,
}


CHAIN_URL = os.environ.get("CHAIN_URL", "https://jerylihub.github.io/gate/chains.txt")
HOSTS_URL = os.environ.get("HOSTS_URL", "https://jerylihub.github.io/gate/hosts.txt")
SUB_URL = os.environ.get("SUB_URL", "https://jerylihub.github.io/gate/sub.txt")
EDT_UUID = os.environ.get("EDT_UUID", "88d67d47-d159-424f-9918-5a8477606307")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "ss.memory44.ccwu.cc")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")

def build_chains_text(data):
lines = [f"# VPN Gate 链式代理清单 | 更新: {data['generated_at']} | {CHAIN_URL}"]
for cname, grp in sorted(data["countries"].items(), key=lambda kv: (-int(kv[1].get("count") or 0))):
code = str(grp.get("code") or "?").upper()
zh = COUNTRY_ZH.get(code) or cname
res = [n for n in grp["nodes"] if n.get("residential") == "residential"]
dc = [n for n in grp["nodes"] if n.get("residential") != "residential"]
lines.append(f"\n# ---- {zh} {code} · {grp['count']} 节点 ----")
for i, n in enumerate(res, 1):
lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
for i, n in enumerate(dc, 1):
lines.append(f"{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
return "\n".join(lines) + "\n"

def build_hosts_text(data):
edge = [e.strip() for e in os.environ.get("HOSTS_ENTRY", "").split(",") if e.strip()] or EDGE_HOSTS
lines = [f"# edgetunnel 优选 IP 清单 | 更新: {data['generated_at']} | {HOSTS_URL}"]
idx = 0
for cname, grp in sorted(data["countries"].items(), key=lambda kv: (-int(kv[1].get("count") or 0))):
code = str(grp.get("code") or "?").upper()
zh = COUNTRY_ZH.get(code) or cname
res = [n for n in grp["nodes"] if n.get("residential") == "residential"]
dc = [n for n in grp["nodes"] if n.get("residential") != "residential"]
lines.append(f"\n# ---- {zh} {code} · {grp['count']} 节点 ----")
for i, n in enumerate(res, 1):
lines.append(f"{edge[idx % len(edge)]}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
idx += 1
for i, n in enumerate(dc, 1):
lines.append(f"{edge[idx % len(edge)]}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
idx += 1
return "\n".join(lines) + "\n"

def _b64_secret_encode(plaintext, secret):
data, key = plaintext.encode("utf-8"), secret.encode("utf-8")
return base64.b64encode(bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))).decode("ascii")

def build_sub_text(data):
lines = [f"# edgetunnel 完整订阅 | 更新: {data['generated_at']} | {SUB_URL}"]
for cname, grp in sorted(data["countries"].items(), key=lambda kv: (-int(kv[1].get("count") or 0))):
code = str(grp.get("code") or "?").upper()
zh = COUNTRY_ZH.get(code) or cname
for i, n in enumerate(grp["nodes"], 1):
name = f"{zh}-{i:02d}"
chain = {"type": "sstp", "username": "vpn", "password": "vpn", "hostname": n['host'], "port": n['port']}
enc = _b64_secret_encode(json.dumps(chain, separators=(",", ":")), EDT_UUID)
path = quote("/video/" + enc, safe="")
lines.append(
f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
)
return "\n".join(lines) + "\n"

def write_outputs(data):
os.makedirs(PUBLIC_DIR, exist_ok=True)
paths = {
"data.json": (os.path.join(PUBLIC_DIR, "data.json"), json.dumps(data, ensure_ascii=False, indent=1)),
"chains.txt": (os.path.join(PUBLIC_DIR, "chains.txt"), build_chains_text(data)),
"hosts.txt": (os.path.join(PUBLIC_DIR, "hosts.txt"), build_hosts_text(data)),
"sub.txt": (os.path.join(PUBLIC_DIR, "sub.txt"), build_sub_text(data))
}
for _, (p, content) in paths.items():
with open(p, "w", encoding="utf-8") as f:
f.write(content)

html_path = os.path.join(PUBLIC_DIR, "index.html")
if os.path.exists(TEMPLATE_HTML):
    with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
        html = f.read()
else:
    html = "<html><body><h1>VPN Gate Nodes</h1></body></html>"
with open(html_path, "w", encoding="utf-8") as f:
    f.write(html)
return [p for p, _ in paths.values()] + [html_path]


def main():
session = requests.Session()
rows, source = fetch_vpngate()
raw_count = len(rows)
sstp_nodes = to_sstp_nodes(rows)

# 合并外部扩展节点（重点补充美国节点）
extra_nodes = fetch_extra_nodes()
combined_nodes = sstp_nodes + extra_nodes
uniq = dedupe(combined_nodes)

if not uniq:
    die("未解析出任何待测节点，流程中止。")
if MAX_CHECK_NODES > 0:
    uniq = uniq[:MAX_CHECK_NODES]

log("CHECK", f"待测节点总数: {len(uniq)} (VPNGate: {len(sstp_nodes)}, 扩展补充: {len(extra_nodes)})")
results = check_all(uniq, session)
success = [r for r in results if r.get("success")]
log("CHECK", f"检测完成，可用节点: {len(success)}")

data = build_outputs(results, raw_count, len(combined_nodes), source)
write_outputs(data)
log("FINISH", "所有订阅清单与数据文件已成功生成。")


if name == "main":
try:
main()
except Exception as exc:
die(f"程序异常: {exc}")
