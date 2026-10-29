#!/usr/bin/env python3
"""
Async Sticky Residential Proxy Scanner & Tier-1 Eyeball /24 Deduplicator
========================================================================
Probes sticky residential proxy ports concurrently, enriches exit IPs via
batch ASN/ISP intelligence, strips datacenter/hosting/VPN/leased subnets
(M247, Datacamp, Choopa, IPXO, Netrouting, PacketHub, etc.), prioritizes
Tier-1 US consumer eyeball ISPs (Comcast, AT&T, Verizon, Charter/Spectrum,
Cox, T-Mobile, CenturyLink/Lumen), and deduplicates strictly by /24 subnet.
"""

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import aiohttp

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

BAD_ASN_KEYWORDS: List[str] = [
    "m247", "datacamp", "cdn77", "choopa", "vultr", "digitalocean",
    "hetzner", "ovh", "linode", "akamai", "colocrossing", "performive",
    "psychz", "tzulo", "leaseweb", "contabo", "tefincom", "frantech",
    "buyvm", "sharktech", "quadranet", "zenlayer", "multacom", "hostwinds",
    "hivelocity", "nocix", "wholesale internet", "total server", "constant company",
    "amazon", "aws", "google cloud", "microsoft", "oracle", "alibaba", "tencent",
    "cloudflare", "fastly", "hurricane electric", "cogent", "retn", "gtt",
    "zscaler", "avast", "kaspersky", "private internet access", "vpn", "hosting",
    "datacenter", "server", "cloud", "dedipath", "teraswitch", "latitude.sh",
    "phoenixnap", "ionos", "1&1 ionos", "kamatera", "upcloud", "scaleway",
    "turknet", "ipxo", "netrouting", "packethub", "teknosos", "flash edge",
    "asn-feit", "idc cube", "zenwalk", "glide group", "aviation", "stingers",
    "ws telecom", "wst", "telcom llc", "castro telecom", "internexus",
    "colocation", "proton", "litlink", "xirgo", "vickohm", "telus",
]

BAD_AS_NUMBERS: Set[str] = {
    "AS9009", "AS60068", "AS212238", "AS20473", "AS14061", "AS24940",
    "AS16276", "AS63949", "AS36352", "AS46562", "AS40676", "AS11878",
    "AS51167", "AS136787", "AS53667", "AS46844", "AS29761", "AS8100",
    "AS21859", "AS35916", "AS54290", "AS29802", "AS33387", "AS16509",
    "AS14618", "AS15169", "AS396982", "AS8075", "AS31898", "AS13335",
    "AS6939", "AS174", "AS9002", "AS62904", "AS398101", "AS206092",
}

EYEBALL_ISP_KEYWORDS: List[str] = [
    "comcast", "at&t", "att ", "verizon", "charter", "spectrum", "cox ",
    "rcn", "astound", "cablevision", "optimum", "grande", "windstream",
    "centurylink", "lumen", "t-mobile", "starlink", "space exploration",
    "cable one", "sparklight", "mediacom", "consolidated", "tds telecom",
    "midcontinent", "midco", "atlantic broadband", "breezeline", "ziply",
    "frontier", "sonic", "google fiber", "armstrong", "altafiber", "cincinnati bell",
    "shenandoah", "shentel", "buckeye", "hargray", "fidelity", "wideopenwest", "wow!",
]


async def probe_port(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    proxy_host: str,
    proxy_user: str,
    proxy_pass: str,
    port: int,
) -> Dict[str, Any]:
    proxy_url = f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{port}"
    t0 = time.perf_counter()
    async with sem:
        for test_url in ("http://checkip.amazonaws.com", "http://api.ipify.org"):
            try:
                async with session.get(
                    test_url,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=8, connect=5),
                ) as resp:
                    if resp.status == 200:
                        text = (await resp.text()).strip()
                        if text and "." in text and len(text) <= 45:
                            latency_ms = round((time.perf_counter() - t0) * 1000, 1)
                            return {
                                "port": port,
                                "host": proxy_host,
                                "ip": text,
                                "latency_ms": latency_ms,
                                "alive": True,
                            }
            except Exception:
                continue
    return {
        "port": port,
        "host": proxy_host,
        "ip": None,
        "latency_ms": None,
        "alive": False,
    }


async def lookup_ip_batches(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    fields = "status,message,countryCode,regionName,city,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
    url = f"http://ip-api.com/batch?fields={fields}"
    async with aiohttp.ClientSession() as session:
        for i in range(0, len(ips), 100):
            chunk = ips[i : i + 100]
            for _ in range(3):
                try:
                    async with session.post(
                        url, json=chunk, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for item in data:
                                q = item.get("query")
                                if q:
                                    results[q] = item
                            break
                        if resp.status == 429:
                            await asyncio.sleep(5)
                except Exception:
                    await asyncio.sleep(2)
            await asyncio.sleep(1.5)
    return results


def evaluate_strict_residential(meta: Dict[str, Any]) -> Tuple[bool, str, bool]:
    """
    Returns (is_clean, reason, is_tier1_eyeball).
    Enforces US country, hosting=False, proxy=False, ASN blocklist, and keyword blocklist.
    """
    if not meta or meta.get("status") != "success":
        return False, "lookup_failed", False
    if meta.get("countryCode") != "US":
        return False, f"non_us_country:{meta.get('countryCode')}", False
    if meta.get("hosting") is True:
        return False, "flagged_hosting", False
    if meta.get("proxy") is True:
        return False, "flagged_proxy", False

    as_field = (meta.get("as") or "").strip()
    as_num = as_field.split(" ")[0].upper() if as_field else ""
    if as_num in BAD_AS_NUMBERS:
        return False, f"banned_asn:{as_num}", False

    combined = f"{meta.get('isp', '')} {meta.get('org', '')} {as_field} {meta.get('asname', '')}".lower()
    for kw in BAD_ASN_KEYWORDS:
        if kw in combined:
            return False, f"banned_keyword:{kw}", False

    is_tier1 = any(k in combined for k in EYEBALL_ISP_KEYWORDS)
    return True, "clean_residential", is_tier1


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan sticky residential proxy ports and deduplicate by /24 eyeball ISP subnet."
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.environ.get("PROXY_HOST", "gw.dataimpulse.com"),
        help="Proxy gateway hostname (env: PROXY_HOST)",
    )
    parser.add_argument(
        "--user",
        type=str,
        default=os.environ.get("PROXY_USER", ""),
        help="Proxy username (env: PROXY_USER)",
    )
    parser.add_argument(
        "--password",
        type=str,
        default=os.environ.get("PROXY_PASS", ""),
        help="Proxy password (env: PROXY_PASS)",
    )
    parser.add_argument(
        "--start-port",
        type=int,
        default=int(os.environ.get("PROXY_START_PORT", "10000")),
        help="Start port (inclusive)",
    )
    parser.add_argument(
        "--end-port",
        type=int,
        default=int(os.environ.get("PROXY_END_PORT", "10998")),
        help="End port (inclusive)",
    )
    parser.add_argument(
        "--target-count",
        type=int,
        default=333,
        help="Number of top clean proxies to export",
    )
    parser.add_argument(
        "--meta-out",
        type=Path,
        default=Path(os.environ.get("PROXIES_META_FILE", str(DATA_DIR / "clean_proxies_metadata.json"))),
        help="Output path for clean proxy metadata JSON",
    )
    args = parser.parse_args()

    if not args.user or not args.password or args.user == "your_proxy_user":
        raise SystemExit(
            "[Error] Missing proxy credentials. Set PROXY_USER and PROXY_PASS in .env or pass --user / --password."
        )

    args.meta_out.parent.mkdir(parents=True, exist_ok=True)
    ports = list(range(args.start_port, args.end_port + 1))
    print(f"Scanning {len(ports)} sticky proxy ports ({args.start_port}..{args.end_port}) on {args.host}...")
    t_start = time.perf_counter()

    connector = aiohttp.TCPConnector(limit=150, ssl=False)
    sem = asyncio.Semaphore(120)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            probe_port(session, sem, args.host, args.user, args.password, p)
            for p in ports
        ]
        probe_results = await asyncio.gather(*tasks)

    alive_ports = [r for r in probe_results if r["alive"] and r["ip"]]
    dead_count = len(probe_results) - len(alive_ports)
    unique_ips = sorted({r["ip"] for r in alive_ports})
    print(f"Probed {len(ports)} ports in {time.perf_counter() - t_start:.1f}s:")
    print(f"  Alive ports: {len(alive_ports)} | Dead/Timeout: {dead_count} | Unique Exit IPs: {len(unique_ips)}")

    print(f"Querying ASN / Hosting / Proxy intelligence for {len(unique_ips)} unique IPs...")
    ip_meta = await lookup_ip_batches(unique_ips)

    strict_clean: List[Dict[str, Any]] = []
    rejected_reasons: Dict[str, int] = {}
    asn_counts: Dict[str, int] = {}

    for r in alive_ports:
        ip = r["ip"]
        meta = ip_meta.get(ip, {})
        is_clean, reason, is_tier1 = evaluate_strict_residential(meta)
        parts = ip.split(".")
        subnet_24 = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip
        as_str = meta.get("as", "UNKNOWN")
        isp_str = meta.get("isp", "UNKNOWN")

        record = {
            "port": r["port"],
            "host": r["host"],
            "ip": ip,
            "latency_ms": r["latency_ms"],
            "subnet_24": subnet_24,
            "country": meta.get("countryCode"),
            "region": meta.get("regionName"),
            "city": meta.get("city"),
            "timezone": meta.get("timezone"),
            "isp": isp_str,
            "org": meta.get("org"),
            "as": as_str,
            "asname": meta.get("asname"),
            "mobile": meta.get("mobile"),
            "proxy_flag": meta.get("proxy"),
            "hosting_flag": meta.get("hosting"),
            "is_clean": is_clean,
            "is_tier1_eyeball": is_tier1,
            "reason": reason,
        }

        if is_clean:
            strict_clean.append(record)
            asn_counts[f"{as_str} ({isp_str})"] = asn_counts.get(f"{as_str} ({isp_str})", 0) + 1
        else:
            rejected_reasons[reason] = rejected_reasons.get(reason, 0) + 1

    # Prioritize Tier-1 US eyeball ISPs first, then lowest latency
    strict_clean.sort(key=lambda x: (not x["is_tier1_eyeball"], x["latency_ms"] or 99999))

    # Strict /24 subnet deduplication first, then unique IP overflow
    seen_subnets: Set[str] = set()
    seen_ips: Set[str] = set()
    sub_unique: List[Dict[str, Any]] = []
    sub_overflow: List[Dict[str, Any]] = []

    for candidate in strict_clean:
        if candidate["ip"] in seen_ips:
            continue
        seen_ips.add(candidate["ip"])
        if candidate["subnet_24"] not in seen_subnets:
            seen_subnets.add(candidate["subnet_24"])
            sub_unique.append(candidate)
        else:
            sub_overflow.append(candidate)

    final_strict = sub_unique + sub_overflow
    top_selected = final_strict[: args.target_count]

    args.meta_out.write_text(json.dumps(top_selected, indent=2) + "\n", encoding="utf-8")

    summary_file = args.meta_out.parent / "scan_results_summary.json"
    summary_file.write_text(
        json.dumps(
            {
                "total_ports_scanned": len(ports),
                "alive_ports": len(alive_ports),
                "dead_ports": dead_count,
                "unique_exit_ips": len(unique_ips),
                "strict_clean_unique_ips": len(final_strict),
                "strict_unique_24_subnets": len(sub_unique),
                "selected_count": len(top_selected),
                "tier1_eyeball_in_selected": sum(1 for x in top_selected if x["is_tier1_eyeball"]),
                "rejected_reasons": rejected_reasons,
                "top_clean_asns": dict(sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)[:25]),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print("\n=== STRICT RESIDENTIAL PROXY SCAN SUMMARY ===")
    print(f"Total Ports Scanned            : {len(ports)}")
    print(f"Alive Sticky Ports             : {len(alive_ports)}")
    print(f"Strict Clean Unique IPs        : {len(final_strict)}")
    print(f"Strict Unique /24 Subnets      : {len(sub_unique)}")
    print(
        f"Tier-1 Eyeball ISPs in Top {len(top_selected):3d} : "
        f"{sum(1 for x in top_selected if x['is_tier1_eyeball'])} / {len(top_selected)}"
    )
    print(f"Saved Metadata JSON            : {args.meta_out}")


if __name__ == "__main__":
    asyncio.run(main())
