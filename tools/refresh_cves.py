#!/usr/bin/env python3
"""Extend db/cves.json from NVD without touching hand-curated entries.

Standard library only. NVD's public API allows 5 requests per 30 seconds, so the
script sleeps between vendor queries. Raw results are cached in --cache.
"""
import argparse
import json
import os
import re
import time
import urllib.parse
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# keyword -> (banner keywords, port profile, vendor, device class)
KEYWORDS = {
    "hikvision": (["hikvision", "dvrdvs"], "camera", "Hikvision", "camera"),
    "dahua": (["dahua"], "camera", "Dahua", "camera"),
    "axis communications": (["axis"], "camera", "Axis", "camera"),
    "uniview": (["uniview"], "camera", "Uniview", "camera"),
    "hanwha": (["hanwha"], "camera", "Hanwha", "camera"),
    "vivotek": (["vivotek"], "camera", "Vivotek", "camera"),
    "geovision": (["geovision"], "camera", "GeoVision", "camera"),
    "reolink": (["reolink"], "camera", "Reolink", "camera"),
    "amcrest": (["amcrest"], "camera", "Amcrest", "camera"),
    "foscam": (["foscam"], "camera", "Foscam", "camera"),
    "d-link": (["d-link", "dlink"], "router", "D-Link", "router"),
    "netgear": (["netgear"], "router", "NETGEAR", "router"),
    "tp-link": (["tp-link", "tplink"], "router", "TP-Link", "router"),
    "tenda": (["tenda"], "router", "Tenda", "router"),
    "mikrotik": (["mikrotik", "routeros"], "router", "MikroTik", "router"),
    "zyxel": (["zyxel"], "router", "Zyxel", "router"),
    "ubiquiti": (["ubiquiti", "ubnt", "unifi"], "router", "Ubiquiti", "network"),
    "linksys": (["linksys"], "router", "Linksys", "router"),
    "draytek": (["draytek"], "router", "DrayTek", "router"),
    "totolink": (["totolink"], "router", "TOTOlink", "router"),
    "arcadyan": (["arcadyan"], "router", "Arcadyan", "router"),
    "dasan": (["dasan", "gpon"], "router", "Dasan", "router"),
    "huawei": (["huawei", "hg532"], "router", "Huawei", "router"),
    "zte": (["zte"], "router", "ZTE", "router"),
    "asus": (["asus"], "router", "ASUS", "router"),
    "cisco": (["cisco", "ios xe"], "network", "Cisco", "network"),
    "juniper": (["juniper"], "network", "Juniper", "network"),
    "fortinet": (["fortinet", "fortios"], "network", "Fortinet", "network"),
    "sonicwall": (["sonicwall"], "network", "SonicWall", "network"),
    "citrix": (["citrix", "netscaler"], "network", "Citrix", "network"),
    "ivanti": (["ivanti", "pulse secure"], "network", "Ivanti", "network"),
    "synology": (["synology", "diskstation"], "nas", "Synology", "nas"),
    "qnap": (["qnap"], "nas", "QNAP", "nas"),
    "asustor": (["asustor"], "nas", "Asustor", "nas"),
    "netatalk": (["netatalk"], "nas", "Netatalk", "nas"),
    "tuya": (["tuya"], "smarthome", "Tuya", "smarthome"),
    "shelly": (["shelly"], "smarthome", "Shelly", "smarthome"),
    "espressif": (["espressif", "esp32", "esp8266"], "smarthome", "Espressif", "smarthome"),
    "xiaomi": (["xiaomi"], "smarthome", "Xiaomi", "smarthome"),
    "openwrt": (["openwrt"], "router", "OpenWrt", "router"),
    "siemens": (["siemens", "simatic"], "industrial", "Siemens", "industrial"),
    "schneider electric": (["schneider electric"], "industrial", "Schneider", "industrial"),
    "rockwell automation": (["rockwell", "allen-bradley"], "industrial", "Rockwell", "industrial"),
    "moxa": (["moxa"], "industrial", "Moxa", "industrial"),
    "codesys": (["codesys"], "industrial", "CODESYS", "industrial"),
    "wago": (["wago"], "industrial", "WAGO", "industrial"),
    "advantech": (["advantech"], "industrial", "Advantech", "industrial"),
    "modbus": (["modbus"], "industrial", None, "industrial"),
    "mqtt": (["mqtt"], "mqtt", None, "mqtt"),
    "coap": (["coap"], "coap", None, "coap"),
    "upnp": (["upnp"], "upnp", None, "upnp"),
    "samba": (["samba"], "nas", "Samba", "nas"),
}

PROFILES = {
    "camera": [80, 443, 554, 8000, 8080, 8443, 8554, 37777, 34567],
    "router": [80, 443, 1900, 49152, 52869, 7547, 8000, 8080, 8443],
    "network": [80, 443, 8443, 8080, 10443],
    "nas": [80, 443, 445, 5000, 5001, 8080, 8443],
    "smarthome": [80, 443, 1883, 8883, 5683, 8080],
    "industrial": [80, 443, 502, 2404, 44818, 47808, 4840, 9600, 8080],
    "mqtt": [1883, 8883],
    "coap": [5683],
    "upnp": [1900, 49152, 52869],
}

STOP = {"router", "camera", "device", "system", "server", "software", "product",
        "firmware", "linux", "unknown", "appliance", "network", "web", "http",
        "security", "cpe", "gateway", "nas", "printer", "os", "controller"}


def score(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            return float(data.get("baseScore", 0) or 0), (data.get("baseSeverity") or "").lower()
    return 0.0, ""


def severity(value, label):
    if label in ("critical", "high", "medium", "low"):
        return label
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low"


def clean(text, limit):
    text = re.sub(r"\s+", " ", text).strip()[:limit]
    return text


def fetch(keyword, cache, pause):
    slug = re.sub(r"[^a-z0-9]+", "_", keyword.lower())
    path = os.path.join(cache, slug + ".json")
    if os.path.exists(path):
        return json.load(open(path))
    params = urllib.parse.urlencode(
        {"keywordSearch": keyword, "resultsPerPage": 2000, "noRejected": ""}
    )
    for attempt in range(4):
        try:
            req = urllib.request.Request(API + "?" + params, headers={"User-Agent": "boggy-refresh/1.0"})
            with urllib.request.urlopen(req, timeout=180) as response:
                data = json.load(response)
            rows = []
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
                )
                s, label = score(cve)
                products = []
                for conf in cve.get("configurations", []) or []:
                    for node in conf.get("nodes", []) or []:
                        for match in node.get("cpeMatch", []) or []:
                            product = match.get("criteria", "").split(":")[4:5]
                            if product:
                                products.append(product[0].replace("_", "-").lower())
                            if len(products) >= 3:
                                break
                rows.append({
                    "id": cve["id"], "desc": desc, "score": s, "severity": label,
                    "published": cve.get("published", "")[:10],
                    "products": [p for p in products if len(p) > 3 and p not in STOP],
                })
            json.dump(rows, open(path, "w"), separators=(",", ":"))
            time.sleep(pause)
            return rows
        except Exception as exc:
            print(f"{keyword}: {exc}; retrying", flush=True)
            time.sleep(15 + attempt * 10)
    print(f"{keyword}: skipped after 4 attempts", flush=True)
    return []


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="db/cves.json")
    ap.add_argument("--cache", default=".cache/nvd")
    ap.add_argument("--max-per-vendor", type=int, default=8)
    ap.add_argument("--pause", type=float, default=6.5)
    args = ap.parse_args()

    os.makedirs(args.cache, exist_ok=True)
    entries = {e["id"]: e for e in json.load(open(args.db))}
    before = len(entries)

    for keyword, (words, profile, vendor, device_class) in KEYWORDS.items():
        rows = fetch(keyword, args.cache, args.pause)
        rows.sort(key=lambda r: (-(r["score"] or 0), -int((r["published"] or "0000")[:4] or 0)))
        added = 0
        for row in rows:
            if added >= args.max_per_vendor:
                break
            if row["id"] in entries:
                continue
            if int((row["published"] or "0000")[:4] or 0) < 2010:
                continue
            if len(row["desc"]) < 40:
                continue
            keywords = list(words)
            for product in row["products"][:2]:
                if product not in keywords and len(product) > 4:
                    keywords.append(product)
            entry = {
                "id": row["id"],
                "cve": row["id"],
                "severity": severity(row["score"], row["severity"]),
                "title": clean(row["desc"].split(". ")[0], 110),
                "detail": clean(row["desc"], 420),
                "cvss": round(row["score"], 1) or None,
                "vendor": vendor,
                "ports": PROFILES[profile],
                "keywords": keywords,
                "device_types": [device_class],
                "reference": f"https://nvd.nist.gov/vuln/detail/{row['id']}",
            }
            entries[row["id"]] = {k: v for k, v in entry.items() if v is not None}
            added += 1
        print(f"{keyword}: +{added}", flush=True)

    final = [entries[k] for k in sorted(entries)]
    with open(args.db, "w") as out:
        json.dump(final, out, indent=1, ensure_ascii=False)
        out.write("\n")
    print(f"{before} -> {len(final)} entries in {args.db}")


if __name__ == "__main__":
    main()
