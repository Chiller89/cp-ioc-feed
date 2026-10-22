#!/usr/bin/env python3
"""Baut einen IoC-Feed im Check-Point-CSV-Format (sk132193) fuer Quantum Spark.

IP-Quellen (Typ "IP" bzw. "IP Range", Produkt AB = Anti-Bot):
  - Spamhaus DROP
  - Emerging Threats Block-IPs
  - FireHOL Level 1 (private/Bogon-Netze werden herausgefiltert)

Nur oeffentlich routbare Adressen landen im Feed; Duplikate werden entfernt.
Faellt eine Quelle aus, wird mit den anderen weitergebaut.
Fallen alle aus, endet das Skript mit Fehler und die alte Datei bleibt bestehen.

Aufruf: python build_feed.py cp_ioc_feed.csv
Quellen abschalten per Umgebungsvariable: SKIP_SPAMHAUS=1, SKIP_ET=1, SKIP_FIREHOL=1
"""
import ipaddress
import os
import sys
import urllib.request

HEADER = "#UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT"

# (Schluessel, Anzeigename, URL, Skip-Variable)
SOURCES = [
    ("spamhaus", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", "SKIP_SPAMHAUS"),
    ("et", "Emerging Threats", "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "SKIP_ET"),
    ("firehol", "FireHOL Level1",
     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "SKIP_FIREHOL"),
]


def fetch_lines(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cp-ioc-feed-builder/1.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace").splitlines()


def parse_networks(lines):
    """Liest IPv4-Adressen/Netze aus Textlisten; Kommentare mit # oder ; werden ignoriert."""
    nets = []
    for line in lines:
        token = line.split("#")[0].split(";")[0].strip()
        if not token:
            continue
        try:
            net = ipaddress.IPv4Network(token, strict=False)
        except ValueError:
            continue
        if net.is_global:  # private, Loopback, Multicast, Bogons raus
            nets.append(net)
    return nets


def to_row(key, label, idx, net):
    if net.prefixlen == 32:
        value, typ = str(net.network_address), "IP"
    else:
        value, typ = f"{net.network_address}-{net.broadcast_address}", "IP Range"
    return f"{key}-{idx},{value},{typ},high,high,AB,{label}"


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "cp_ioc_feed.csv"
    seen = set()
    rows = []

    for key, label, url, skip_var in SOURCES:
        if os.environ.get(skip_var) == "1":
            continue
        try:
            nets = parse_networks(fetch_lines(url))
        except Exception as exc:  # noqa: BLE001
            print(f"WARNUNG {label}: {exc}", file=sys.stderr)
            continue
        added = 0
        for net in nets:
            if net in seen:
                continue
            seen.add(net)
            added += 1
            rows.append(to_row(key, label, added, net))
        print(f"{label}: {len(nets)} geladen, {added} neu")

    if not rows:
        sys.exit("FEHLER: keine Indikatoren geladen - bestehender Feed bleibt unveraendert")

    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(HEADER + "\n" + "\n".join(rows) + "\n")
    os.replace(tmp, out_path)
    print(f"{len(rows)} Indikatoren geschrieben nach {out_path}")


if __name__ == "__main__":
    main()
