# cp-ioc-feed

IoC feed in Check Point CSV format (sk132193) for Quantum Spark custom intelligence feeds.

Sources: Spamhaus DROP, Emerging Threats Block-IPs, FireHOL Level 1. Private and bogon networks are filtered out.
Rebuilt every 2 hours by GitHub Actions (`.github/workflows/build-feed.yml`); commits only on change.

Feed URL: https://raw.githubusercontent.com/Chiller89/cp-ioc-feed/main/cp_ioc_feed.csv

Local build: `python3 build_feed.py cp_ioc_feed.csv`
