# MSc Thesis: Residential Proxies in Telecom Networks

Welcome to the code storage of my Master Thesis. Code for Chapter 5.2, generating our own traffic can be found [here](./data-gathering/README.md). Code for Chapter 5.3 and most plots can be found [here](./data-analysis/README.md). 

## Datasets
This project uses a small set of lookup databases plus several external reference datasets for comparison. They are not bundled in this repository but can be downloaded from their respective sources.

### Core lookup datasets

- **GeoLite2-City_20260421**  
  - Type: MaxMind GeoIP `.mmdb`  
  - Purpose: Maps IP addresses to approximate city-level locations.

- **dbip-asn-lite-2026-04.csv**  
  - Type: DB-IP IP-to-ASN Lite CSV  
  - Purpose: Maps IP ranges to Autonomous System Numbers (ASNs).
  - Source: https://db-ip.com/db/download/ip-to-asn-lite


### Additional reference datasets

- `all_traffic_metadata.csv`  
  Flow-like traffic metadata from the bandwidth sharing project  
  Source: <https://github.com/ChaseSecurity/bandwidth_sharing>

- `june.week1.csv.uniqblacklistremoved`  
  UGR’16 June week 1 ISP traffic subset (blacklist removed)  
  Source: <https://nesg.ugr.es/nesg-ugr16/june_week1.php#INI>

- `ip_captured_as_web_proxy.tsv`  
  IP addresses observed as residential web proxies (2017–2018)  
  Source: <https://rpaas.site/>

- `dataset/regular_domain_names/january`  
  DNS traffic from a regular user  
  Source: <https://zenodo.org/records/10887463>
