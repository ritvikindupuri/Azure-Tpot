# Azure T-Pot Honeypot — SOC Telemetry & Threat Analysis

A reproducible honeynet I deployed on **Microsoft Azure** using **T-Pot** (Telekom Security’s multi-honeypot platform). The lab captured **real-world attack telemetry** across **SSH, FTP, and HTTP**, generated **4,000+ Suricata IDS alerts**, and logged **100+ honeypot engagements**. I analyzed everything in **Kibana** using **prebuilt Suricata/T-Pot dashboards** (no custom queries), interpreting **threat signatures, IP reputation, and ASN intelligence** to simulate a full **Tier-1 → Tier-2 SOC workflow**.

---

## Highlights

- **Cloud:** Azure VM with public IP and research-oriented NSG rules  
- **Platform:** T-Pot (Honeytrap, Cowrie, HOneYtr4p, Tanner, Sentrypeer) + Suricata NIDS  
- **Dashboards:** Kibana prebuilt Suricata & T-Pot boards (attack map, signatures, ASNs, countries, JA3/JA4, HTTP/SSH)  
- **Outcomes:** ~**4,412** Suricata events, **100+** honeypot hits, dominated by **Honeytrap**; sources heavily from **US/UK/DE/FR/NL** with scanners on major clouds (Microsoft, Google, Akamai)

---

## Architecture (Mermaid)

flowchart TD
  Internet["Internet"] --> PublicIP["Azure Public IP"]
  PublicIP --> NSG["Network Security Group"]
  NSG --> VM["Ubuntu 22.04 VM"]

  subgraph TPot["T-Pot Stack on VM"]
    Honeytrap["Honeytrap"] --> ES["Elasticsearch"]
    Cowrie["Cowrie"] --> ES
    H4["HOneYtr4p"] --> ES
    Tanner["Tanner"] --> ES
    Sentry["Sentrypeer"] --> ES
    Suricata["Suricata NIDS"] --> ES
    ES --> Kibana["Kibana T-Pot Portal"]
  end

  VM --> Honeytrap
  VM --> Cowrie
  VM --> H4
  VM --> Tanner
  VM --> Sentry
  VM --> Suricata


Figure A — High-level architecture rendered with Mermaid.

Bill of Materials
Azure VM: Ubuntu 22.04 LTS; suggested size Standard_D4s_v5 (≥4 vCPU, 8–16 GB RAM, 100+ GB SSD)

Networking: Static public IP; NSG rules (see below)

Software: git and T-Pot CE installer (bundles Docker, Suricata, Elasticsearch, Kibana)

⚠️ Ethics & Safety. Use an isolated resource group/subscription. Treat the VM as untrusted. This system intentionally attracts malicious traffic—never place it on a production VNet.

Quick Start (Azure)
1) Provision the VM
bash
Copy
Edit
# Resource group & VM
az group create -n tpot-rg -l eastus
az vm create \
  -g tpot-rg -n tpot-vm \
  --image Ubuntu2204 \
  --size Standard_D4s_v5 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-sku Standard
2) Network Security Group
Pick one profile.

A) Research (wide to attract scans — used for this report)

bash
Copy
Edit
# Allow SSH for admin
az network nsg rule create -g tpot-rg --nsg-name tpot-vmNSG \
  -n Allow-SSH --priority 300 --access Allow --protocol Tcp \
  --direction Inbound --source-address-prefixes '*' \
  --source-port-ranges '*' --destination-port-ranges 22

# Broad inbound (1-65535) for honeypots
az network nsg rule create -g tpot-rg --nsg-name tpot-vmNSG \
  -n Allow-Custom-1-65535 --priority 310 --access Allow --protocol '*' \
  --direction Inbound --source-address-prefixes '*' \
  --source-port-ranges '*' --destination-port-ranges 1-65535
Figure 1 — Azure NIC/NSG configuration used for the capture.
<img width="2200" height="992" alt="Screenshot 2025-08-03 101856" src="https://github.com/user-attachments/assets/f5fef050-777c-4aef-84e4-603abd74b070" />

B) Minimal (safer; expose only what you plan to study)

bash
Copy
Edit
for p in 21 22 80 443; do
  az network nsg rule create -g tpot-rg --nsg-name tpot-vmNSG \
    -n "Allow-$p" --priority $((400+p)) --access Allow --protocol Tcp \
    --direction Inbound --source-address-prefixes '*' \
    --source-port-ranges '*' --destination-port-ranges $p
done
3) Install T-Pot
bash
Copy
Edit
ssh azureuser@<PUBLIC_IP>

# Update & prerequisites
sudo apt update && sudo apt -y upgrade
sudo apt -y install git

# Fetch T-Pot CE and run the installer
git clone https://github.com/telekom-security/tpotce.git
cd tpotce/iso/installer
sudo ./install.sh
# Choose a profile (e.g., Standard/full stack), set passwords, confirm & reboot.
Access: After reboot, open the T-Pot Portal at
https://<PUBLIC_IP>:64297 → use the portal link to Kibana.
(If you chose the minimal NSG, allow 64297/TCP as well.)

Verify Sensors & Data Flow
T-Pot portal: Confirm containers for Honeytrap, Cowrie, HOneYtr4p, Tanner, Sentrypeer are running.

Kibana → Suricata dashboards: Events should increase over time.

Kibana → T-Pot dashboards: Check hits by honeypot and destination ports.

Figure 2 — Global attack map & top service hits (T-Pot overview).
<img width="1838" height="898" alt="Screenshot 2025-08-03 101950" src="https://github.com/user-attachments/assets/86de6c17-7e82-47a8-9c6a-b9618177be40" />


What I Captured (Key Results)
Values below reflect the screenshots/time window of this lab.

Volume & Mix
Honeypot engagements: 111 (Honeytrap ≫ others)

Suricata events: 4,412
183 unique source IPs, 37 unique JA3 hashes, 14 unique JA4 hashes

Figure 3 — Suricata overview (events, categories, dynamic map).
<img width="1912" height="501" alt="Screenshot 2025-08-03 102150" src="https://github.com/user-attachments/assets/00f97015-7685-4fe4-8e9a-45a004b7f678" />


Top IDS Signatures
ET INFO HTTP Request on Unusual Port Possibly Hostile (~49)

ET DROP DShield Block Listed Source group 1 (~38)

SURICATA AppLayer Mismatch protocol both directions (~20)

ET SCAN NMAP -sS window 1024 (~17)

Plus: SURICATA STREAM RST no session, Reserved Internal IP Traffic,
CINS Active Threat Intelligence (poor-reputation IPs), GPL SNMP trap UDP

Figure 4 — Top attacker ASNs, frequent source IPs, and Suricata alert signatures.
<img width="1911" height="798" alt="Screenshot 2025-08-03 102219" src="https://github.com/user-attachments/assets/bef75b6c-cd2a-4bc5-9e65-8ae5ba48fc82" />


Geography & ASNs
Top countries: United States, United Kingdom, Germany, France, The Netherlands, Thailand

Top ASNs (by count): Microsoft-CORP-MSN-AS-BLOCK (~379), AT&T-INTERNET4 (~218), Google-Cloud-Platform (~80),
Akamai Connected Cloud (~50), MEVSPACE (~49), Contabo (~27), Censys-ARIN-01/02 (~25/18),
Hurricane Electric (~19), DediOutlet-Networks (~18)

Figure 5 — Attacks by country and ASN distribution.
<img width="1906" height="534" alt="suricata ASN alert" src="https://github.com/user-attachments/assets/9cba42ed-1fd4-43bf-b91d-2470698c31b1" />


Sources & Protocols
Repeated sources incl. 207.167.67.206, 47.251.59.83, 167.94.138.127, 185.242.226.24, 207.90.244.19, …

HTTP methods: PUT / GET / POST / CONNECT

Content-Types: text/xml, text/plain, application/json, text/html

Hostnames hit: the VM public IP plus Azure infra probes (e.g., 168.63.129.16)

Figure 6 — HTTP/TLS fingerprints and reputation (Hostnames, Methods, Content-Types, JA3/JA4, Known attacker vs Mass scanner).
<img width="1917" height="582" alt="Screenshot 2025-08-03 102234" src="https://github.com/user-attachments/assets/360f4df6-e679-4ace-8c17-66223251dcc7" />


Honeypot Services Observed
Probes/engagements across SSH (22), FTP (21), HTTP (80/443), and opportunistic scans of high-risk/IoT ports.

Figure 7 — Honeypot overview (counts, destination ports, attacks by country) and sensor mix.
<img width="1907" height="702" alt="Screenshot 2025-08-03 102127" src="https://github.com/user-attachments/assets/aff8dc76-89c0-40bd-a971-f3543ac0adb3" />



SOC Workflow Followed
Detection – Monitor Suricata dashboards for high-signal rules (Nmap scans, DShield, CINS intel).

Triage – Prioritize noisy sources with reputation hits; distinguish mass scanning vs targeted.

Scope – Pivot by Source IP → ASN → Country → JA3/JA4; check dwell/re-entry via time histograms.

Hypothesize – Map signatures to behaviors (e.g., fast uncommon-port probes ⇒ bot/worm crawlers; -sS ⇒ recon).

Report – Summarize IOCs (IPs, ASNs, hashes), note impact (isolated research host), and propose mitigations a SOC would take (geo throttling, reputation-based blocks, WAF sims, sensor tuning).

How to Reproduce the Analysis
Let the honeypot run 24–72 hours to accumulate data.

In Kibana, open T-Pot and Suricata dashboards and capture:

Totals (events, unique source IPs/JA3/JA4)

Top signatures

Attack map, countries, ASNs, top source IPs

Destination ports and honeypot breakdown

Save the key views as PNGs and embed them as shown in this README.

What This Demonstrates
Cloud Security Engineering: Safe deployment of an internet-facing research host on Azure.

Threat Intel & Detection: Turning noisy honeypot/NIDS logs into actionable findings (signatures, reputation, fingerprints).

SOC Practice: End-to-end workflow—detection → triage → scope → hypothesis → reporting—with artifacts & metrics.

Cleanup
bash
Copy
Edit
# From your workstation
az group delete -n tpot-rg --yes --no-wait
Extensions (Roadmap)
Add alerting (Elastic Watcher/Elastalert) for high-confidence Suricata rules.

Enrich with MaxMind GeoIP, AbuseIPDB, Shodan (cache results to avoid external dependencies).

Deploy a second region VM to compare geo attack patterns.

Export IOC feeds (IPs/ASNs/JA3) to simulate WAF/firewall blocklists.

Credits
T-Pot CE — Telekom Security

Suricata — OISF

Elastic Stack — Elasticsearch & Kibana

License
This lab & write-up are for educational and research purposes only. Comply with cloud AUPs and never expose sensitive networks or data.
