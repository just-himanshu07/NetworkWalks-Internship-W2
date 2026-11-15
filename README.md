# NetworkWalks Cybersecurity Internship — Week 2
## Domain Footprinting & Local Network Host Discovery

**Author:** Himanshu Raj  
**Environment:** Kali Linux  
**Tools:** WHOIS, WhatWeb, Nslookup, cURL, Wafw00f, DNSRecon, Nmap, ARP  
**Date:** 14 November 2026  
**Program:** NetworkWalks Cybersecurity Internship — Week 2

---

## 1. Overview

This repository documents my Week 2 practical work focused on two foundational cybersecurity activities:

1. **Domain Footprinting:** Collecting publicly available domain, DNS, web-technology, HTTP-header, and WAF information.
2. **Local Network Host Discovery:** Identifying active devices on a local network and reviewing available IP and MAC address information.

The exercises were performed for learning and documentation. The domain used for the footprinting demonstration was `example.com`, an IANA-reserved example domain. The network scan was performed against the local network visible to my Kali Linux machine.

## 2. Objectives

- Understand how passive and low-impact reconnaissance tools collect domain information.
- Query common DNS record types.
- Inspect HTTP response headers and identify a detected web application firewall.
- Discover responding hosts on a local IPv4 subnet.
- Review host and MAC-address information available from Nmap and the ARP table.
- Record tool limitations and practical observations accurately.

## 3. Lab Environment

| Component | Observed details |
|---|---|
| Operating system | Kali Linux |
| WHOIS | 5.6.6 |
| WhatWeb | 0.6.4 |
| Nslookup | 9.20.23-1-Debian |
| cURL | 8.22.0 |
| Wafw00f | 2.4.2 |
| Nmap | 7.99 |
| DNSRecon | Installed, but execution failed due to a Python compatibility error |
| Network interface | `wlan0` |
| Local IPv4 address | `192.168.1.13` |
| Netmask | `255.255.255.0` |
| Scanned subnet | `192.168.1.0/24` |

> **Scope and accuracy note:** The supplied terminal evidence shows Kali Linux commands and the `wlan0` interface. It does not demonstrate execution on Windows 11 or use of the Zenmap graphical interface. Those activities are not claimed in this report.

---

# Part A — W2-PM1: Domain Footprinting

## 4. Target and Scope

**Demonstration domain:** `example.com`

`example.com` is reserved for documentation and examples. The results below are a tool-practice demonstration, not a penetration test or security assessment of a customer-owned production website.

## 5. Tool Execution and Findings

### 5.1 WHOIS — Domain Registration Information

**Command**
```bash
whois example.com
```

**Observed findings**
- Domain: `EXAMPLE.COM`
- Registry WHOIS server: `whois.iana.org`
- Registrar shown: `RESERVED-Internet Assigned Numbers Authority`
- Creation date shown in the registry response: `1995-08-14`
- Registry expiry date shown: `2027-08-13`
- Name servers:
  - `ELLIOTT.NS.CLOUDFLARE.COM`
  - `HERA.NS.CLOUDFLARE.COM`
- DNSSEC: `signedDelegation`
- Domain status included client delete, transfer, and update prohibitions.

**Learning:** WHOIS can expose registration and delegation metadata. Some registrant details may be redacted or unavailable, and registry data should be interpreted in the context of the domain's reserved status.

### 5.2 WhatWeb — Web Technology Fingerprinting

**Command**
```bash
whatweb https://example.com
```

**Observed output summary**
- HTTP status: `200 OK`
- HTML5 detected
- HTTP server identified as Cloudflare
- IP reported by WhatWeb: `172.66.147.243`
- Page title: `Example Domain`
- Additional response indicators included `cf-cache-status`, `cf-ray`, and `alt-svc`.

**Learning:** WhatWeb helps identify technologies and response characteristics exposed by a website. Fingerprinting results are indicators, not a complete inventory of the underlying infrastructure.

### 5.3 Nslookup — DNS Queries

**Commands**
```bash
nslookup example.com
nslookup -type=A example.com
nslookup -type=MX example.com
nslookup -type=NS example.com
nslookup -type=TXT example.com
```

**Observed findings**
- A records returned:
  - `172.66.147.243`
  - `104.20.23.154`
- An IPv6 address was also returned by the default lookup:
  - `2606:4700:8395:72db:f239:9be:ef6b:ff98`
- MX response: `0 .` (null MX)
- NS records:
  - `elliott.ns.cloudflare.com`
  - `hera.ns.cloudflare.com`
- TXT responses included:
  - `v=spf1 -all`
  - A separate domain-verification-like token.

**Learning:** DNS record types serve different purposes. A records map names to IPv4 addresses; MX records describe mail routing; NS records identify authoritative name servers; TXT records can publish policy and verification data.

**Interpretation:** The null MX and `v=spf1 -all` response indicate that the domain does not advertise normal inbound mail service and its SPF policy rejects mail claiming to originate from the domain. This interpretation is limited to the observed DNS response.

### 5.4 cURL — HTTP Response Header Inspection

**Command**
```bash
curl -I https://example.com
```

**Observed findings**
- HTTP response: `HTTP/2 200`
- Content type: `text/html; charset=utf-8`
- Server header: `cloudflare`
- Cache status: `HIT`
- Cloudflare Ray identifier was returned.
- `alt-svc` advertised HTTP/3.

**Learning:** HTTP headers provide useful information about protocol behavior, server-side response metadata, caching, and selected security controls. The captured output did not show headers such as `Strict-Transport-Security` or `Content-Security-Policy`; this single response should not be treated as a complete security-header audit.

### 5.5 Wafw00f — Web Application Firewall Detection

**Command**
```bash
wafw00f https://example.com
```

**Observed finding**
```text
The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
```

Wafw00f identified Cloudflare as the detected WAF provider.

**Learning:** WAF fingerprinting tools can identify indicators of a protective layer in front of a web application. Detection does not prove that every request is inspected or that the application itself is secure.

### 5.6 DNSRecon — DNS Enumeration

**Command attempted**
```bash
dnsrecon -d example.com
```

**Observed issue**
DNSRecon did not run. It terminated with:
```text
AttributeError: module 'urllib.request' has no attribute 'FancyURLopener'
```

**Interpretation:** The installed DNSRecon code attempted to use a Python API that is unavailable in the current Python environment. No DNSRecon enumeration results were produced.

**Status:** Not completed. This issue is documented rather than presenting unverified DNSRecon findings.

---

# Part B — W2-PM5: Local Network Host Discovery

## 6. Network Identification

**Command**
```bash
ifconfig
```

The active wireless interface shown in the supplied output was `wlan0`.

| Parameter | Observed value |
|---|---|
| Interface | `wlan0` |
| IPv4 address | `192.168.1.13` |
| Netmask | `255.255.255.0` |
| Broadcast | `192.168.1.255` |
| MAC address of local interface | `14:13:33:c9:11:2b` |
| Subnet used for scan | `192.168.1.0/24` |

The `/24` subnet contains 256 IPv4 addresses in total, including network and broadcast addresses.

## 7. Nmap Host Discovery

**Nmap version check**
```bash
nmap --version
```

Observed version: `Nmap 7.99`.

**Initial command attempted**
```bash
nmap -sn 192.168.43.0/24
```

The supplied terminal capture shows the scan starting but does not show completed host results for this subnet. The interface configuration showed `192.168.1.13/24`, so the scan was then run against the matching local subnet.

**Completed scan command**
```bash
nmap -sn 192.168.1.0/24
```

`-sn` performs host discovery without a port scan.

**Observed result**
```text
Nmap done: 256 IP addresses (4 hosts up) scanned in 5.34 seconds
```

Four responding hosts were reported:

| IP address | Status | MAC address | Vendor shown |
|---|---|---|---|
| `192.168.1.1` | Up | `78:BB:5C:78:BC:10` | Unknown |
| `192.168.1.8` | Up | `2A:3E:63:7B:28:39` | Unknown |
| `192.168.1.11` | Up | `A8:41:F4:3B:D3:CF` | AzureWave Technology |
| `192.168.1.13` | Up | Not shown in this host result | Local scanning machine |

**Observation:** Four hosts responded during the scan. The gateway was identified at `192.168.1.1`; the local machine was `192.168.1.13`. The supplied output does not establish the exact device identity or owner of the other hosts.

## 8. ARP Table Review

**Command**
```bash
arp -a
```

**Observed entries**
```text
192.168.1.8  -> 2a:3e:63:7b:28:39
192.168.1.1  -> 78:bb:5c:78:bc:10
```

**Learning:** The ARP table contains IP-to-MAC mappings learned by the local machine. It may not contain every host found by Nmap because ARP entries depend on recent local network communication and the network environment.

## 9. Practical Observations

1. The wireless interface used the `192.168.1.0/24` subnet.
2. The completed Nmap ping scan reported four active hosts out of 256 scanned addresses.
3. Nmap displayed MAC addresses for the gateway and two other responding hosts; the local host was also listed.
4. The ARP table contained two mappings at the time it was checked.
5. Host discovery results depend on network conditions, device availability, firewall rules, and access-point/client isolation.

---

# 10. Issues and Limitations

| Item | Status | Notes |
|---|---|---|
| WHOIS | Completed | Reserved example domain used |
| WhatWeb | Completed | Technology indicators returned |
| Nslookup | Completed | A, MX, NS, and TXT queries returned |
| cURL | Completed | HTTP response headers inspected |
| Wafw00f | Completed | Cloudflare WAF detected |
| DNSRecon | Not completed | Python `FancyURLopener` compatibility error |
| Nmap | Completed | Four hosts reported on `192.168.1.0/24` |
| ARP | Completed | Two IP-to-MAC entries displayed |
| Zenmap topology | Not evidenced | No Zenmap GUI output was supplied |
| Windows 11 execution | Not evidenced | Supplied commands were run in Kali Linux |

These limitations are included to keep the report reproducible and evidence-based.

# 11. Key Learnings

- Domain footprinting combines registration, DNS, web-technology, HTTP, and WAF information.
- DNS record types provide different kinds of infrastructure and mail-policy information.
- HTTP response headers can reveal server and caching details, but one response is not a complete security assessment.
- WAF detection identifies a protective technology indicator; it does not establish application security.
- Nmap host discovery helps identify responding systems on a local subnet.
- ARP provides local IP-to-MAC mappings, but its table may be incomplete.
- Tool compatibility and environment differences can affect practical results; errors should be documented rather than hidden.

# 12. Conclusion

This week's practical provided hands-on exposure to domain reconnaissance and local network host discovery. I used multiple command-line tools to inspect a reserved demonstration domain, queried DNS records, reviewed HTTP headers, and identified Cloudflare through Wafw00f. I also used Nmap to scan the local `192.168.1.0/24` subnet and observed four responding hosts.

The DNSRecon compatibility issue highlighted the importance of validating tool versions and dependencies. Overall, the exercise strengthened my understanding of reconnaissance workflows, DNS fundamentals, HTTP metadata, and basic network discovery.

---

## 13. Evidence / Screenshots

Add your original terminal screenshots to a folder named `screenshots/` and link them here. Do not add screenshots that you have not captured.

Suggested filenames:

```text
screenshots/
├── 01-tool-versions.png
├── 02-whois-example-domain.png
├── 03-whatweb-output.png
├── 04-nslookup-records.png
├── 05-curl-response-headers.png
├── 06-wafw00f-detection.png
├── 07-dnsrecon-error.png
├── 08-network-interface-ip.png
├── 09-nmap-host-discovery.png
└── 10-arp-table.png
```

## 14. Suggested Repository Structure

```text
networkwalks-week2/
├── README.md
├── report/
│   └── week-2-practical-report.md
└── screenshots/
    └── (add your actual screenshots here)
```

## 15. Disclaimer

This repository is for educational purposes. Domain footprinting was demonstrated using the IANA-reserved `example.com` domain. Network discovery was performed against the local network visible to the author. Always obtain explicit authorization before testing domains, systems, or networks that you do not own or administer.
