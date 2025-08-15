# subdomain-enumeration-playbook

awesome — here’s a clean, **step-by-step subdomain enumeration playbook** with the **best automation tools** and lots of examples. use it for **authorized pentests / bug bounty only** ✅

---

# 🛰️ Subdomain Enumeration — End-to-End Guide

## 0) 🧰 Setup (Kali/Debian-friendly)

```bash
# Go-based tools
sudo apt update
sudo apt install -y git make jq python3-pip
# If you don't have Go yet, install it first (then reopen your shell)

# ProjectDiscovery stack
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Recon extras
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/Findomain/Findomain@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ProjectAnte/dnsgen@latest
go install -v github.com/d3mondev/puredns@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Screenshots (optional, nice for reports)
go install -v github.com/sensepost/gowitness@latest

# Wordlists
sudo apt install -y seclists
```

> 💡 Put `$GOPATH/bin` on your `PATH` so commands are available.

---

## 1) 🎯 Define target + workspace

```bash
export TARGET=example.com
mkdir -p recon/$TARGET && cd $_
```

---

## 2) 💤 Passive enumeration (fast, safe)

Gather subdomains without touching the target’s DNS much.

### 🔎 Multi-source harvest

```bash
subfinder -d $TARGET -all -recursive -silent -o subfinder.txt
assetfinder --subs-only $TARGET | anew assetfinder.txt
findomain -t $TARGET -q | anew findomain.txt
amass enum -passive -d $TARGET -o amass.txt 2>/dev/null
```

### 📰 Certificate Transparency (CT)

```bash
curl -s "https://crt.sh/?q=%25$TARGET&output=json" \
 | jq -r '.[].name_value' | sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' \
 | anew crtsh.txt
```

### 🕸️ Historical URLs → extract hosts

```bash
gau --subs $TARGET | awk -F/ '{print $3}' | sed 's/:.*//' | anew gau-hosts.txt
waybackurls $TARGET | awk -F/ '{print $3}' | sed 's/:.*//' | anew wayback-hosts.txt
```

### 🧹 Merge & dedupe

```bash
cat *.*txt | sed '/^$/d' | sort -u > 00.passive-raw.txt
```

---

## 3) ⚡ Validate with DNS (alive subdomains)

Use **fast, reliable resolvers** to cut noise.

```bash
# Get a resolvers list
puredns resolve dns.bufferover.run | head -n1 >/dev/null # warms cache (optional)
puredns resolvers > resolvers.txt

# Resolve
puredns resolve 00.passive-raw.txt -r resolvers.txt -w 10.resolved.txt
# Or mass-DNS style:
shuffledns -d $TARGET -list 00.passive-raw.txt -r resolvers.txt -o 10.resolved.txt
```

> ✅ Result: `10.resolved.txt` = hosts that actually resolve.

---

## 4) 🧨 Active expansion (bruteforce + permutations)

Find what passive missed.

### 📚 Wordlist bruteforce

Use a strong list (e.g., `SecLists/Discovery/DNS/dns-Jhaddix.txt`):

```bash
puredns bruteforce /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt \
  $TARGET -r resolvers.txt -w 20.bruteforce.txt
```

### 🧩 Permutations with dnsgen

```bash
# Seed with what you have, plus words list
cat 10.resolved.txt | dnsgen -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  > 21.perm-candidates.txt

# Resolve permutations
puredns resolve 21.perm-candidates.txt -r resolvers.txt -w 22.perm-resolved.txt
```

### 🔗 Merge everything

```bash
cat 10.resolved.txt 20.bruteforce.txt 22.perm-resolved.txt | sort -u > 30.all-resolved.txt
```

---

## 5) 📡 DNS enrichment (records & takeovers)

### 📜 Grab A/AAAA/CNAME/MX/NS/etc.

```bash
dnsx -l 30.all-resolved.txt -a -aaaa -cname -mx -ns -caa -resp -silent -o 40.dnsx.txt
```

### 🏴 Subdomain takeover checks

```bash
# Nuclei templates (keep templates updated: nuclei -update-templates)
nuclei -l 30.all-resolved.txt -tags takeover -severity medium,high,critical -o 41.takeover.txt
```

> 🧠 Tip: Look for CNAMEs pointing to deprovisioned cloud services (GitHub Pages, Heroku, Azure, Fastly, etc.).

---

## 6) 🌐 Probe live web services

### 🚪 Check which hosts speak HTTP(S)

```bash
httpx -l 30.all-resolved.txt -threads 200 -follow-host-redirects \
  -status-code -title -tech-detect -server -ip -cdn -silent -o 50.httpx.txt
```

> You’ll get a neat list like: `https://api.dev.example.com [200] "Swagger UI" (nginx,cloudflare)`

### 🖼️ Optional screenshots for reporting

```bash
cat 50.httpx.txt | awk '{print $1}' | gowitness file -f - --disable-db --path 51.screens/
```

---

## 7) 🧭 Discover more via content

Sometimes new subdomains appear inside JS/HTML.

```bash
# Pull URLs & JS, then extract hostnames again
cat 50.httpx.txt | awk '{print $1}' | gau | anew 60.urls.txt
grep -Eo 'https?://[^/"]+' 60.urls.txt | awk -F/ '{print $3}' | sed 's/:.*//' \
 | anew 61.found-hosts.txt

# Resolve any new hosts
puredns resolve 61.found-hosts.txt -r resolvers.txt -w 62.found-resolved.txt
cat 30.all-resolved.txt 62.found-resolved.txt | sort -u > 30.all-resolved.txt
```

---

## 8) 🧪 Quick security triage (optional but powerful)

Leverage **Nuclei** for fast wins (respect rate limits).

```bash
# Fingerprint + common misconfigurations
nuclei -list 50.httpx.txt -tags exposures,misc,misconfig,cves \
  -severity medium,high,critical -o 70.nuclei-web.txt

# DNS-focused templates (zone transfer, wildcard, etc.)
nuclei -l 30.all-resolved.txt -tags dns -o 71.nuclei-dns.txt
```

---

## 9) 📦 Save clean outputs for your report

```bash
sort -u 30.all-resolved.txt > ${TARGET}_subdomains.txt
awk '{print $1}' 50.httpx.txt | sort -u > ${TARGET}_alive_hosts.txt
```

---

# 🧱 One-Command “All-in” Pipeline (quick run) 🚀

```bash
#!/bin/bash
domain=$1
echo "🔍 Enumerating $domain..."
subfinder -d $domain -o $domain-passive.txt
amass enum -active -d $domain -brute -w /path/to/wordlist.txt -o $domain-active.txt
cat $domain-*.txt | sort -u | httpx -silent > $domain-final.txt
echo "✅ Done! Results in $domain-final.txt"
```
> Runs passive → resolve → probe, producing two key files.

```bash
export TARGET=example.com
mkdir -p recon/$TARGET && cd $_

(subfinder -d $TARGET -all -recursive -silent; \
 assetfinder --subs-only $TARGET; \
 findomain -t $TARGET -q; \
 amass enum -passive -d $TARGET 2>/dev/null; \
 curl -s "https://crt.sh/?q=%25$TARGET&output=json" | jq -r '.[].name_value' \
   | sed 's/\*\.//g' \
) | tr '[:upper:]' '[:lower:]' | sed '/^$/d' | sort -u > 00.passive-raw.txt

puredns resolvers > resolvers.txt
puredns resolve 00.passive-raw.txt -r resolvers.txt -w 30.all-resolved.txt

httpx -l 30.all-resolved.txt -threads 200 -follow-host-redirects \
  -status-code -title -tech-detect -server -ip -cdn -silent -o 50.httpx.txt

sort -u 30.all-resolved.txt > ${TARGET}_subdomains.txt
awk '{print $1}' 50.httpx.txt | sort -u > ${TARGET}_alive_hosts.txt
```

---

## 🧠 Pro Tips & Gotchas

* 🪪 **Permission first**: enumerate only what’s in-scope.
* 🧵 **Threading**: start conservative (`-threads 100–200`) to avoid rate limits.
* 🌍 **Resolvers**: quality resolvers = better results; refresh `resolvers.txt` often.
* 🧪 **Iterate**: feed newly found hosts back into permutations & content discovery.
* 🧩 **Group by environment**: `dev.`, `stg.`, `qa.`, `int.`, `preprod.`, country codes, etc.
* 🧵 **De-dup on the fly**: pipe to `anew` when chaining tools.
* 🗂️ **Organize**: keep `/recon/<target>/` consistent so you can diff runs over time.

---

## 🛠️ Tool Cheatsheet (best-in-class)

* 🔭 **Passive**: `subfinder`, `assetfinder`, `findomain`, `amass -passive`, CT (`crt.sh`)
* 🧪 **Resolve**: `puredns`, `shuffledns`, `dnsx`
* 🌐 **Probe**: `httpx`, `gowitness`
* 🧩 **Expand**: `dnsgen`, `puredns bruteforce`, SecLists wordlists
* 🔍 **OSINT URLs**: `gau`, `waybackurls`
* 🧨 **Quick vuln sweep**: `nuclei` (keep templates updated: `nuclei -update-templates`)
* 🧼 **Dedupe**: `anew`

---

Got it ✅ — I’ll give you a **single Bash script** that will:

* Take a target domain as input 🖊
* Enumerate subdomains 🌐
* Probe for live hosts 🟢
* Grab HTTP titles + status codes 🏷
* Take screenshots 📸
* Save **CSV + HTML reports** neatly into `/out` 📂

---

## **📜 Automated Subdomain Enumeration Script**

```bash
#!/bin/bash

# 🚀 Automated Subdomain Enumeration + Recon
# Requirements: assetfinder, subfinder, amass, httprobe, httpx, aquatone, csvkit
# Install missing tools with: go install github.com/tomnomnom/assetfinder@latest ...etc

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 example.com"
    exit 1
fi

# 📂 Output folder
OUTDIR="out_$DOMAIN"
mkdir -p "$OUTDIR"

echo "🔍 Enumerating subdomains for $DOMAIN..."

# 🌐 Gather subdomains
assetfinder --subs-only "$DOMAIN" > "$OUTDIR/subs_assetfinder.txt"
subfinder -d "$DOMAIN" -silent > "$OUTDIR/subs_subfinder.txt"
amass enum -passive -d "$DOMAIN" -o "$OUTDIR/subs_amass.txt"

# 📦 Merge & deduplicate
cat "$OUTDIR"/subs_*.txt | sort -u > "$OUTDIR/all_subs.txt"
echo "✅ Found $(wc -l < "$OUTDIR/all_subs.txt") unique subdomains"

# 🟢 Probe for live hosts
cat "$OUTDIR/all_subs.txt" | httprobe -c 50 > "$OUTDIR/live_hosts.txt"
echo "🌟 Live hosts: $(wc -l < "$OUTDIR/live_hosts.txt")"

# 🏷 Grab status codes + titles
httpx -l "$OUTDIR/live_hosts.txt" -status-code -title -o "$OUTDIR/httpx_report.txt"

# 📊 Convert to CSV
echo "URL,Status,Title" > "$OUTDIR/report.csv"
cat "$OUTDIR/httpx_report.txt" | sed 's/\ \[/:/' | awk -F':' '{print $1","$2","$3}' >> "$OUTDIR/report.csv"

# 📸 Take screenshots
cat "$OUTDIR/live_hosts.txt" | aquatone -out "$OUTDIR/screenshots" -silent

# 📝 Make HTML report
echo "<html><body><h1>Recon Report for $DOMAIN</h1><pre>" > "$OUTDIR/report.html"
cat "$OUTDIR/httpx_report.txt" >> "$OUTDIR/report.html"
echo "</pre></body></html>" >> "$OUTDIR/report.html"

echo "🎯 Done! Reports & screenshots saved in: $OUTDIR"
```

---

## **⚡ Tools Used**

| Step                | Tool                                | Purpose                            |
| ------------------- | ----------------------------------- | ---------------------------------- |
| Subdomain Discovery | `assetfinder`, `subfinder`, `amass` | Find as many subs as possible      |
| Live Check          | `httprobe`, `httpx`                 | Detect running HTTP/HTTPS services |
| Reporting           | `csvkit` (optional)                 | Create CSV outputs                 |
| Screenshots         | `aquatone`                          | Capture site previews              |

---

## **💡 Usage**

```bash
chmod +x recon.sh
./recon.sh example.com
```

* Results will be in `/out_example.com/` folder
* CSV + HTML + screenshots all tidy 📂

---

If you want, I can **upgrade this** so it also:

* Runs **nuclei** for vuln scanning ⚠
* Runs **gau/waybackurls** for JS & endpoint collection 📜
* Auto-extracts API keys/secrets 🔑

That would make it a **complete bug bounty recon bot** 🚀
Do you want me to build that upgraded version?

