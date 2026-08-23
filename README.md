# 🚀 Ping — High-Performance Data Engine in Golang

`ping` adalah layanan inspeksi HTTP, IP, & Network **berfokus 100% pada kelengkapan dan kedalaman DATA** tanpa overhead Web UI / HTML. Layanan ini dirancang khusus untuk API client, terminal, logging, bot analysis, dan security inspection, dengan kedalaman data jauh melampaui `ping.hiiruki.moe`.

---

## ⚡ Kedalaman Data yang Dihasilkan

1. **Client & Transport Layer (`client`)**:
   - IP address (IPv4 / IPv6).
   - Port koneksi client.
   - Reverse DNS / PTR lookup otomatis.
   - Indicator IP: `is_private`, `is_loopback`, `is_multicast`, `is_global_unicast`.

2. **Network & ASN Intelligence (`network`)**:
   - Nomor ASN (Autonomous System Number).
   - AS Organization & AS Name.
   - ISP (Internet Service Provider) & Organization provider.

3. **Geolocation & Location Details (`geo`)**:
   - Kode & Nama Negara, Emoji Bendera (contoh: `🇮🇩`).
   - Kode & Nama Region/Provinsi, Kota, Postal Code.
   - Koordinat Presisi (Latitude & Longitude).
   - Timezone & Mata Uang.

4. **Security & Threat Intelligence (`security`)**:
   - Cloud Provider Detection (AWS, GCP, Azure, Cloudflare, DigitalOcean, Hetzner, OVH, Vultr, dll).
   - Datacenter IP vs Residential IP detection (`is_datacenter`).
   - Proxy / VPN / Tor detection (`is_proxy`, `is_vpn`, `is_tor`).
   - Assessment Threat Level (`Low`, `Medium`, `High`).

5. **Header Order & Fingerprinting (`headers`)**:
   - `all`: Map header rata dengan key ter-normalize lowercase.
   - `raw`: Map header asli (preservasi multi-value & casing).
   - `order`: Array urutan asli kedatangan HTTP header.
   - `signature`: Hash SHA-256 dari urutan header untuk mendeteksi bot / client fingerprinting.

6. **Client Hints (`client_hints`)**:
   - Ekstraksi otomatis `Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Architecture`, `Sec-CH-UA-Model`, `Sec-CH-UA-Bitness`.

7. **User-Agent Intelligence (`user_agent`)**:
   - Browser family & version.
   - OS & OS version.
   - Engine (Blink, Gecko, WebKit, dll).
   - Device Type (Desktop, Mobile, Tablet, Bot, CLI Tool, Headless Browser Automation).
   - Indikator Headless Browser Automation (Playwright, Puppeteer, Selenium, PhantomJS).

8. **Server Execution Metrics (`server`)**:
   - Unix Timestamp (millisecond precision).
   - Processing duration / latensi dieksekusi server dalam mikrodetik (`processing_time_us`).
   - Uptime, Go version, jumlah active Goroutines, dan Memory Allocation (MB).

9. **Backward Compatibility (`cf`)**:
   - Struktur `cf` 100% identik dengan Cloudflare Workers / `ping.hiiruki.moe` untuk kompatibilitas penuh dengan script eksisting.

---

## 📌 Data Endpoints

| Endpoint | Deskripsi Data | Format |
|---|---|---|
| `GET /` | Master JSON Data Engine | `application/json` |
| `GET /json` | Direct Pure JSON Response | `application/json` |
| `GET /ip` | Raw IP Client (`180.252.174.159`) | `text/plain` |
| `GET /network` | ASN, ISP, & Organization | `application/json` |
| `GET /security` | Threat, Cloud Provider, Proxy/VPN Flags | `application/json` |
| `GET /geo` | Geolocation, Coordinates, Timezone | `application/json` |
| `GET /headers` | Header map, original order, & SHA256 signature | `application/json` |
| `GET /header/{name}` | Nilai spesifik header (misal `/header/User-Agent`) | `text/plain` |
| `GET /user-agent` | Detail parsing UA & Headless Browser detection | `application/json` |
| `GET /tls` | Versi TLS, Cipher Suite, SNI, ALPN | `application/json` |
| `GET /echo` | Echo request payload, params, headers, cookies | `application/json` |
| `GET /dns?domain=google.com` | Tool Query DNS Record (A, AAAA, MX, TXT, CNAME, NS) | `application/json` |
| `GET /ping` | Healthcheck & server uptime | `application/json` |

---

## 🛠️ Cara Menjalankan

```bash
# Running langsung
go run main.go

# Run unit tests
go test -v ./...

# Build binary
make build
./ping

# Run via Docker
docker-compose up -d --build
```
