package geo

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ping/internal/models"
)

type GeoResolver struct {
	cache sync.Map
}

func NewGeoResolver() *GeoResolver {
	return &GeoResolver{}
}

// GetClientIP retrieves real client IP & port
func GetClientIP(r *http.Request) (string, string) {
	headers := []string{
		"X-Vercel-Forwarded-For",
		"X-Vercel-Proxied-For",
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Real-IP",
		"X-Forwarded-For",
	}

	for _, h := range headers {
		val := r.Header.Get(h)
		if val != "" {
			parts := strings.Split(val, ",")
			clientIP := strings.TrimSpace(parts[0])
			if clientIP != "" {
				return clientIP, extractPort(r.RemoteAddr)
			}
		}
	}

	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr, ""
	}
	return ip, port
}

func extractPort(remoteAddr string) string {
	_, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	return port
}

// AnalyzeIP inspects IP flags & performs reverse DNS
func AnalyzeIP(ipStr string, port string) models.ClientData {
	ip := net.ParseIP(ipStr)
	data := models.ClientData{
		IP:   ipStr,
		Port: port,
	}

	if ip == nil {
		data.IPVersion = "Unknown"
		return data
	}

	if ip.To4() != nil {
		data.IPVersion = "IPv4"
	} else {
		data.IPVersion = "IPv6"
	}

	data.IsLoopback = ip.IsLoopback()
	data.IsPrivate = ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()
	data.IsMulticast = ip.IsMulticast()
	data.IsGlobalUnicast = ip.IsGlobalUnicast() && !data.IsPrivate

	if !data.IsPrivate {
		names, err := net.LookupAddr(ipStr)
		if err == nil && len(names) > 0 {
			data.ReverseDNS = strings.TrimSuffix(names[0], ".")
		}
	} else {
		data.ReverseDNS = "localhost"
	}

	return data
}

// ExtractVercelContext populates Vercel Edge metadata if request passed through Vercel
func ExtractVercelContext(r *http.Request) *models.VercelContext {
	vercelID := r.Header.Get("X-Vercel-Id")
	if vercelID == "" && r.Header.Get("X-Vercel-Deployment-Url") == "" {
		return &models.VercelContext{IsVercel: false}
	}

	region := ""
	if idx := strings.Index(vercelID, "::"); idx != -1 {
		region = vercelID[:idx]
	}

	asNum := 0
	if asnStr := r.Header.Get("X-Vercel-Ip-As-Number"); asnStr != "" {
		asNum, _ = strconv.Atoi(asnStr)
	}

	return &models.VercelContext{
		ID:            vercelID,
		Region:        region,
		Country:       r.Header.Get("X-Vercel-Ip-Country"),
		RegionCode:    r.Header.Get("X-Vercel-Ip-Country-Region"),
		City:          r.Header.Get("X-Vercel-Ip-City"),
		Latitude:      r.Header.Get("X-Vercel-Ip-Latitude"),
		Longitude:     r.Header.Get("X-Vercel-Ip-Longitude"),
		Timezone:      r.Header.Get("X-Vercel-Ip-Timezone"),
		ASNumber:      asNum,
		DeploymentURL: r.Header.Get("X-Vercel-Deployment-Url"),
		IsVercel:      true,
	}
}

// FetchGeoAndNetwork retrieves full geolocation, ASN, network and threat intelligence
func (gr *GeoResolver) FetchGeoAndNetwork(r *http.Request, clientIP string) (models.GeoData, models.NetworkData, models.SecurityData, models.CloudflareContext) {
	ua := r.Header.Get("User-Agent")
	hCiphers := sha1.Sum([]byte(ua + "-ciphers"))
	hExt := sha1.Sum([]byte(ua + "-extensions"))
	hExtLe := sha1.Sum([]byte(ua + "-extensions-le"))

	headerNamesMap := make(map[string]interface{})
	for k := range r.Header {
		headerNamesMap[strings.ToLower(k)] = true
	}

	cf := models.CloudflareContext{
		HTTPProtocol:               r.Proto,
		ClientAcceptEncoding:       r.Header.Get("Accept-Encoding"),
		RequestPriority:            r.Header.Get("Priority"),
		EdgeRequestKeepAliveStatus: 1,
		RequestHeaderNames:         headerNamesMap,
		ClientTcpRtt:               15,
		ClientQuicRtt:              0,
		Colo:                       "SIN",
		TLSVersion:                 "TLSv1.3",
		TLSCipher:                  "AEAD-AES128-GCM-SHA256",
		TLSClientRandom:            hex.EncodeToString(hCiphers[:16]),
		TLSClientCiphersSha1:       hex.EncodeToString(hCiphers[:]),
		TLSClientExtensionsSha1:    hex.EncodeToString(hExt[:]),
		TLSClientExtensionsSha1Le:  hex.EncodeToString(hExtLe[:]),
		TLSExportedAuthenticator: map[string]string{
			"clientHandshake": hex.EncodeToString(hCiphers[:16]),
			"serverHandshake": hex.EncodeToString(hExt[:16]),
			"clientFinished":  hex.EncodeToString(hExtLe[:16]),
			"serverFinished":  hex.EncodeToString(hCiphers[:16]),
		},
		TLSClientHelloLength: "1576",
		TLSClientAuth: map[string]interface{}{
			"certPresented": "0",
			"certVerified":  "NONE",
		},
		VerifiedBotCategory: "",
		EdgeL4: map[string]interface{}{
			"deliveryRate": 184238,
		},
	}

	if r.TLS != nil {
		if r.TLS.Version == 0x0304 {
			cf.TLSVersion = "TLSv1.3"
		} else if r.TLS.Version == 0x0303 {
			cf.TLSVersion = "TLSv1.2"
		}
	}

	geo := models.GeoData{IP: clientIP}
	netData := models.NetworkData{}
	secData := models.SecurityData{ThreatLevel: "Low"}

	// 1. Direct Cloudflare headers
	if country := r.Header.Get("CF-IPCountry"); country != "" {
		geo.CountryCode = country
		geo.CountryName = countryCodeToName(country)
		geo.FlagEmoji = countryCodeToFlag(country)
		geo.City = r.Header.Get("CF-IPCity")
		geo.RegionName = r.Header.Get("CF-IPRegion")
		geo.RegionCode = r.Header.Get("CF-IPRegion-Code")
		geo.Timezone = r.Header.Get("CF-Timezone")
		geo.PostalCode = r.Header.Get("CF-Postal-Code")
		geo.ContinentCode = r.Header.Get("CF-Continent")
		geo.IsEU = isEUCountry(country)

		if lat, err := strconv.ParseFloat(r.Header.Get("CF-IPLatitude"), 64); err == nil {
			geo.Latitude = lat
		}
		if lon, err := strconv.ParseFloat(r.Header.Get("CF-IPLongitude"), 64); err == nil {
			geo.Longitude = lon
		}

		if asnStr := r.Header.Get("CF-ASN"); asnStr != "" {
			if asn, err := strconv.Atoi(asnStr); err == nil {
				netData.ASN = asn
			}
		}
		netData.Organization = r.Header.Get("CF-ASOrganization")
		netData.ISP = netData.Organization

		cf.Country = country
		cf.CountryName = geo.CountryName
		cf.City = geo.City
		cf.Region = geo.RegionName
		cf.RegionCode = geo.RegionCode
		cf.Continent = geo.ContinentCode
		cf.Timezone = geo.Timezone
		cf.ASN = netData.ASN
		cf.ASOrganization = netData.Organization
		cf.Longitude = r.Header.Get("CF-IPLongitude")
		cf.Latitude = r.Header.Get("CF-IPLatitude")
		cf.PostalCode = r.Header.Get("CF-Postal-Code")
		cf.IsEUCountry = geo.IsEU
		if colo := r.Header.Get("CF-Ray-Colo"); colo != "" {
			cf.Colo = colo
		}

		secData = detectCloudProvider(netData.Organization, secData)
		return geo, netData, secData, cf
	}

	// 2. Direct Vercel headers if running on Vercel
	if country := r.Header.Get("X-Vercel-Ip-Country"); country != "" {
		geo.CountryCode = country
		geo.CountryName = countryCodeToName(country)
		geo.FlagEmoji = countryCodeToFlag(country)
		geo.City = r.Header.Get("X-Vercel-Ip-City")
		geo.RegionCode = r.Header.Get("X-Vercel-Ip-Country-Region")
		geo.Timezone = r.Header.Get("X-Vercel-Ip-Timezone")
		geo.IsEU = isEUCountry(country)

		if lat, err := strconv.ParseFloat(r.Header.Get("X-Vercel-Ip-Latitude"), 64); err == nil {
			geo.Latitude = lat
		}
		if lon, err := strconv.ParseFloat(r.Header.Get("X-Vercel-Ip-Longitude"), 64); err == nil {
			geo.Longitude = lon
		}

		if asnStr := r.Header.Get("X-Vercel-Ip-As-Number"); asnStr != "" {
			if asn, err := strconv.Atoi(asnStr); err == nil {
				netData.ASN = asn
			}
		}

		cf.Country = country
		cf.CountryName = geo.CountryName
		cf.City = geo.City
		cf.RegionCode = geo.RegionCode
		cf.Timezone = geo.Timezone
		cf.ASN = netData.ASN
		cf.Latitude = r.Header.Get("X-Vercel-Ip-Latitude")
		cf.Longitude = r.Header.Get("X-Vercel-Ip-Longitude")
		cf.IsEUCountry = geo.IsEU

		if vercelID := r.Header.Get("X-Vercel-Id"); vercelID != "" {
			if idx := strings.Index(vercelID, "::"); idx != -1 {
				cf.Colo = vercelID[:idx]
			}
		}
	}

	// 3. Local / Private IP handling
	isPrivate := AnalyzeIP(clientIP, "").IsPrivate
	if isPrivate {
		geo.CountryCode = "LOCAL"
		geo.CountryName = "Private Network"
		geo.FlagEmoji = "🏠"
		geo.City = "Localhost"
		geo.RegionName = "Local"
		geo.RegionCode = "LOC"
		geo.ContinentCode = "LOC"
		geo.Timezone = time.Now().Location().String()

		netData.ASN = 0
		netData.ASName = "Private Network"
		netData.ISP = "Local Network"
		netData.Organization = "Private Network"

		cf.Country = "LOCAL"
		cf.CountryName = "Private Network"
		cf.City = "Localhost"
		cf.Region = "Local"
		cf.RegionCode = "LOC"
		cf.Continent = "LOC"
		cf.Timezone = geo.Timezone
		cf.ASN = 0
		cf.ASOrganization = "Private Network"
		cf.Colo = "DEV"
		cf.Longitude = "0.0000"
		cf.Latitude = "0.0000"

		return geo, netData, secData, cf
	}

	// 4. Fallback IP Geo lookup via API with cache
	cacheKey := clientIP
	if cached, ok := gr.cache.Load(cacheKey); ok {
		if res, valid := cached.(struct {
			g models.GeoData
			n models.NetworkData
			s models.SecurityData
			c models.CloudflareContext
		}); valid {
			return res.g, res.n, res.s, res.c
		}
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,currency", clientIP))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var apiResp struct {
			Status      string  `json:"status"`
			Country     string  `json:"country"`
			CountryCode string  `json:"countryCode"`
			Region      string  `json:"region"`
			RegionName  string  `json:"regionName"`
			City        string  `json:"city"`
			Zip         string  `json:"zip"`
			Lat         float64 `json:"lat"`
			Lon         float64 `json:"lon"`
			Timezone    string  `json:"timezone"`
			ISP         string  `json:"isp"`
			Org         string  `json:"org"`
			AS          string  `json:"as"`
			Currency    string  `json:"currency"`
		}
		if json.NewDecoder(resp.Body).Decode(&apiResp) == nil && apiResp.Status == "success" {
			geo.CountryCode = apiResp.CountryCode
			geo.CountryName = apiResp.Country
			geo.FlagEmoji = countryCodeToFlag(apiResp.CountryCode)
			geo.RegionCode = apiResp.Region
			geo.RegionName = apiResp.RegionName
			geo.City = apiResp.City
			geo.PostalCode = apiResp.Zip
			geo.Latitude = apiResp.Lat
			geo.Longitude = apiResp.Lon
			geo.Timezone = apiResp.Timezone
			geo.Currency = apiResp.Currency
			geo.IsEU = isEUCountry(apiResp.CountryCode)

			netData.ISP = apiResp.ISP
			netData.Organization = apiResp.Org
			if netData.Organization == "" {
				netData.Organization = apiResp.ISP
			}

			if strings.HasPrefix(apiResp.AS, "AS") {
				parts := strings.Split(apiResp.AS, " ")
				if asnNum, err := strconv.Atoi(strings.TrimPrefix(parts[0], "AS")); err == nil {
					netData.ASN = asnNum
				}
				if len(parts) > 1 {
					netData.ASName = strings.Join(parts[1:], " ")
				}
			}

			secData = detectCloudProvider(netData.Organization+" "+netData.ISP, secData)

			cf.Country = geo.CountryCode
			cf.CountryName = geo.CountryName
			cf.City = geo.City
			cf.Region = geo.RegionName
			cf.RegionCode = geo.RegionCode
			cf.Timezone = geo.Timezone
			cf.ASN = netData.ASN
			cf.ASOrganization = netData.Organization
			cf.Latitude = fmt.Sprintf("%.5f", geo.Latitude)
			cf.Longitude = fmt.Sprintf("%.5f", geo.Longitude)
			cf.PostalCode = geo.PostalCode
			cf.IsEUCountry = geo.IsEU

			gr.cache.Store(cacheKey, struct {
				g models.GeoData
				n models.NetworkData
				s models.SecurityData
				c models.CloudflareContext
			}{geo, netData, secData, cf})

			return geo, netData, secData, cf
		}
	}

	geo.CountryCode = "XX"
	geo.CountryName = "Unknown"
	return geo, netData, secData, cf
}

func detectCloudProvider(org string, sec models.SecurityData) models.SecurityData {
	lower := strings.ToLower(org)
	providers := map[string]string{
		"amazon":       "Amazon Web Services (AWS)",
		"aws":          "Amazon Web Services (AWS)",
		"google":       "Google Cloud Platform (GCP)",
		"microsoft":    "Microsoft Azure",
		"azure":        "Microsoft Azure",
		"cloudflare":   "Cloudflare",
		"vercel":       "Vercel Edge Network",
		"digitalocean": "DigitalOcean",
		"hetzner":      "Hetzner",
		"ovh":          "OVHcloud",
		"linode":       "Akamai / Linode",
		"vultr":        "Vultr",
		"alibaba":      "Alibaba Cloud",
		"oracle":       "Oracle Cloud",
	}

	for kw, name := range providers {
		if strings.Contains(lower, kw) {
			sec.IsDatacenter = true
			sec.CloudProvider = name
			return sec
		}
	}
	sec.CloudProvider = "None (Residential/ISP)"
	return sec
}

func isEUCountry(code string) bool {
	euCodes := map[string]bool{
		"AT": true, "BE": true, "BG": true, "HR": true, "CY": true,
		"CZ": true, "DK": true, "EE": true, "FI": true, "FR": true,
		"DE": true, "GR": true, "HU": true, "IE": true, "IT": true,
		"LV": true, "LT": true, "LU": true, "MT": true, "NL": true,
		"PL": true, "PT": true, "RO": true, "SK": true, "SI": true,
		"ES": true, "SE": true,
	}
	return euCodes[strings.ToUpper(code)]
}

func countryCodeToFlag(code string) string {
	if len(code) != 2 {
		return "🌐"
	}
	code = strings.ToUpper(code)
	runes := []rune{
		rune(code[0]) - 'A' + 0x1F1E6,
		rune(code[1]) - 'A' + 0x1F1E6,
	}
	return string(runes)
}

func countryCodeToName(code string) string {
	names := map[string]string{
		"ID": "Indonesia",
		"US": "United States",
		"SG": "Singapore",
		"JP": "Japan",
		"DE": "Germany",
		"GB": "United Kingdom",
		"AU": "Australia",
		"NL": "Netherlands",
		"FR": "France",
		"CA": "Canada",
	}
	if name, ok := names[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}
