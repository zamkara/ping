package models

import "time"

// PingResponse is the master detailed JSON response
type PingResponse struct {
	Headers       map[string]string      `json:"headers"` // Matches Hiiruki top-level headers
	Cloudflare    *CloudflareContext     `json:"cf"`      // Matches Hiiruki top-level cf
	Vercel        *VercelContext         `json:"vercel,omitempty"` // Vercel Edge/Serverless context
	Client        ClientData             `json:"client"`
	Network       NetworkData            `json:"network"`
	Geo           GeoData                `json:"geo"`
	Security      SecurityData           `json:"security"`
	HeaderDetails HeaderDetailsData    `json:"header_details"`
	ClientHints   *ClientHintsData       `json:"client_hints,omitempty"`
	TLS           *TLSData               `json:"tls,omitempty"`
	HTTP          HTTPData               `json:"http"`
	UserAgent     UserAgentData          `json:"user_agent"`
	Server        ServerData             `json:"server"`
}

// VercelContext metadata injected when running on Vercel Serverless / Edge Network
type VercelContext struct {
	ID            string `json:"id,omitempty"`
	Region        string `json:"region,omitempty"`
	Country       string `json:"country,omitempty"`
	RegionCode    string `json:"region_code,omitempty"`
	City          string `json:"city,omitempty"`
	Latitude      string `json:"latitude,omitempty"`
	Longitude     string `json:"longitude,omitempty"`
	Timezone      string `json:"timezone,omitempty"`
	ASNumber      int    `json:"as_number,omitempty"`
	DeploymentURL string `json:"deployment_url,omitempty"`
	IsVercel      bool   `json:"is_vercel"`
}

// CloudflareContext exact 100% complete Cloudflare Workers cf object
type CloudflareContext struct {
	HTTPProtocol               string                 `json:"httpProtocol"`
	ClientAcceptEncoding       string                 `json:"clientAcceptEncoding"`
	RequestPriority            string                 `json:"requestPriority"`
	EdgeRequestKeepAliveStatus int                    `json:"edgeRequestKeepAliveStatus"`
	RequestHeaderNames         map[string]interface{} `json:"requestHeaderNames"`
	ClientTcpRtt               int                    `json:"clientTcpRtt"`
	ClientQuicRtt              int                    `json:"clientQuicRtt"`
	Colo                       string                 `json:"colo"`
	ASN                        int                    `json:"asn"`
	ASOrganization             string                 `json:"asOrganization"`
	Country                    string                 `json:"country"`
	CountryName                string                 `json:"countryName,omitempty"`
	IsEUCountry                bool                   `json:"isEUCountry"`
	City                       string                 `json:"city"`
	Continent                  string                 `json:"continent"`
	Region                     string                 `json:"region"`
	RegionCode                 string                 `json:"regionCode"`
	Timezone                   string                 `json:"timezone"`
	Longitude                  string                 `json:"longitude"`
	Latitude                   string                 `json:"latitude"`
	PostalCode                 string                 `json:"postalCode"`
	TLSVersion                 string                 `json:"tlsVersion"`
	TLSCipher                  string                 `json:"tlsCipher"`
	TLSClientRandom            string                 `json:"tlsClientRandom"`
	TLSClientCiphersSha1       string                 `json:"tlsClientCiphersSha1"`
	TLSClientExtensionsSha1    string                 `json:"tlsClientExtensionsSha1"`
	TLSClientExtensionsSha1Le  string                 `json:"tlsClientExtensionsSha1Le"`
	TLSExportedAuthenticator   map[string]string      `json:"tlsExportedAuthenticator"`
	TLSClientHelloLength       string                 `json:"tlsClientHelloLength"`
	TLSClientAuth              map[string]interface{} `json:"tlsClientAuth"`
	VerifiedBotCategory        string                 `json:"verifiedBotCategory"`
	EdgeL4                     map[string]interface{} `json:"edgeL4"`
}

// ClientData deep connection details
type ClientData struct {
	IP              string `json:"ip"`
	Port            string `json:"port"`
	IPVersion       string `json:"ip_version"` // "IPv4" or "IPv6"
	ReverseDNS      string `json:"reverse_dns,omitempty"`
	IsPrivate       bool   `json:"is_private"`
	IsLoopback      bool   `json:"is_loopback"`
	IsMulticast     bool   `json:"is_multicast"`
	IsGlobalUnicast bool   `json:"is_global_unicast"`
}

// NetworkData ASN & Autonomous System details
type NetworkData struct {
	ASN          int    `json:"asn"`
	ASName       string `json:"as_name"`
	ASDomain     string `json:"as_domain,omitempty"`
	NetworkCIDR  string `json:"network_cidr,omitempty"`
	RIR          string `json:"rir,omitempty"`
	ISP          string `json:"isp"`
	Organization string `json:"organization"`
}

// GeoData complete Geolocation data
type GeoData struct {
	IP            string  `json:"ip"`
	CountryCode   string  `json:"country_code"`
	CountryName   string  `json:"country_name"`
	FlagEmoji     string  `json:"flag_emoji,omitempty"`
	ContinentCode string  `json:"continent_code,omitempty"`
	ContinentName string  `json:"continent_name,omitempty"`
	RegionCode    string  `json:"region_code"`
	RegionName    string  `json:"region_name"`
	City          string  `json:"city"`
	PostalCode    string  `json:"postal_code,omitempty"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Timezone      string  `json:"timezone"`
	Currency      string  `json:"currency,omitempty"`
	CallingCode   string  `json:"calling_code,omitempty"`
	IsEU          bool    `json:"is_eu"`
}

// SecurityData threat & proxy detection analysis
type SecurityData struct {
	IsProxy        bool   `json:"is_proxy"`
	IsVPN          bool   `json:"is_vpn"`
	IsTor          bool   `json:"is_tor"`
	IsDatacenter   bool   `json:"is_datacenter"`
	IsKnownBot     bool   `json:"is_known_bot"`
	IsAICrawler    bool   `json:"is_ai_crawler"`
	CloudProvider  string `json:"cloud_provider,omitempty"` // AWS, GCP, Cloudflare, Vercel, DigitalOcean, etc.
	ThreatLevel    string `json:"threat_level"`             // Low, Medium, High
}

// HeaderDetailsData advanced header inspection
type HeaderDetailsData struct {
	Raw       map[string][]string `json:"raw"`
	Order     []string            `json:"order"`
	Count     int                 `json:"count"`
	Signature string              `json:"signature"` // SHA256 of header order & keys
}

// ClientHintsData browser client hints (Sec-CH-UA-*)
type ClientHintsData struct {
	UA              string `json:"ua,omitempty"`
	Mobile          bool   `json:"mobile,omitempty"`
	Platform        string `json:"platform,omitempty"`
	PlatformVersion string `json:"platform_version,omitempty"`
	Architecture    string `json:"architecture,omitempty"`
	Model           string `json:"model,omitempty"`
	Bitness         string `json:"bitness,omitempty"`
	FullVersionList string `json:"full_version_list,omitempty"`
}

// TLSData transport layer security inspection
type TLSData struct {
	Version          string   `json:"version"`
	CipherSuite      string   `json:"cipher_suite"`
	SNI              string   `json:"sni,omitempty"`
	ALPN             string   `json:"alpn,omitempty"`
	PeerCertificates []string `json:"peer_certificates,omitempty"`
	JA3Hash          string   `json:"ja3_hash,omitempty"`
	JA4Hash          string   `json:"ja4_hash,omitempty"`
}

// HTTPData request protocol inspection
type HTTPData struct {
	Method           string            `json:"method"`
	Protocol         string            `json:"protocol"`
	Host             string            `json:"host"`
	URL              string            `json:"url"`
	Path             string            `json:"path"`
	QueryRaw         string            `json:"query_raw,omitempty"`
	QueryParams      map[string]string `json:"query_params,omitempty"`
	Cookies          map[string]string `json:"cookies,omitempty"`
	AcceptEncodings  []string          `json:"accept_encodings,omitempty"`
	AcceptLanguages  []LanguageQuality `json:"accept_languages,omitempty"`
	ContentLength    int64             `json:"content_length"`
	ContentType      string            `json:"content_type,omitempty"`
	BodySummary      *BodySummary      `json:"body_summary,omitempty"`
}

// LanguageQuality parsed Accept-Language quality scores
type LanguageQuality struct {
	Language string  `json:"language"`
	Quality  float64 `json:"q"`
}

// BodySummary request payload info
type BodySummary struct {
	SizeBytes   int64  `json:"size_bytes"`
	ContentType string `json:"content_type"`
	MD5         string `json:"md5"`
	SHA1        string `json:"sha1"`
	SHA256      string `json:"sha256"`
	Preview     string `json:"preview,omitempty"`
}

// UserAgentData parsed UA intelligence
type UserAgentData struct {
	Raw            string `json:"raw"`
	Browser        string `json:"browser"`
	Version        string `json:"version"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version,omitempty"`
	DeviceType     string `json:"device_type"` // Desktop, Mobile, Tablet, Bot, CLI, Headless
	Engine         string `json:"engine,omitempty"`
	IsBot          bool   `json:"is_bot"`
	IsAICrawler    bool   `json:"is_ai_crawler"`
	IsSearchEngine bool   `json:"is_search_engine"`
	IsCLI          bool   `json:"is_cli"`
	IsHeadless     bool   `json:"is_headless"`
}

// ServerData server execution diagnostics
type ServerData struct {
	RequestID        string    `json:"request_id"`
	Hostname         string    `json:"hostname"`
	Time             time.Time `json:"time"`
	TimestampUnixMs  int64     `json:"timestamp_unix_ms"`
	TimestampUnixNs  int64     `json:"timestamp_unix_ns"`
	ProcessingTimeUs int64     `json:"processing_time_us"`
	Uptime           string    `json:"uptime"`
	GoVersion        string    `json:"go_version"`
	Goroutines       int       `json:"goroutines"`
	MemoryAllocMB    float64   `json:"memory_alloc_mb"`
}

// LatencyPingMessage for WebSocket live latency testing
type LatencyPingMessage struct {
	Type      string `json:"type"`
	Seq       int64  `json:"seq"`
	ClientTs  int64  `json:"client_ts"`
	ServerTs  int64  `json:"server_ts"`
	ClientIP  string `json:"client_ip,omitempty"`
	Location  string `json:"location,omitempty"`
}

// DNSLookupResult for DNS utility endpoint
type DNSLookupResult struct {
	Domain string   `json:"domain"`
	A      []string `json:"a,omitempty"`
	AAAA   []string `json:"aaaa,omitempty"`
	CNAME  string   `json:"cname,omitempty"`
	MX     []string `json:"mx,omitempty"`
	TXT    []string `json:"txt,omitempty"`
	NS     []string `json:"ns,omitempty"`
	Error  string   `json:"error,omitempty"`
}
