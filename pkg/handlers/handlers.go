package handlers

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"ping/config"
	"ping/pkg/geo"
	"ping/pkg/models"
	"ping/pkg/storage"
	"ping/pkg/tlsinfo"
	"ping/pkg/useragent"
)

type Handler struct {
	cfg           *config.Config
	geoResolver   *geo.GeoResolver
	storageEngine *storage.StorageEngine
	startTime     time.Time
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{
		cfg:           cfg,
		geoResolver:   geo.NewGeoResolver(),
		storageEngine: storage.NewStorageEngine(),
		startTime:     time.Now(),
	}
}

// isSensitiveHeader identifies internal/deployment headers to conceal from public output
func isSensitiveHeader(name string) bool {
	lower := strings.ToLower(name)
	return lower == "x-vercel-oidc-token" ||
		lower == "x-vercel-proxy-signature" ||
		lower == "x-vercel-proxy-signature-ts" ||
		lower == "x-vercel-deployment-url" ||
		lower == "authorization" ||
		lower == "proxy-authorization"
}

// sanitizeHeaderValue scrubs secret tokens/signatures from header values
func sanitizeHeaderValue(key, val string) string {
	lowerKey := strings.ToLower(key)
	if lowerKey == "forwarded" {
		if idx := strings.Index(val, ";sig="); idx != -1 {
			end := strings.Index(val[idx+5:], ";")
			if end != -1 {
				val = val[:idx] + val[idx+5+end:]
			} else {
				val = val[:idx]
			}
		}
	}
	return val
}

// BuildPingResponse generates client-focused data response without exposing deployment/internal server metadata
func (h *Handler) BuildPingResponse(r *http.Request) (*models.PingResponse, []byte) {
	startTime := time.Now()

	clientIP, clientPort := geo.GetClientIP(r)
	clientData := geo.AnalyzeIP(clientIP, clientPort)

	// Collect & Sanitize Headers (filtering sensitive internal/deployment tokens)
	headersAll := make(map[string]string)
	headersRaw := make(map[string][]string)
	headerOrder := make([]string, 0, len(r.Header))

	for k, v := range r.Header {
		if isSensitiveHeader(k) {
			continue
		}

		sanitizedVals := make([]string, len(v))
		for i, val := range v {
			sanitizedVals[i] = sanitizeHeaderValue(k, val)
		}

		lowerK := strings.ToLower(k)
		headersAll[lowerK] = strings.Join(sanitizedVals, ", ")
		headersRaw[k] = sanitizedVals
		headerOrder = append(headerOrder, k)
	}

	sigInput := strings.Join(headerOrder, ":")
	hHash := sha256.Sum256([]byte(sigInput))
	headerSig := hex.EncodeToString(hHash[:])

	headerDetails := models.HeaderDetailsData{
		Raw:       headersRaw,
		Order:     headerOrder,
		Count:     len(headersAll),
		Signature: headerSig,
	}

	var clientHints *models.ClientHintsData
	if r.Header.Get("Sec-CH-UA") != "" || r.Header.Get("Sec-CH-UA-Platform") != "" {
		clientHints = &models.ClientHintsData{
			UA:              r.Header.Get("Sec-CH-UA"),
			Mobile:          r.Header.Get("Sec-CH-UA-Mobile") == "?1",
			Platform:        r.Header.Get("Sec-CH-UA-Platform"),
			PlatformVersion: r.Header.Get("Sec-CH-UA-Platform-Version"),
			Architecture:    r.Header.Get("Sec-CH-UA-Architecture"),
			Model:           r.Header.Get("Sec-CH-UA-Model"),
			Bitness:         r.Header.Get("Sec-CH-UA-Bitness"),
			FullVersionList: r.Header.Get("Sec-CH-UA-Full-Version-List"),
		}
	}

	geoData, netData, secData, cfContext := h.geoResolver.FetchGeoAndNetwork(r, clientIP)

	// Filter requestHeaderNames in cfContext as well
	if cfContext.RequestHeaderNames != nil {
		for k := range cfContext.RequestHeaderNames {
			if isSensitiveHeader(k) {
				delete(cfContext.RequestHeaderNames, k)
			}
		}
	}

	uaRaw := r.Header.Get("User-Agent")
	uaParsed := useragent.Parse(uaRaw)
	if uaParsed.IsAICrawler {
		secData.IsAICrawler = true
	}

	tlsData := tlsinfo.Extract(r)

	queryParams := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			queryParams[k] = v[0]
		}
	}

	cookiesMap := make(map[string]string)
	for _, c := range r.Cookies() {
		cookiesMap[c.Name] = c.Value
	}

	encodings := parseAcceptEncoding(r.Header.Get("Accept-Encoding"))
	languages := parseAcceptLanguage(r.Header.Get("Accept-Language"))

	var bodySum *models.BodySummary
	var bodyBytes []byte
	if r.Body != nil && r.ContentLength != 0 {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if len(bodyBytes) > 0 {
			md5Hash := md5.Sum(bodyBytes)
			sha1Hash := sha1.Sum(bodyBytes)
			sha256Hash := sha256.Sum256(bodyBytes)

			preview := string(bodyBytes)
			if len(preview) > 300 {
				preview = preview[:300] + "...(truncated)"
			}

			bodySum = &models.BodySummary{
				SizeBytes:   int64(len(bodyBytes)),
				ContentType: r.Header.Get("Content-Type"),
				MD5:         hex.EncodeToString(md5Hash[:]),
				SHA1:        hex.EncodeToString(sha1Hash[:]),
				SHA256:      hex.EncodeToString(sha256Hash[:]),
				Preview:     preview,
			}
		}
	}

	httpData := models.HTTPData{
		Method:          r.Method,
		Protocol:        r.Proto,
		Host:            r.Host,
		URL:             r.URL.String(),
		Path:            r.URL.Path,
		QueryRaw:        r.URL.RawQuery,
		QueryParams:     queryParams,
		Cookies:         cookiesMap,
		AcceptEncodings: encodings,
		AcceptLanguages: languages,
		ContentLength:   r.ContentLength,
		ContentType:     r.Header.Get("Content-Type"),
		BodySummary:     bodySum,
	}

	resp := &models.PingResponse{
		Headers:       headersAll,
		Cloudflare:    &cfContext,
		Client:        clientData,
		Network:       netData,
		Geo:           geoData,
		Security:      secData,
		HeaderDetails: headerDetails,
		ClientHints:   clientHints,
		TLS:           tlsData,
		HTTP:          httpData,
		UserAgent:     uaParsed,
	}

	// Persist client ping log to storage
	logID, saved := h.storageEngine.SaveRecord(resp)
	logsList := h.storageEngine.GetLogs(0)

	resp.Storage = models.StorageData{
		Saved:          saved,
		LogID:          logID,
		TotalLogsSaved: len(logsList),
	}

	_ = startTime

	return resp, bodyBytes
}

func parseAcceptEncoding(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if idx := strings.Index(trimmed, ";"); idx != -1 {
			trimmed = trimmed[:idx]
		}
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

func parseAcceptLanguage(val string) []models.LanguageQuality {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	res := make([]models.LanguageQuality, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		lang := p
		qVal := 1.0

		if idx := strings.Index(p, ";q="); idx != -1 {
			lang = p[:idx]
			if parsed, err := strconv.ParseFloat(p[idx+3:], 64); err == nil {
				qVal = parsed
			}
		}
		res = append(res, models.LanguageQuality{
			Language: lang,
			Quality:  qVal,
		})
	}
	return res
}

func (h *Handler) HandleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	resp, _ := h.BuildPingResponse(r)
	format := r.URL.Query().Get("format")

	if format == "text" || format == "ansi" {
		h.writeANSITerminal(w, resp)
		return
	}

	h.writeJSON(w, resp)
}

func (h *Handler) HandleJSON(w http.ResponseWriter, r *http.Request) {
	resp, _ := h.BuildPingResponse(r)
	h.writeJSON(w, resp)
}

func (h *Handler) HandleIP(w http.ResponseWriter, r *http.Request) {
	ip, port := geo.GetClientIP(r)
	if r.URL.Query().Get("format") == "json" {
		h.writeJSON(w, geo.AnalyzeIP(ip, port))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, ip)
}

func (h *Handler) HandleHeaders(w http.ResponseWriter, r *http.Request) {
	resp, _ := h.BuildPingResponse(r)
	h.writeJSON(w, resp.Headers)
}

func (h *Handler) HandleHeaderByKey(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/header/")
	if key == "" {
		http.Error(w, "Header name required", http.StatusBadRequest)
		return
	}
	if isSensitiveHeader(key) {
		http.Error(w, "Access to sensitive header denied", http.StatusForbidden)
		return
	}

	val := r.Header.Get(key)
	if val == "" {
		for k, v := range r.Header {
			if strings.EqualFold(k, key) && len(v) > 0 {
				val = v[0]
				break
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, sanitizeHeaderValue(key, val))
}

func (h *Handler) HandleUserAgent(w http.ResponseWriter, r *http.Request) {
	resp, _ := h.BuildPingResponse(r)
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, resp.UserAgent.Raw)
		return
	}
	h.writeJSON(w, resp.UserAgent)
}

func (h *Handler) HandleGeo(w http.ResponseWriter, r *http.Request) {
	resp, _ := h.BuildPingResponse(r)
	h.writeJSON(w, resp.Geo)
}

func (h *Handler) HandleNetwork(w http.ResponseWriter, r *http.Request) {
	resp, _ := h.BuildPingResponse(r)
	h.writeJSON(w, resp.Network)
}

func (h *Handler) HandleSecurity(w http.ResponseWriter, r *http.Request) {
	resp, _ := h.BuildPingResponse(r)
	h.writeJSON(w, resp.Security)
}

func (h *Handler) HandleTLS(w http.ResponseWriter, r *http.Request) {
	resp, _ := h.BuildPingResponse(r)
	if resp.TLS == nil {
		h.writeJSON(w, map[string]string{"message": "No TLS session detected (Plain HTTP)"})
		return
	}
	h.writeJSON(w, resp.TLS)
}

// HandleLogs returns list of saved client ping logs
func (h *Handler) HandleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil {
			limit = val
		}
	}
	logs := h.storageEngine.GetLogs(limit)
	h.writeJSON(w, map[string]interface{}{
		"total_logs": len(logs),
		"limit":      limit,
		"logs":       logs,
	})
}

// HandleClearLogs clears stored client ping logs
func (h *Handler) HandleClearLogs(w http.ResponseWriter, r *http.Request) {
	h.storageEngine.ClearLogs()
	h.writeJSON(w, map[string]interface{}{
		"message": "Client ping logs cleared successfully",
		"status":  "ok",
	})
}

func (h *Handler) HandleEcho(w http.ResponseWriter, r *http.Request) {
	resp, bodyBytes := h.BuildPingResponse(r)
	echoData := map[string]interface{}{
		"method":       r.Method,
		"url":          r.URL.String(),
		"headers":      resp.Headers,
		"header_order": resp.HeaderDetails.Order,
		"query":        resp.HTTP.QueryParams,
		"cookies":      resp.HTTP.Cookies,
		"client":       resp.Client,
		"body_raw":     string(bodyBytes),
		"body_size":    len(bodyBytes),
	}
	h.writeJSON(w, echoData)
}

func (h *Handler) HandleDNS(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Query param 'domain' is required, e.g., /dns?domain=google.com", http.StatusBadRequest)
		return
	}

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	result := models.DNSLookupResult{Domain: domain}

	ips, err := net.LookupHost(domain)
	if err == nil {
		for _, ip := range ips {
			if net.ParseIP(ip).To4() != nil {
				result.A = append(result.A, ip)
			} else {
				result.AAAA = append(result.AAAA, ip)
			}
		}
	}

	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != domain+"." {
		result.CNAME = cname
	}

	mxs, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxs {
			result.MX = append(result.MX, fmt.Sprintf("%s (pref %d)", mx.Host, mx.Pref))
		}
	}

	txts, err := net.LookupTXT(domain)
	if err == nil {
		result.TXT = txts
	}

	nss, err := net.LookupNS(domain)
	if err == nil {
		for _, ns := range nss {
			result.NS = append(result.NS, ns.Host)
		}
	}

	if len(result.A) == 0 && len(result.AAAA) == 0 && err != nil {
		result.Error = err.Error()
	}

	h.writeJSON(w, result)
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, map[string]interface{}{
		"status": "ok",
		"pong":   true,
		"time":   time.Now().UTC(),
	})
}

func (h *Handler) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
}

func (h *Handler) writeANSITerminal(w http.ResponseWriter, resp *models.PingResponse) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	const (
		reset   = "\033[0m"
		bold    = "\033[1m"
		cyan    = "\033[36m"
		green   = "\033[32m"
		yellow  = "\033[33m"
		magenta = "\033[35m"
		blue    = "\033[34m"
	)

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s%s🚀 PING DATA ENGINE — CLIENT DATA INSPECTOR%s\n", bold, cyan, reset))
	buf.WriteString(fmt.Sprintf("%s---------------------------------------------------%s\n", blue, reset))

	buf.WriteString(fmt.Sprintf("%s🌐 CLIENT IP    :%s %s%s%s (%s, PTR: %s)\n", bold, reset, green, resp.Client.IP, reset, resp.Client.IPVersion, resp.Client.ReverseDNS))
	buf.WriteString(fmt.Sprintf("%s📍 LOCATION     :%s %s %s, %s (%s, Lat: %.4f, Lon: %.4f)\n", bold, reset, resp.Geo.FlagEmoji, resp.Geo.City, resp.Geo.CountryName, resp.Geo.RegionName, resp.Geo.Latitude, resp.Geo.Longitude))
	buf.WriteString(fmt.Sprintf("%s🏢 NETWORK (ASN):%s AS%d %s (ISP: %s)\n", bold, reset, resp.Network.ASN, resp.Network.Organization, resp.Network.ISP))
	buf.WriteString(fmt.Sprintf("%s🛡️ RISK / CLOUD :%s Datacenter: %t, Provider: %s, Threat: %s\n", bold, reset, resp.Security.IsDatacenter, resp.Security.CloudProvider, resp.Security.ThreatLevel))
	buf.WriteString(fmt.Sprintf("%s💾 LOG STORAGE  :%s LogID: %s (Total Saved: %d)\n", bold, reset, resp.Storage.LogID, resp.Storage.TotalLogsSaved))
	buf.WriteString(fmt.Sprintf("%s💻 USER AGENT   :%s %s (%s / %s)\n", bold, reset, resp.UserAgent.Browser, resp.UserAgent.OS, resp.UserAgent.DeviceType))
	buf.WriteString(fmt.Sprintf("%s🔒 PROTOCOL     :%s %s\n", bold, reset, resp.HTTP.Protocol))

	if resp.TLS != nil {
		buf.WriteString(fmt.Sprintf("%s🔑 TLS VERSION  :%s %s (%s)\n", bold, reset, resp.TLS.Version, resp.TLS.CipherSuite))
	}

	buf.WriteString(fmt.Sprintf("\n%s📋 REQUEST HEADERS (%d headers, Hash: %s):%s\n", bold, resp.HeaderDetails.Count, resp.HeaderDetails.Signature[:12], reset))
	keys := make([]string, 0, len(resp.Headers))
	for k := range resp.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		buf.WriteString(fmt.Sprintf("  %s%-26s%s: %s\n", yellow, k, reset, resp.Headers[k]))
	}

	buf.WriteString(fmt.Sprintf("%s---------------------------------------------------%s\n", blue, reset))

	w.Write(buf.Bytes())
}
