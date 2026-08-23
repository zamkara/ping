package useragent

import (
	"strings"

	"ping/pkg/models"
)

// Parse inspects raw user-agent string and returns deep UserAgentData
func Parse(ua string) models.UserAgentData {
	info := models.UserAgentData{
		Raw:            ua,
		Browser:        "Unknown",
		Version:        "Unknown",
		OS:             "Unknown",
		DeviceType:     "Desktop",
		Engine:         "Unknown",
		IsBot:          false,
		IsAICrawler:    false,
		IsSearchEngine: false,
		IsCLI:          false,
		IsHeadless:     false,
	}

	if ua == "" {
		return info
	}

	lowerUA := strings.ToLower(ua)

	// Check AI Crawlers
	aiCrawlers := map[string]string{
		"gptbot":          "OpenAI GPTBot",
		"chatgpt-user":    "OpenAI ChatGPT User",
		"claudebot":       "Anthropic ClaudeBot",
		"claude-web":      "Anthropic Claude-Web",
		"perplexitybot":   "Perplexity AI Bot",
		"bytespider":      "ByteDance ByteSpider",
		"ccbot":           "Common Crawl CCBot",
		"google-extended": "Google Gemini Crawler",
		"cohere-ai":       "Cohere AI Bot",
	}

	for kw, name := range aiCrawlers {
		if strings.Contains(lowerUA, kw) {
			info.IsBot = true
			info.IsAICrawler = true
			info.Browser = name
			info.DeviceType = "AI Search & Scraper Bot"
			return info
		}
	}

	// Check Search Engine Crawlers
	searchBots := map[string]string{
		"googlebot":    "Google Search Engine Bot",
		"bingbot":      "Microsoft BingBot",
		"yandexbot":    "Yandex Search Bot",
		"duckduckbot":  "DuckDuckGo Bot",
		"baiduspider":  "Baidu Search Spider",
		"slurp":        "Yahoo Slurp Bot",
		"sogou":        "Sogou Spider",
		"exabot":       "Exalead Bot",
		"facebookexternalhit": "Facebook Crawler",
		"twitterbot":   "Twitter Card Bot",
		"discordbot":   "Discord Embed Bot",
		"telegrambot":  "Telegram Link Preview",
	}

	for kw, name := range searchBots {
		if strings.Contains(lowerUA, kw) {
			info.IsBot = true
			info.IsSearchEngine = true
			info.Browser = name
			info.DeviceType = "Search Engine Crawler"
			return info
		}
	}

	// Check Headless Automation Frameworks
	if strings.Contains(lowerUA, "headlesschrome") || strings.Contains(lowerUA, "phantomjs") || strings.Contains(lowerUA, "selenium") || strings.Contains(lowerUA, "puppeteer") || strings.Contains(lowerUA, "playwright") {
		info.IsHeadless = true
		info.DeviceType = "Headless Browser Automation"
	}

	// Check CLI tools
	cliTools := map[string]string{
		"curl":            "curl",
		"wget":            "Wget",
		"postmanruntime":  "Postman",
		"httpie":          "HTTPie",
		"python":          "Python-requests",
		"go-http-client":  "Go HTTP Client",
		"axios":           "Axios JS",
		"node-fetch":      "Node.js Fetch",
		"java":            "Java HTTP Client",
		"ruby":            "Ruby Net::HTTP",
		"php":             "PHP cURL",
		"insomnia":        "Insomnia REST Client",
	}

	for kw, name := range cliTools {
		if strings.Contains(lowerUA, kw) {
			info.Browser = name
			info.DeviceType = "CLI Tool / API Client"
			info.IsCLI = true
			info.Version = extractVersion(ua, kw)
			return info
		}
	}

	// OS Detection
	if strings.Contains(lowerUA, "windows nt 10.0") {
		info.OS = "Windows"
		info.OSVersion = "10 / 11"
	} else if strings.Contains(lowerUA, "windows") {
		info.OS = "Windows"
	} else if strings.Contains(lowerUA, "macintosh") || strings.Contains(lowerUA, "mac os x") {
		info.OS = "macOS"
		info.OSVersion = extractVersion(ua, "Mac OS X ")
	} else if strings.Contains(lowerUA, "android") {
		info.OS = "Android"
		info.OSVersion = extractVersion(ua, "Android ")
		info.DeviceType = "Mobile"
	} else if strings.Contains(lowerUA, "iphone") || strings.Contains(lowerUA, "ipad") || strings.Contains(lowerUA, "ipod") {
		info.OS = "iOS"
		info.OSVersion = extractVersion(ua, "OS ")
		if strings.Contains(lowerUA, "ipad") {
			info.DeviceType = "Tablet"
		} else {
			info.DeviceType = "Mobile"
		}
	} else if strings.Contains(lowerUA, "linux") {
		info.OS = "Linux"
	}

	if strings.Contains(lowerUA, "mobile") && info.DeviceType == "Desktop" {
		info.DeviceType = "Mobile"
	}

	// Engine & Browser
	if strings.Contains(lowerUA, "applewebkit") {
		info.Engine = "WebKit"
	} else if strings.Contains(lowerUA, "gecko") && !strings.Contains(lowerUA, "like gecko") {
		info.Engine = "Gecko"
	} else if strings.Contains(lowerUA, "trident") {
		info.Engine = "Trident"
	}

	if !info.IsBot {
		if strings.Contains(lowerUA, "edg/") || strings.Contains(lowerUA, "edge/") {
			info.Browser = "Microsoft Edge"
			info.Engine = "Blink"
			info.Version = extractVersion(ua, "Edg/")
		} else if strings.Contains(lowerUA, "opr/") || strings.Contains(lowerUA, "opera") {
			info.Browser = "Opera"
			info.Engine = "Blink"
			info.Version = extractVersion(ua, "OPR/")
		} else if strings.Contains(lowerUA, "chrome/") || strings.Contains(lowerUA, "crios/") {
			info.Browser = "Google Chrome"
			info.Engine = "Blink"
			info.Version = extractVersion(ua, "Chrome/")
			if info.Version == "" {
				info.Version = extractVersion(ua, "CriOS/")
			}
		} else if strings.Contains(lowerUA, "firefox/") || strings.Contains(lowerUA, "fxios/") {
			info.Browser = "Mozilla Firefox"
			info.Engine = "Gecko"
			info.Version = extractVersion(ua, "Firefox/")
		} else if strings.Contains(lowerUA, "safari/") && !strings.Contains(lowerUA, "chrome") {
			info.Browser = "Apple Safari"
			info.Version = extractVersion(ua, "Version/")
		}
	}

	return info
}

func extractVersion(ua, prefix string) string {
	idx := strings.Index(strings.ToLower(ua), strings.ToLower(prefix))
	if idx == -1 {
		return ""
	}
	start := idx + len(prefix)
	end := strings.IndexAny(ua[start:], " ()\t\n;_")
	if end == -1 {
		return ua[start:]
	}
	return strings.ReplaceAll(ua[start:start+end], "_", ".")
}
