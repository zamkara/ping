package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port         int
	Env          string
	Version      string
	TrustProxies bool
}

func Load() *Config {
	port := 8080
	if p := os.Getenv("PORT"); p != "" {
		if val, err := strconv.Atoi(p); err == nil {
			port = val
		}
	}

	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "production"
	}

	version := os.Getenv("APP_VERSION")
	if version == "" {
		version = "1.0.0"
	}

	trustProxies := true
	if tp := os.Getenv("TRUST_PROXIES"); tp == "false" || tp == "0" {
		trustProxies = false
	}

	return &Config{
		Port:         port,
		Env:          env,
		Version:      version,
		TrustProxies: trustProxies,
	}
}
