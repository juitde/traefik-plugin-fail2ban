// Package traefik_plugin_fail2ban plugin for traefik reverse proxy.
package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zerodha/logf"
)

type configIPSpec struct {
	IP []string `yaml:"ip"`
}

// Config plugin configuration.
type Config struct {
	Enabled       bool            `yaml:"enabled"`
	AlwaysAllowed configIPSpec    `yaml:"alwaysAllowed"`
	AlwaysDenied  configIPSpec    `yaml:"alwaysDenied"`
	LogLevel      string          `yaml:"logLevel"`
	Rules         configRules     `yaml:"rules"`
	AbuseIPDB     configAbuseIPDB `yaml:"abuseIpdb"`
}

type configAbuseIPDB struct {
	Enabled             bool   `yaml:"enabled"`
	APIKey              string `yaml:"apiKey"`
	ConfidenceThreshold int    `yaml:"confidenceThreshold"`
	MaxAgeInDays        int    `yaml:"maxAgeInDays"`
	Timeout             string `yaml:"timeout"`
}

type configRules struct {
	FindTime         string         `yaml:"findTime"`
	BanTime          string         `yaml:"banTime"`
	MaliciousBanTime string         `yaml:"maliciousBanTime"`
	MaxRetries       uint32         `yaml:"maxRetries"`
	Response         configResponse `yaml:"response"`
}

type configResponse struct {
	StatusCodes []string `yaml:"statusCodes"`
	ErrorCode   int      `yaml:"errorCode"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:       true,
		AlwaysAllowed: configIPSpec{},
		AlwaysDenied:  configIPSpec{},
		LogLevel:      "INFO",
		Rules: configRules{
			FindTime:   "10m",
			BanTime:    "3h",
			MaxRetries: 4,
			Response: configResponse{
				StatusCodes: strings.Split("400-499", ","),
				ErrorCode:   http.StatusForbidden,
			},
		},
		AbuseIPDB: configAbuseIPDB{
			Enabled:             false,
			APIKey:              "",
			ConfidenceThreshold: 75,
			MaxAgeInDays:        90,
			Timeout:             "5s",
		},
	}
}

type responseRules struct {
	StatusCode *regexp.Regexp
}

// AbuseIPDBResponse represents the response from AbuseIPDB API.
type AbuseIPDBResponse struct {
	Data struct {
		IPAddress             string `json:"ipAddress"`
		IsPublic              bool   `json:"isPublic"`
		IPVersion             int    `json:"ipVersion"`
		IsWhitelisted         bool   `json:"isWhitelisted"`
		AbuseConfidenceRating int    `json:"abuseConfidenceScore"`
		CountryCode           string `json:"countryCode"`
		CountryName           string `json:"countryName"`
		UsageType             string `json:"usageType"`
		ISP                   string `json:"isp"`
		Domain                string `json:"domain"`
		TotalReports          int    `json:"totalReports"`
		NumDistinctUsers      int    `json:"numDistinctUsers"`
		LastReportedAt        string `json:"lastReportedAt"`
	} `json:"data"`
}

// Fail2Ban plugin data structure.
type Fail2Ban struct {
	next                         http.Handler
	name                         string
	cache                        *Cache
	logger                       *logf.Logger
	enabled                      bool
	staticAllowedIPNets          []*net.IPNet
	staticDeniedIPNets           []*net.IPNet
	findTime                     time.Duration
	banTime                      time.Duration
	maliciousBanTime             time.Duration
	maxRetries                   uint32
	responseRules                responseRules
	errorCode                    int
	abuseIPDBEnabled             bool
	abuseIPDBAPIKey              string
	abuseIPDBConfidenceThreshold int
	abuseIPDBMaxAgeInDays        int
	abuseIPDBTimeout             time.Duration
	httpClient                   *http.Client
}

// checkIPWithAbuseIPDB checks if an IP is malicious using AbuseIPDB API.
func (a *Fail2Ban) checkIPWithAbuseIPDB(ip string) (bool, error) {
	if !a.abuseIPDBEnabled || a.abuseIPDBAPIKey == "" {
		return false, nil
	}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=%d&verbose",
		ip, a.abuseIPDBMaxAgeInDays)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create AbuseIPDB request: %w", err)
	}

	req.Header.Set("Key", a.abuseIPDBAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to query AbuseIPDB: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			a.logger.Error("Failed to close AbuseIPDB response body", "error", closeErr.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("AbuseIPDB API returned status %d: %s", resp.StatusCode, string(body))
	}

	var abuseResp AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&abuseResp); err != nil {
		return false, fmt.Errorf("failed to decode AbuseIPDB response: %w", err)
	}

	isMalicious := abuseResp.Data.AbuseConfidenceRating >= a.abuseIPDBConfidenceThreshold

	a.logger.Info("AbuseIPDB check completed",
		"remoteIP", ip,
		"confidenceRating", abuseResp.Data.AbuseConfidenceRating,
		"threshold", a.abuseIPDBConfidenceThreshold,
		"isMalicious", isMalicious,
		"countryCode", abuseResp.Data.CountryCode,
		"totalReports", abuseResp.Data.TotalReports,
	)

	return isMalicious, nil
}

func parseConfigIPList(specs []string) []*net.IPNet {
	parsedIPNets := make([]*net.IPNet, 0, 10)

	for _, spec := range specs {
		if !strings.Contains(spec, "/") {
			if strings.Contains(spec, ":") {
				spec = fmt.Sprintf("%s/64", spec)
			} else {
				spec = fmt.Sprintf("%s/32", spec)
			}
		}
		_, ipNet, err := net.ParseCIDR(spec)
		if err != nil {
			fmt.Printf("Error: %+v\n", err)
			continue
		}

		parsedIPNets = append(parsedIPNets, ipNet)
	}

	return parsedIPNets
}

func parseDuration(spec string, fallback time.Duration) time.Duration {
	val, err := time.ParseDuration(spec)
	if err != nil {
		return fallback
	}

	return val
}

func removeDuplicates[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	var list []T
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func parseResponseRules(config configResponse) responseRules {
	var statusCodes []int
	for _, val := range config.StatusCodes {
		if strings.Contains(val, "-") {
			r := strings.Split(val, "-")
			a, _ := strconv.Atoi(r[0])
			b, _ := strconv.Atoi(r[1])
			for i := a; i <= b; i++ {
				statusCodes = append(statusCodes, i)
			}
		} else {
			a, _ := strconv.Atoi(val)
			statusCodes = append(statusCodes, a)
		}
	}
	sort.Ints(statusCodes)
	statusCodes = removeDuplicates[int](statusCodes)
	cleanedStatusCodes := make([]string, 0, 100)
	for _, k := range statusCodes {
		cleanedStatusCodes = append(cleanedStatusCodes, strconv.Itoa(k))
	}

	statusCodesRegex := regexp.MustCompile(fmt.Sprintf("^(%s)$", strings.Join(cleanedStatusCodes, "|")))

	return responseRules{
		StatusCode: statusCodesRegex,
	}
}

// New creates a Fail2Ban plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	httpClient := &http.Client{
		Timeout: parseDuration(config.AbuseIPDB.Timeout, 5*time.Second),
	}

	return &Fail2Ban{
		next:                         next,
		name:                         name,
		cache:                        NewCache(),
		logger:                       NewLogger(config.LogLevel),
		enabled:                      config.Enabled,
		staticAllowedIPNets:          parseConfigIPList(config.AlwaysAllowed.IP),
		staticDeniedIPNets:           parseConfigIPList(config.AlwaysDenied.IP),
		findTime:                     parseDuration(config.Rules.FindTime, 10*time.Minute),
		banTime:                      parseDuration(config.Rules.BanTime, 3*time.Hour),
		maliciousBanTime:             parseDuration(config.Rules.MaliciousBanTime, 24*time.Hour),
		maxRetries:                   config.Rules.MaxRetries,
		responseRules:                parseResponseRules(config.Rules.Response),
		errorCode:                    config.Rules.Response.ErrorCode,
		abuseIPDBEnabled:             config.AbuseIPDB.Enabled,
		abuseIPDBAPIKey:              config.AbuseIPDB.APIKey,
		abuseIPDBConfidenceThreshold: config.AbuseIPDB.ConfidenceThreshold,
		abuseIPDBMaxAgeInDays:        config.AbuseIPDB.MaxAgeInDays,
		abuseIPDBTimeout:             parseDuration(config.AbuseIPDB.Timeout, 5*time.Second),
		httpClient:                   httpClient,
	}, nil
}

// checkStaticDeniedIPs checks if the IP is in the static denied list.
func (a *Fail2Ban) checkStaticDeniedIPs(remoteIP string, responseWriter http.ResponseWriter) bool {
	for _, ipNet := range a.staticDeniedIPNets {
		a.logger.Debug("Checking if remoteIP is in static denied Netmask.", "remoteIP", remoteIP, "netmask", ipNet, "phase", "check_request")
		if ipNet.Contains(net.ParseIP(remoteIP)) {
			a.logger.Info("RemoteIP was found in staticDeniedIPNets. Access Denied.", "remoteIP", remoteIP, "staticDeniedIPNets", a.staticDeniedIPNets, "phase", "check_request", "status", "denied")
			responseWriter.WriteHeader(a.errorCode)
			return true
		}
	}
	return false
}

// checkStaticAllowedIPs checks if the IP is in the static allowed list.
func (a *Fail2Ban) checkStaticAllowedIPs(remoteIP string) bool {
	for _, ipNet := range a.staticAllowedIPNets {
		a.logger.Debug("Checking if remoteIP is in static allowed Netmask.", "remoteIP", remoteIP, "netmask", ipNet, "phase", "check_request")
		if ipNet.Contains(net.ParseIP(remoteIP)) {
			a.logger.Info("RemoteIP was found in staticAllowedIPNets. Access Granted.", "remoteIP", remoteIP, "staticAllowedIPNets", a.staticAllowedIPNets, "phase", "check_request", "status", "granted")
			return true
		}
	}
	return false
}

// handleBanLogic handles the banning logic when max retries are exceeded.
func (a *Fail2Ban) handleBanLogic(remoteIP string, request *http.Request, entry *CacheEntry) {
	// Check if IP is malicious using AbuseIPDB
	isMalicious := false
	banTime := a.banTime
	if a.abuseIPDBEnabled {
		malicious, err := a.checkIPWithAbuseIPDB(remoteIP)
		if err != nil {
			a.logger.Error("Failed to check IP with AbuseIPDB, using standard ban time",
				"remoteIP", remoteIP, "error", err.Error())
		} else {
			isMalicious = malicious
			banTime = a.maliciousBanTime
		}
	}

	a.logger.Info("Client has been banned.",
		"remoteIP", remoteIP,
		"maxRetries", a.maxRetries,
		"host", request.Host,
		"banTime", banTime,
		"findTime", a.findTime,
		"phase", "check_request",
		"status", "denied",
		"malicious", isMalicious)

	entry.IssueBan(isMalicious)
}

func (a *Fail2Ban) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if !a.enabled {
		a.logger.Debug("Handler is not enabled. Skipping.", "phase", "accept_request")
		a.next.ServeHTTP(responseWriter, request)
		return
	}
	a.logger.Debug("Handler is enabled. Analyzing request.", "phase", "accept_request")

	remoteIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		a.logger.Error("Failed to detect remoteIP from request.RemoteAddr.", "request.RemoteAddr", request.RemoteAddr, "phase", "accept_request")
		responseWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Check static denied IPs
	if a.checkStaticDeniedIPs(remoteIP, responseWriter) {
		return
	}

	// Check static allowed IPs
	if a.checkStaticAllowedIPs(remoteIP) {
		a.next.ServeHTTP(responseWriter, request)
		return
	}

	requestTime := time.Now()
	a.cache.CleanEntries(a.findTime, a.banTime, a.maliciousBanTime)
	a.cache.CleanEntryIfPossible(remoteIP, a.findTime, a.banTime, a.maliciousBanTime, requestTime)
	entry := a.cache.CreateEntry(remoteIP, requestTime)

	if entry.GetTimesSeen() >= a.maxRetries && !entry.IsBanned() {
		a.handleBanLogic(remoteIP, request, entry)
	}

	if entry.IsBanned() {
		a.logger.Debug("Client is still banned.", "remoteIP", remoteIP, "phase", "check_request", "status", "denied")
		responseWriter.WriteHeader(a.errorCode)
		return
	}
	defer entry.SetLastSeen(requestTime)

	// At this stage request rules might be checked (NOT YET IMPLEMENTED)

	// Response rules will be checked in the wrapped response writer
	wrappedResponseWriter := &ResponseWriter{
		ResponseWriter: responseWriter,
		logger:         a.logger,
		cacheEntry:     entry,
		rules:          a.responseRules,
	}

	// Continue serving request
	a.next.ServeHTTP(wrappedResponseWriter, request)
}
