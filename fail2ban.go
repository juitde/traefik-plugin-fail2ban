// Package traefik_plugin_fail2ban plugin for traefik reverse proxy.
package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"context"
	"fmt"
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
	Enabled       bool         `yaml:"enabled"`
	AlwaysAllowed configIPSpec `yaml:"alwaysAllowed"`
	AlwaysDenied  configIPSpec `yaml:"alwaysDenied"`
	LogLevel      string       `yaml:"logLevel"`
	Rules         configRules  `yaml:"rules"`
}

type configRules struct {
	FindTime   string         `yaml:"findTime"`
	BanTime    string         `yaml:"banTime"`
	MaxRetries uint32         `yaml:"maxRetries"`
	Response   configResponse `yaml:"response"`
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
	}
}

type responseRules struct {
	StatusCode *regexp.Regexp
}

// Fail2Ban plugin data structure.
type Fail2Ban struct {
	next                http.Handler
	name                string
	cache               *Cache
	logger              *logf.Logger
	enabled             bool
	staticAllowedIPNets []*net.IPNet
	staticDeniedIPNets  []*net.IPNet
	findTime            time.Duration
	banTime             time.Duration
	maxRetries          uint32
	responseRules       responseRules
	errorCode           int
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
	return &Fail2Ban{
		next:                next,
		name:                name,
		cache:               NewCache(),
		logger:              NewLogger(config.LogLevel),
		enabled:             config.Enabled,
		staticAllowedIPNets: parseConfigIPList(config.AlwaysAllowed.IP),
		staticDeniedIPNets:  parseConfigIPList(config.AlwaysDenied.IP),
		findTime:            parseDuration(config.Rules.FindTime, 10*time.Minute),
		banTime:             parseDuration(config.Rules.BanTime, 3*time.Hour),
		maxRetries:          config.Rules.MaxRetries,
		responseRules:       parseResponseRules(config.Rules.Response),
		errorCode:           config.Rules.Response.ErrorCode,
	}, nil
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

	for _, ipNet := range a.staticDeniedIPNets {
		a.logger.Debug("Checking if remoteIP is in static denied Netmask.", "remoteIP", remoteIP, "netmask", ipNet, "phase", "check_request")
		if ipNet.Contains(net.ParseIP(remoteIP)) {
			a.logger.Info("RemoteIP was found in staticDeniedIPNets. Access Denied.", "remoteIP", remoteIP, "staticDeniedIPNets", a.staticDeniedIPNets, "phase", "check_request", "status", "denied")
			responseWriter.WriteHeader(a.errorCode)
			return
		}
	}

	for _, ipNet := range a.staticAllowedIPNets {
		a.logger.Debug("Checking if remoteIP is in static allowed Netmask.", "remoteIP", remoteIP, "netmask", ipNet, "phase", "check_request")
		if ipNet.Contains(net.ParseIP(remoteIP)) {
			a.logger.Info("RemoteIP was found in staticAllowedIPNets. Access Granted.", "remoteIP", remoteIP, "staticAllowedIPNets", a.staticAllowedIPNets, "phase", "check_request", "status", "granted")
			a.next.ServeHTTP(responseWriter, request)
			return
		}
	}

	requestTime := time.Now()
	a.cache.CleanEntries(a.findTime, a.banTime)
	a.cache.CleanEntryIfPossible(remoteIP, a.findTime, a.banTime, requestTime)
	entry := a.cache.CreateEntry(remoteIP, requestTime)

	if entry.GetTimesSeen() >= a.maxRetries && !entry.IsBanned() {
		a.logger.Info("Client has been banned.", "remoteIP", remoteIP, "maxRetries", a.maxRetries, "banTime", a.banTime, "findTime", a.findTime, "phase", "check_request", "status", "denied")
		entry.IssueBan()
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
