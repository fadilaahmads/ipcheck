package models

import (
	"net/http"
	"time"
)

// ============================================================================
// AbuseIPDB Response Structures
// ============================================================================
type AbuseIPDBError struct {
	Errors []struct {
		Detail string `json:"detail"`
		Status int 		`json:"status"`
	} `json:"errors"`
}

// ============================================================================
// CHECK Endpoint - Primary endpoint
// ============================================================================

type CheckResponse struct {
	Data CheckData `json:"data"`
}

type CheckData struct {
	IPAddress            string    `json:"ipAddress"`
	IsPublic             bool      `json:"isPublic"`
	IPVersion            int       `json:"ipVersion"`
	IsWhitelisted        bool      `json:"isWhitelisted"`
	AbuseConfidenceScore int       `json:"abuseConfidenceScore"` // 0-100, main metric
	CountryCode          string    `json:"countryCode"`
	CountryName          string    `json:"countryName"`
	UsageType            string    `json:"usageType"`
	ISP                  string    `json:"isp"`
	Domain               string    `json:"domain"`
	Hostnames            []string  `json:"hostnames"`
	IsTor                bool      `json:"isTor"`
	TotalReports         int       `json:"totalReports"`
	NumDistinctUsers     int       `json:"numDistinctUsers"`
	LastReportedAt       string    `json:"lastReportedAt"`
	Reports              []Report  `json:"reports,omitempty"` // Only if verbose=true
}

type Report struct {
	ReportedAt          string `json:"reportedAt"`
	Comment             string `json:"comment"`
	Categories          []int  `json:"categories"`
	ReporterID          int    `json:"reporterId"`
	ReporterCountryCode string `json:"reporterCountryCode"`
	ReporterCountryName string `json:"reporterCountryName"`
}

// ============================================================================
// BLACKLIST Endpoint - Optional, for bulk checking
// ============================================================================

type BlacklistResponse struct {
	Meta BlacklistMeta   `json:"meta"`
	Data []BlacklistItem `json:"data"`
}

type BlacklistMeta struct {
	GeneratedAt string `json:"generatedAt"`
}

type BlacklistItem struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	LastReportedAt       string `json:"lastReportedAt"`
}

// ============================================================================
// REPORTS Endpoint - Optional, for detailed investigation
// ============================================================================

type ReportsResponse struct {
	Data ReportsData `json:"data"`
}

type ReportsData struct {
	Total           int      `json:"total"`
	Page            int      `json:"page"`
	Count           int      `json:"count"`
	PerPage         int      `json:"perPage"`
	LastPage        int      `json:"lastPage"`
	NextPageURL     string   `json:"nextPageUrl"`
	PreviousPageURL string   `json:"previousPageUrl"`
	Results         []Report `json:"results"`
}

// ============================================================================
// CHECK-BLOCK Endpoint - Optional, for CIDR analysis
// ============================================================================

type CheckBlockResponse struct {
	Data CheckBlockData `json:"data"`
}

type CheckBlockData struct {
	NetworkAddress   string                `json:"networkAddress"`
	Netmask          string                `json:"netmask"`
	MinAddress       string                `json:"minAddress"`
	MaxAddress       string                `json:"maxAddress"`
	NumPossibleHosts int                   `json:"numPossibleHosts"`
	AddressSpaceDesc string                `json:"addressSpaceDesc"`
	ReportedAddress  []ReportedAddressItem `json:"reportedAddress"`
}

type ReportedAddressItem struct {
	IPAddress            string `json:"ipAddress"`
	NumReports           int    `json:"numReports"`
	MostRecentReport     string `json:"mostRecentReport"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
}

// ============================================================================
// AbuseIPDB Client
// ============================================================================

type AbuseIPDBClient struct {
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

// AbuseIPDB response structures (only what we need)
type AbuseCheckResponse struct {
	Data AbuseCheckData `json:"data"`
}

type AbuseCheckData struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	TotalReports         int    `json:"totalReports"`
	IsTor                bool   `json:"isTor"`
	CountryCode          string `json:"countryCode"`
	ISP                  string `json:"isp"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
}

// Konfigurasi CLI
type CliConfig struct {
	FileFlag			string
	IntervalFlag	time.Duration
	DailyFlag			int
	CacheFlag			string
	MalFile				string
	SuspFile			string
	ProviderFlag	string
}

// Konfigurasi untuk provider threat intelligence
type ProviderConfig struct {
	VTAPIKey				string
	AbuseIPDBAPIKey	string
	UseVT						bool
	UseAbuse				bool
}
