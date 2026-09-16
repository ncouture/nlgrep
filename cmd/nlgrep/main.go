package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ANSI color codes
const (
	colorReset = "\033[0m"
	colorBold  = "\033[1m"
	colorRed   = "\033[31;1m"
	colorCyan  = "\033[36m"
	colorDim   = "\033[2m"
)

// MatchResult stores a matched substring and its byte indices within a line
type MatchResult struct {
	Value string
	Start int
	End   int
}

// Extractor defines a specialized data type parser
type Extractor struct {
	ID          string
	Name        string
	Category    string
	Description string
	Aliases     []string
	Extract     func(line string) []MatchResult
}

// Config holds runtime options
type Config struct {
	PrintWholeLine bool
	AfterCount     int
	BeforeCount    int
	ShowLineNum    bool
	UniqueOnly     bool
	CountOnly      bool
	Color          bool
}

type inputSource struct {
	name   string
	reader io.Reader
}

type bufferedLine struct {
	lineNum int
	text    string
	matches []MatchResult
}

// -------------------------------------------------------------
// Checksum & Validation Helpers
// -------------------------------------------------------------

// Luhn algorithm verification (Credit cards, IMEI, Canadian SIN)
func isLuhnValid(s string) bool {
	var clean strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			clean.WriteRune(r)
		}
	}
	digits := clean.String()
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

// ISO 13616 IBAN Modulo 97 verification
func isIBANValid(s string) bool {
	s = strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// Rearrange: move first 4 characters to the end
	rearranged := s[4:] + s[:4]
	var numeric strings.Builder
	for _, ch := range rearranged {
		if ch >= '0' && ch <= '9' {
			numeric.WriteRune(ch)
		} else if ch >= 'A' && ch <= 'Z' {
			numeric.WriteString(strconv.Itoa(int(ch - 'A' + 10)))
		} else if ch >= 'a' && ch <= 'z' {
			numeric.WriteString(strconv.Itoa(int(ch - 'a' + 10)))
		} else {
			return false
		}
	}
	bigVal, ok := new(big.Int).SetString(numeric.String(), 10)
	if !ok {
		return false
	}
	rem := new(big.Int).Mod(bigVal, big.NewInt(97))
	return rem.Int64() == 1
}

// ISBN-10 and ISBN-13 verification
func isISBNValid(s string) bool {
	s = strings.TrimPrefix(s, "ISBN")
	s = strings.TrimPrefix(s, "-10")
	s = strings.TrimPrefix(s, "-13")
	s = strings.TrimPrefix(s, ":")
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), " ", "")

	if len(s) == 10 {
		sum := 0
		for i := 0; i < 9; i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
			sum += int(s[i]-'0') * (10 - i)
		}
		last := s[9]
		if last == 'X' || last == 'x' {
			sum += 10
		} else if last >= '0' && last <= '9' {
			sum += int(last - '0')
		} else {
			return false
		}
		return sum%11 == 0
	} else if len(s) == 13 {
		sum := 0
		for i := 0; i < 12; i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
			digit := int(s[i] - '0')
			if i%2 == 0 {
				sum += digit
			} else {
				sum += digit * 3
			}
		}
		check := (10 - (sum % 10)) % 10
		return int(s[12]-'0') == check
	}
	return false
}

// ISO 3779 VIN Modulo 11 check digit verification
func isVINValid(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 17 {
		return false
	}
	if strings.ContainsAny(s, "IOQ") {
		return false // I, O, Q forbidden in VIN
	}
	weights := []int{8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2}
	valMap := map[byte]int{
		'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
		'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
		'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
	}
	sum := 0
	for i := 0; i < 17; i++ {
		c := s[i]
		var val int
		if c >= '0' && c <= '9' {
			val = int(c - '0')
		} else if v, ok := valMap[c]; ok {
			val = v
		} else {
			return false
		}
		sum += val * weights[i]
	}
	rem := sum % 11
	var expected byte
	if rem == 10 {
		expected = 'X'
	} else {
		expected = byte('0' + rem)
	}
	return s[8] == expected
}

// US SSN Rule Validator
func isSSNValid(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	area, _ := strconv.Atoi(parts[0])
	group, _ := strconv.Atoi(parts[1])
	serial, _ := strconv.Atoi(parts[2])
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if group == 0 || serial == 0 {
		return false
	}
	return true
}

// -------------------------------------------------------------
// Compiled RE2-Compatible Regular Expressions
// -------------------------------------------------------------

var (
	reURL           = regexp.MustCompile(`(?i)\b(?:https?://|ftp://|www\.)[a-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+[a-z0-9/_=]`)
	reEmail         = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	rePhone         = regexp.MustCompile(`(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)
	reIPv4          = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reIPv6          = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}\b|\b(?:[a-f0-9]{1,4}:){1,7}:[a-f0-9]{1,4}\b`)
	reCreditCard    = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b`)
	reUUID          = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	reMAC           = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	reCVE           = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	reDOI           = regexp.MustCompile(`(?i)\b10\.\d{4,9}/[-._;()/:A-Za-z0-9]+[A-Za-z0-9]\b`)
	reSemVer        = regexp.MustCompile(`\bv?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?\b`)
	reSSN           = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reIBAN          = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9\s]{11,30}\b`)
	reBTC           = regexp.MustCompile(`\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b`)
	reETH           = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	reSolana        = regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`)
	reVIN           = regexp.MustCompile(`\b[A-HJ-NPR-Z0-9]{17}\b`)
	reISBNRaw       = regexp.MustCompile(`(?i)\b(?:ISBN(?:-1[03])?:?\s*)?(?:97[89][-\s]?)?[0-9]{1,5}[-\s]?[0-9]+[-\s]?[0-9]+[-\s]?[0-9X]\b`)
	reMD5           = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	reSHA1          = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	reSHA256        = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	reDate          = regexp.MustCompile(`\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b|\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/\d{4}\b`)
	reGPS           = regexp.MustCompile(`[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)`)
	reCron          = regexp.MustCompile(`\b(?:[0-5]?\d|\*|\*/\d+)\s+(?:[01]?\d|2[0-3]|\*|\*/\d+)\s+(?:0?[1-9]|[12]\d|3[01]|\*|\*/\d+)\s+(?:0?[1-9]|1[0-2]|\*|\*/\d+)\s+(?:[0-6]|\*|\*/\d+)\b`)
	reASN           = regexp.MustCompile(`(?i)\bAS[0-9]{1,10}\b`)
	reAirportIATA   = regexp.MustCompile(`\b[A-Z]{3}\b`)
	reCurrency      = regexp.MustCompile(`\b(?:USD|EUR|GBP|JPY|AUD|CAD|CHF|CNY|INR|BRL|RUB|KRW|SEK|NOK|MXN|NZD|SGD|HKD|ZAR|TRY)\b`)
	reJSONPath      = regexp.MustCompile(`\$(?:\.[a-zA-Z_][a-zA-Z0-9_]*|\[(?:'[^']*'|"[^"]*"|\*|\d+|\d*:\d*(?::\d*)?)\])+`)
	reXPath         = regexp.MustCompile(`(?:\/(?:\/)?(?:[a-zA-Z_][a-zA-Z0-9_-]*|\*)(?:\[(?:@[a-zA-Z_][a-zA-Z0-9_-]*(?:=[\'"][^\'"]*[\'"])?|\d+|contains\([^)]+\))\])*)+`)
	reDomain        = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|ai|dev|app|co|uk|de|fr|jp|cn|nl|eu|info|biz|me|tv)\b`)
	reMETAR         = regexp.MustCompile(`\b[A-Z]{4}\s+\d{6}Z\s+(?:AUTO\s+)?(?:\d{3}|VRB)\d{2,3}(?:G\d{2,3})?(?:KT|MPS)\s+(?:\d{4}|\d+(?:/\d+)?SM)\b`)
	reChessFEN      = regexp.MustCompile(`\b((?:[pnbrqkPNBRQK1-8]{1,8}/){7}[pnbrqkPNBRQK1-8]{1,8})\s+([wb])\s+(-|[KQkq]{1,4})\s+(-|[a-h][36])\s+(\d+)\s+(\d+)\b`)
	reUserAgent     = regexp.MustCompile(`\bMozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[0-9.]+|Gecko/[0-9]+|Chrome/[0-9.]+|Safari/[0-9.]+)[A-Za-z0-9./\s_-]*`)
	reNameHonorific    = regexp.MustCompile(`\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Rev\.|Hon\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b`)
	reSubject          = regexp.MustCompile(`(?i)^(?:\s*(?:subject|re|fwd|fw)):\s*(.+)`)
	cidrExtractorRegex = regexp.MustCompile(`(?i)(?:\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b|(?:::|(?:\b[0-9a-f]{1,4}:))(?:[0-9a-f]{0,4}:){0,6}[0-9a-f]{0,4}/[0-9]{1,3}\b)`)
	reDottedCIDR       = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
)

func regexFindAll(re *regexp.Regexp, line string) []MatchResult {
	indices := re.FindAllStringIndex(line, -1)
	var results []MatchResult
	for _, loc := range indices {
		results = append(results, MatchResult{
			Value: line[loc[0]:loc[1]],
			Start: loc[0],
			End:   loc[1],
		})
	}
	return results
}

// -------------------------------------------------------------
// Registry of All Supported Extractors
// -------------------------------------------------------------

var Registry = []Extractor{
	{
		ID:          "urls",
		Name:        "URLs / Web Addresses",
		Category:    "Web & Internet",
		Description: "RFC 3986 Web addresses (http, https, ftp, www)",
		Aliases:     []string{"url", "urls", "link", "links", "website", "websites", "web address", "http", "https", "find urls", "get urls"},
		Extract: func(line string) []MatchResult {
			var res []MatchResult
			for _, loc := range reURL.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				cleaned := strings.TrimRight(val, ".,!?:;)]}\"'>")
				trimLen := len(val) - len(cleaned)
				res = append(res, MatchResult{
					Value: cleaned,
					Start: loc[0],
					End:   loc[1] - trimLen,
				})
			}
			return res
		},
	},
	{
		ID:          "emails",
		Name:        "Email Addresses",
		Category:    "Communications",
		Description: "RFC 5322 Standard email addresses",
		Aliases:     []string{"email", "emails", "mail", "e-mail", "email address", "contacts", "find emails", "get emails"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reEmail, line)
		},
	},
	{
		ID:          "phone_numbers",
		Name:        "Phone Numbers",
		Category:    "Communications",
		Description: "International E.164 and standard formatted telephone numbers",
		Aliases:     []string{"phone", "phones", "phone number", "phone numbers", "telephone", "cell", "mobile", "find phones"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(rePhone, line)
		},
	},
	{
		ID:          "ips",
		Name:        "IP Addresses",
		Category:    "Networking",
		Description: "Validated IPv4 and IPv6 network host addresses",
		Aliases:     []string{"ip", "ips", "ip address", "ip addresses", "ipv4", "ipv6", "host", "network ip", "find ips"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			for _, loc := range reIPv4.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				if ip := net.ParseIP(val); ip != nil && strings.Contains(val, ".") {
					results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
				}
			}
			for _, loc := range reIPv6.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				if ip := net.ParseIP(val); ip != nil && strings.Contains(val, ":") {
					results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
				}
			}
			return results
		},
	},
	{
		ID:          "credit_cards",
		Name:        "Credit Card Numbers (PAN)",
		Category:    "Financial",
		Description: "Luhn-validated Visa, MasterCard, Amex, and Discover numbers",
		Aliases:     []string{"credit card", "credit cards", "creditcard", "pan", "cards", "payment card", "visa", "mastercard"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			for _, loc := range reCreditCard.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				if isLuhnValid(val) {
					results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
				}
			}
			return results
		},
	},
	{
		ID:          "ibans",
		Name:        "Bank Account Numbers (IBAN)",
		Category:    "Financial",
		Description: "ISO 13616 International Bank Account Numbers (Mod-97 checked)",
		Aliases:     []string{"iban", "ibans", "bank account", "bank accounts", "bank number", "routing"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			for _, loc := range reIBAN.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				if isIBANValid(val) {
					results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
				}
			}
			return results
		},
	},
	{
		ID:          "uuids",
		Name:        "UUIDs / GUIDs",
		Category:    "Software & Systems",
		Description: "RFC 4122 Standard 128-bit hex identifiers",
		Aliases:     []string{"uuid", "uuids", "guid", "guids", "unique identifier"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reUUID, line)
		},
	},
	{
		ID:          "mac_addresses",
		Name:        "MAC Addresses",
		Category:    "Networking",
		Description: "EUI-48 / EUI-64 Hardware Ethernet and Wi-Fi addresses",
		Aliases:     []string{"mac", "macs", "mac address", "mac addresses", "hardware address", "ethernet"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reMAC, line)
		},
	},
	{
		ID:          "cves",
		Name:        "CVE Vulnerabilities",
		Category:    "Cybersecurity",
		Description: "MITRE Common Vulnerabilities and Exposures IDs",
		Aliases:     []string{"cve", "cves", "vulnerability", "vulnerabilities", "security bug", "cve id"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reCVE, line)
		},
	},
	{
		ID:          "dois",
		Name:        "Digital Object Identifiers (DOI)",
		Category:    "Publishing & Academic",
		Description: "ISO 26324 Academic publication persistent identifiers",
		Aliases:     []string{"doi", "dois", "digital object identifier", "paper id", "research id"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reDOI, line)
		},
	},
	{
		ID:          "semver",
		Name:        "Semantic Version Numbers",
		Category:    "Software & Systems",
		Description: "SemVer 2.0.0 software release version strings",
		Aliases:     []string{"semver", "version", "versions", "release", "version number"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reSemVer, line)
		},
	},
	{
		ID:          "ssns",
		Name:        "Social Security Numbers (SSN)",
		Category:    "Government & Identity",
		Description: "US Social Security Numbers with area/group rule checks",
		Aliases:     []string{"ssn", "ssns", "social security", "social security number"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			for _, loc := range reSSN.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				if isSSNValid(val) {
					results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
				}
			}
			return results
		},
	},
	{
		ID:          "crypto",
		Name:        "Cryptocurrency Wallet Addresses",
		Category:    "Blockchain",
		Description: "Bitcoin (Legacy, SegWit), Ethereum (0x), and Solana addresses",
		Aliases:     []string{"crypto", "bitcoin", "btc", "ethereum", "eth", "solana", "wallet", "wallet address"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			results = append(results, regexFindAll(reBTC, line)...)
			results = append(results, regexFindAll(reETH, line)...)
			return results
		},
	},
	{
		ID:          "vins",
		Name:        "Vehicle Identification Numbers (VIN)",
		Category:    "Automotive",
		Description: "ISO 3779 17-character VIN with Modulo-11 check digit verification",
		Aliases:     []string{"vin", "vins", "vehicle id", "chassis number"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			for _, loc := range reVIN.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				if isVINValid(val) {
					results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
				}
			}
			return results
		},
	},
	{
		ID:          "isbns",
		Name:        "ISBNs (Book Identifiers)",
		Category:    "Publishing & Academic",
		Description: "ISBN-10 and ISBN-13 books with mathematical check digits",
		Aliases:     []string{"isbn", "isbns", "book number", "book id"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			for _, loc := range reISBNRaw.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				if isISBNValid(val) {
					results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
				}
			}
			return results
		},
	},
	{
		ID:          "hashes",
		Name:        "Cryptographic Hashes",
		Category:    "Cybersecurity",
		Description: "MD5 (32-hex), SHA-1 (40-hex), and SHA-256 (64-hex) digests",
		Aliases:     []string{"hash", "hashes", "sha256", "sha1", "md5", "digest", "checksum"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			results = append(results, regexFindAll(reSHA256, line)...)
			results = append(results, regexFindAll(reSHA1, line)...)
			results = append(results, regexFindAll(reMD5, line)...)
			return results
		},
	},
	{
		ID:          "dates",
		Name:        "Calendar Dates",
		Category:    "Temporal",
		Description: "Standard ISO 8601 (YYYY-MM-DD) and regional calendar dates",
		Aliases:     []string{"date", "dates", "calendar", "day", "birthdate", "dob"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reDate, line)
		},
	},
	{
		ID:          "coordinates",
		Name:        "GPS Coordinates",
		Category:    "Geospatial",
		Description: "Decimal Degree latitude and longitude coordinate pairs",
		Aliases:     []string{"gps", "coordinates", "coords", "lat lon", "latitude", "longitude"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reGPS, line)
		},
	},
	{
		ID:          "cron",
		Name:        "Cron Expressions",
		Category:    "Software & Systems",
		Description: "Standard 5-field UNIX scheduling cron syntax",
		Aliases:     []string{"cron", "cron expression", "schedule", "crontab"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reCron, line)
		},
	},
	{
		ID:          "asns",
		Name:        "Autonomous System Numbers (ASN)",
		Category:    "Networking",
		Description: "BGP Routing Autonomous System Numbers (e.g. AS15169)",
		Aliases:     []string{"asn", "asns", "autonomous system", "bgp as"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reASN, line)
		},
	},
	{
		ID:          "currencies",
		Name:        "Currency Codes (ISO 4217)",
		Category:    "Financial",
		Description: "Standard 3-letter currency identifiers (USD, EUR, GBP, JPY, etc.)",
		Aliases:     []string{"currency", "currencies", "currency code", "money"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reCurrency, line)
		},
	},
	{
		ID:          "domains",
		Name:        "Domain Names",
		Category:    "Web & Internet",
		Description: "Fully qualified domain names matching top-level domains",
		Aliases:     []string{"domain", "domains", "fqdn", "hostname"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reDomain, line)
		},
	},
	{
		ID:          "jsonpath",
		Name:        "JSONPath Expressions",
		Category:    "Data Formats",
		Description: "RFC 9535 JSONPath structured queries (e.g., $.store.book[*])",
		Aliases:     []string{"jsonpath", "json path", "json query"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reJSONPath, line)
		},
	},
	{
		ID:          "xpath",
		Name:        "XPath Expressions",
		Category:    "Data Formats",
		Description: "W3C XML/HTML XPath navigation paths",
		Aliases:     []string{"xpath", "xml path", "xquery"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reXPath, line)
		},
	},
	{
		ID:          "metar",
		Name:        "METAR Weather Reports",
		Category:    "Aviation & Weather",
		Description: "ICAO standard aeronautical meteorological aerodrome reports",
		Aliases:     []string{"metar", "weather report", "aviation weather"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reMETAR, line)
		},
	},
	{
		ID:          "chess_fen",
		Name:        "Chess FEN Notation",
		Category:    "Gaming & Notation",
		Description: "Forsyth–Edwards Notation board state records",
		Aliases:     []string{"fen", "chess", "chess fen", "board position"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reChessFEN, line)
		},
	},
	{
		ID:          "user_agents",
		Name:        "User Agent Strings",
		Category:    "Web & Internet",
		Description: "HTTP Client / Browser user agent identification strings",
		Aliases:     []string{"user agent", "user agents", "useragent", "browser string"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reUserAgent, line)
		},
	},
	{
		ID:          "names",
		Name:        "Personal Names (Honorific Anchored)",
		Category:    "Identity",
		Description: "Names preceded by title honorifics (Mr., Dr., Ms., Prof., etc.)",
		Aliases:     []string{"name", "names", "person", "people", "doctor", "professor"},
		Extract: func(line string) []MatchResult {
			return regexFindAll(reNameHonorific, line)
		},
	},
	{
		ID:          "subjects",
		Name:        "Subject Lines",
		Category:    "Communications",
		Description: "Email, ticket, or header Subject / Topic lines",
		Aliases:     []string{"subject", "subjects", "topic", "subject line"},
		Extract: func(line string) []MatchResult {
			matches := reSubject.FindStringSubmatchIndex(line)
			if len(matches) >= 4 {
				return []MatchResult{{
					Value: strings.TrimSpace(line[matches[2]:matches[3]]),
					Start: matches[2],
					End:   matches[3],
				}}
			}
			return nil
		},
	},
	{
		ID:          "cidrs",
		Name:        "CIDR Blocks & Subnet Masks",
		Category:    "Networking",
		Description: "IPv4 and IPv6 CIDR prefixes and network masks",
		Aliases:     []string{"cidr", "cidrs", "netmask", "netmasks", "subnet", "subnets", "prefix", "prefixes", "get cidrs", "get netmask", "get subnets", "get netmasks", "find cidrs", "find netmask"},
		Extract: func(line string) []MatchResult {
			var results []MatchResult
			occupied := make([]bool, len(line))

			// 1. Standard CIDRs (IPv4 and IPv6)
			for _, loc := range cidrExtractorRegex.FindAllStringIndex(line, -1) {
				val := line[loc[0]:loc[1]]
				if _, err := netip.ParsePrefix(val); err == nil {
					results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
					for i := loc[0]; i < loc[1] && i < len(occupied); i++ {
						occupied[i] = true
					}
				}
			}

			// 2. Dotted netmask notation: e.g. 192.168.1.0/255.255.255.0
			for _, loc := range reDottedCIDR.FindAllStringIndex(line, -1) {
				if loc[0] < len(occupied) && occupied[loc[0]] {
					continue
				}
				val := line[loc[0]:loc[1]]
				parts := strings.SplitN(val, "/", 2)
				if ip := net.ParseIP(parts[0]).To4(); ip != nil {
					if maskIP := net.ParseIP(parts[1]).To4(); maskIP != nil {
						if ones, bits := net.IPMask(maskIP).Size(); bits == 32 && ones >= 0 {
							results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
							for i := loc[0]; i < loc[1] && i < len(occupied); i++ {
								occupied[i] = true
							}
						}
					}
				}
			}

			// 3. Standalone subnet masks: e.g. 255.255.255.0
			for _, loc := range reIPv4.FindAllStringIndex(line, -1) {
				if loc[0] < len(occupied) && occupied[loc[0]] {
					continue
				}
				val := line[loc[0]:loc[1]]
				if ip := net.ParseIP(val).To4(); ip != nil {
					if ones, bits := net.IPMask(ip).Size(); bits == 32 && ones > 0 && ip[0] == 255 {
						results = append(results, MatchResult{Value: val, Start: loc[0], End: loc[1]})
						for i := loc[0]; i < loc[1] && i < len(occupied); i++ {
							occupied[i] = true
						}
					}
				}
			}

			sort.Slice(results, func(i, j int) bool {
				return results[i].Start < results[j].Start
			})
			return results
		},
	},
}

// -------------------------------------------------------------
// Natural Language Intent Router
// -------------------------------------------------------------

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			min1 := dp[i-1][j] + 1
			min2 := dp[i][j-1] + 1
			min3 := dp[i-1][j-1] + cost
			if min2 < min1 {
				min1 = min2
			}
			if min3 < min1 {
				min1 = min3
			}
			dp[i][j] = min1
		}
	}
	return dp[la][lb]
}

func normalizeQuery(q string) string {
	q = strings.ToLower(strings.TrimSpace(q))
	prefixes := []string{
		"extract all ", "extract ", "find all ", "find ", "show me all ",
		"show me ", "get all ", "get ", "list all ", "list ", "search for ",
		"look for ", "grab all ", "grab ", "where are the ", "what are the ",
		"count all ", "count ", "merge all ", "merge ",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(q, p) {
			q = strings.TrimPrefix(q, p)
			break
		}
	}
	q = strings.TrimSuffix(q, " please")
	q = strings.TrimSuffix(q, "!")
	q = strings.TrimSuffix(q, "?")
	return strings.TrimSpace(q)
}

func isStopWord(w string) bool {
	switch w {
	case "get", "find", "extract", "show", "list", "search", "grab", "all", "me", "for", "the", "where", "what", "are", "a", "an", "in", "of", "count", "merge":
		return true
	}
	return false
}

func ResolveIntentExact(rawQuery string) *Extractor {
	q := normalizeQuery(rawQuery)
	if q == "" || isStopWord(q) {
		return nil
	}
	for i := range Registry {
		ext := &Registry[i]
		if ext.ID == q {
			return ext
		}
		for _, alias := range ext.Aliases {
			if alias == q {
				return ext
			}
		}
	}
	return nil
}

func ResolveIntent(rawQuery string) *Extractor {
	if exact := ResolveIntentExact(rawQuery); exact != nil {
		return exact
	}
	q := normalizeQuery(rawQuery)
	if q == "" || isStopWord(q) {
		return nil
	}

	// 2. Token overlap & substring match
	queryWords := strings.Fields(q)
	bestScore := 0
	var bestMatch *Extractor

	for i := range Registry {
		ext := &Registry[i]
		score := 0
		for _, alias := range ext.Aliases {
			aliasWords := strings.Fields(alias)
			for _, qw := range queryWords {
				if isStopWord(qw) {
					continue
				}
				for _, aw := range aliasWords {
					if isStopWord(aw) {
						continue
					}
					if qw == aw {
						score += 3
					} else if strings.Contains(aw, qw) || strings.Contains(qw, aw) {
						score += 1
					}
				}
			}
			if strings.Contains(q, alias) || strings.Contains(alias, q) {
				score += 4
			}
		}
		if score > bestScore {
			bestScore = score
			bestMatch = ext
		}
	}
	if bestScore >= 3 {
		return bestMatch
	}

	// 3. Fuzzy Levenshtein match for typos (distance <= 2 for words with len >= 4)
	if len(q) >= 4 {
		for i := range Registry {
			ext := &Registry[i]
			if levenshtein(q, ext.ID) <= 2 {
				return ext
			}
			for _, alias := range ext.Aliases {
				if levenshtein(q, alias) <= 2 {
					return ext
				}
			}
		}
	}

	return nil
}

func PrintHelp() {
	fmt.Fprintf(os.Stderr, "nlgrep - Fast Semantic Data Extractor for Linux (Natural Language Grep)\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  nlgrep [options] <data-type | \"natural language query\"> [file ...]\n")
	fmt.Fprintf(os.Stderr, "  cat input.txt | nlgrep [options] <data-type | \"query\">\n")
	fmt.Fprintf(os.Stderr, "  nlgrep [options] <subcommand> [CIDRs / ranges / files ...]\n\n")

	fmt.Fprintf(os.Stderr, "Extractor Options:\n")
	fmt.Fprintf(os.Stderr, "  --line, -L, -whole-line   Print the ENTIRE line containing the pattern (default: pattern only)\n")
	fmt.Fprintf(os.Stderr, "  -A <number>               Print <number> lines after and including the matching line\n")
	fmt.Fprintf(os.Stderr, "  -B <number>               Print <number> lines before and including the matching line\n")
	fmt.Fprintf(os.Stderr, "  -n                        Show 1-based line numbers\n")
	fmt.Fprintf(os.Stderr, "  -u                        Deduplicate matching values\n")
	fmt.Fprintf(os.Stderr, "  -c                        Print only count of matches\n")
	fmt.Fprintf(os.Stderr, "  --color                   Highlight matched patterns (default: auto)\n\n")

	fmt.Fprintf(os.Stderr, "Netblock & Pipeline Options:\n")
	fmt.Fprintf(os.Stderr, "  -h                        Format address counts with readable digit groupings\n")
	fmt.Fprintf(os.Stderr, "  --json                    Emit machine-readable JSON structure\n")
	fmt.Fprintf(os.Stderr, "  --details                 Display itemized breakdown per input prefix\n")
	fmt.Fprintf(os.Stderr, "  --merge                   Display merged/coalesced non-overlapping CIDR blocks\n")
	fmt.Fprintf(os.Stderr, "  -f <file>                 Optional input file path containing subnets\n")
	fmt.Fprintf(os.Stderr, "  -x, --extract             Extract CIDRs automatically from freeform unstructured text\n\n")

	fmt.Fprintf(os.Stderr, "Netblock Subcommands & Operations:\n")
	fmt.Fprintf(os.Stderr, "  nlgrep ip count [CIDR / range / file ...]\n")
	fmt.Fprintf(os.Stderr, "  nlgrep count total ips [CIDR / range / file ...]\n")
	fmt.Fprintf(os.Stderr, "  nlgrep netmask count [CIDR / range / file ...]\n")
	fmt.Fprintf(os.Stderr, "  nlgrep merge ips [CIDR / file ...]\n")
	fmt.Fprintf(os.Stderr, "  nlgrep netmask merge [CIDR / file ...]\n")
	fmt.Fprintf(os.Stderr, "  nlgrep merge netmasks [CIDR / file ...]\n\n")

	categories := make(map[string][]Extractor)
	for _, ext := range Registry {
		categories[ext.Category] = append(categories[ext.Category], ext)
	}

	var catNames []string
	for cat := range categories {
		catNames = append(catNames, cat)
	}
	sort.Strings(catNames)

	fmt.Fprintf(os.Stderr, "Available Data Types by Category:\n")
	for _, cat := range catNames {
		fmt.Fprintf(os.Stderr, "\n  [%s]\n", cat)
		for _, ext := range categories[cat] {
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", ext.ID, ext.Description)
		}
	}

	fmt.Fprintf(os.Stderr, "\nPipeline & Usage Examples:\n")
	fmt.Fprintf(os.Stderr, "  printf \"192.168.1.10\\n192.168.1.11\\n\" | nlgrep get ip addresses | nlgrep ip count\n")
	fmt.Fprintf(os.Stderr, "  printf \"10.0.0.0/24\\n10.0.1.0/24\\n\" | nlgrep merge ips\n")
	fmt.Fprintf(os.Stderr, "  printf \"172.16.0.0/24\\n172.16.1.0/24\\n\" | nlgrep get netmask | nlgrep netmask merge | nlgrep ip count\n")
	fmt.Fprintf(os.Stderr, "  nlgrep ip count 10.0.0.1-10.0.0.10\n")
	fmt.Fprintf(os.Stderr, "  cat subnets.txt | nlgrep count -h --details\n")
	fmt.Fprintf(os.Stderr, "  echo \"test@example.com\" | nlgrep emails\n")
	fmt.Fprintf(os.Stderr, "  nlgrep urls access.log\n")
	fmt.Fprintf(os.Stderr, "  nlgrep \"find all email addresses\" contacts.txt\n")
	fmt.Fprintf(os.Stderr, "  nlgrep --line \"show credit cards\" dump.sql\n")
	fmt.Fprintf(os.Stderr, "  nlgrep -B 2 -A 3 urls server.log\n")
	fmt.Fprintf(os.Stderr, "  cat syslog | nlgrep -n ips\n")
}

func highlightMatch(line string, matches []MatchResult, useColor bool) string {
	if !useColor || len(matches) == 0 {
		return line
	}
	var sb strings.Builder
	lastIdx := 0
	for _, m := range matches {
		if m.Start < lastIdx {
			continue
		}
		sb.WriteString(line[lastIdx:m.Start])
		sb.WriteString(colorRed)
		sb.WriteString(line[m.Start:m.End])
		sb.WriteString(colorReset)
		lastIdx = m.End
	}
	sb.WriteString(line[lastIdx:])
	return sb.String()
}

func processStream(in inputSource, ext *Extractor, cfg Config, seen map[string]bool) int {
	scanner := bufio.NewScanner(in.reader)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	lineNum := 0
	matchCount := 0

	if !cfg.PrintWholeLine && cfg.AfterCount == 0 && cfg.BeforeCount == 0 {
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			matches := ext.Extract(line)
			for _, m := range matches {
				matchCount++
				if cfg.CountOnly {
					continue
				}
				if cfg.UniqueOnly {
					if seen[m.Value] {
						continue
					}
					seen[m.Value] = true
				}
				if cfg.ShowLineNum {
					if cfg.Color {
						fmt.Printf("%s%d%s:%s\n", colorCyan, lineNum, colorReset, m.Value)
					} else {
						fmt.Printf("%d:%s\n", lineNum, m.Value)
					}
				} else {
					fmt.Println(m.Value)
				}
			}
		}
		return matchCount
	}

	linesAfter := 0
	if cfg.AfterCount > 0 {
		linesAfter = cfg.AfterCount - 1
	}

	linesBefore := 0
	if cfg.BeforeCount > 0 {
		linesBefore = cfg.BeforeCount - 1
	}

	var history []bufferedLine
	pendingAfter := 0
	lastPrintedLine := 0

	printLine := func(b bufferedLine, isMatch bool) {
		if b.lineNum <= lastPrintedLine {
			return
		}
		if lastPrintedLine > 0 && b.lineNum > lastPrintedLine+1 {
			if cfg.Color {
				fmt.Printf("%s--%s\n", colorDim, colorReset)
			} else {
				fmt.Println("--")
			}
		}
		lastPrintedLine = b.lineNum

		sep := "-"
		if isMatch {
			sep = ":"
		}

		lineOut := b.text
		if isMatch {
			lineOut = highlightMatch(b.text, b.matches, cfg.Color)
		}

		if cfg.ShowLineNum {
			if cfg.Color {
				if isMatch {
					fmt.Printf("%s%d%s%s%s%s\n", colorCyan, b.lineNum, colorReset, colorBold, sep, colorReset+lineOut)
				} else {
					fmt.Printf("%s%d%s%s%s\n", colorDim, b.lineNum, colorReset, sep, lineOut)
				}
			} else {
				fmt.Printf("%d%s%s\n", b.lineNum, sep, lineOut)
			}
		} else {
			fmt.Println(lineOut)
		}
	}

	for scanner.Scan() {
		lineNum++
		text := scanner.Text()
		matches := ext.Extract(text)
		isMatch := len(matches) > 0

		cur := bufferedLine{
			lineNum: lineNum,
			text:    text,
			matches: matches,
		}

		if isMatch {
			matchCount += len(matches)
			if cfg.CountOnly {
				continue
			}

			if linesBefore > 0 {
				startIdx := 0
				if len(history) > linesBefore {
					startIdx = len(history) - linesBefore
				}
				for i := startIdx; i < len(history); i++ {
					printLine(history[i], len(history[i].matches) > 0)
				}
			}

			printLine(cur, true)

			if linesAfter > pendingAfter {
				pendingAfter = linesAfter
			}
		} else {
			if pendingAfter > 0 && !cfg.CountOnly {
				printLine(cur, false)
				pendingAfter--
			}
		}

		if linesBefore > 0 {
			history = append(history, cur)
			if len(history) > linesBefore*2+10 {
				history = history[len(history)-linesBefore:]
			}
		}
	}

	return matchCount
}

// -------------------------------------------------------------
// Netblock & Interval Math Types and Algorithms
// -------------------------------------------------------------

// IPv4Range represents an inclusive range of IPv4 addresses [Start, End].
type IPv4Range struct {
	Start uint32
	End   uint32
}

// IPv6Range represents an inclusive range of IPv6 addresses [Start, End].
type IPv6Range struct {
	Start *big.Int
	End   *big.Int
}

// PrefixDetail stores metadata for individual parsed targets before coalescing.
type PrefixDetail struct {
	Raw          string `json:"raw"`
	Version      int    `json:"version"`
	StartAddress string `json:"start_address"`
	EndAddress   string `json:"end_address"`
	CountStr     string `json:"count"`
}

// AggregationResult contains consolidated metrics across evaluated ranges.
type AggregationResult struct {
	TotalIPv4Count  uint64         `json:"ipv4_count"`
	TotalIPv6Count  *big.Int       `json:"ipv6_count"`
	TotalCombined   *big.Int       `json:"total_unique_ips"`
	IPv4RangesInput int            `json:"ipv4_ranges_input"`
	IPv4MergedCount int            `json:"ipv4_ranges_merged"`
	IPv6RangesInput int            `json:"ipv6_ranges_input"`
	IPv6MergedCount int            `json:"ipv6_ranges_merged"`
	MergedIPv4      []IPv4Range    `json:"merged_ipv4_intervals,omitempty"`
	MergedIPv6      []IPv6Range    `json:"merged_ipv6_intervals,omitempty"`
	MergedCIDRs     []string       `json:"merged_cidrs,omitempty"`
	Details         []PrefixDetail `json:"details,omitempty"`
}

// ip4ToUint32 converts a 4-byte IPv4 array into a native unsigned 32-bit integer.
func ip4ToUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// uint32ToIP4 converts an unsigned 32-bit integer back to a netip.Addr.
func uint32ToIP4(val uint32) netip.Addr {
	b := [4]byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}
	return netip.AddrFrom4(b)
}

// prefixToIPv4Range translates a netip.Prefix into an exact start and end integer range.
func prefixToIPv4Range(p netip.Prefix) IPv4Range {
	masked := p.Masked()
	start := ip4ToUint32(masked.Addr().As4())
	bitsLen := p.Bits()

	var mask uint32
	if bitsLen == 0 {
		mask = 0
	} else {
		mask = uint32(0xFFFFFFFF) << (32 - bitsLen)
	}
	end := start | (^mask)

	return IPv4Range{Start: start, End: end}
}

// ip6ToBigInt converts a 16-byte IPv6 representation into big.Int.
func ip6ToBigInt(b [16]byte) *big.Int {
	return new(big.Int).SetBytes(b[:])
}

// bigIntToIP6 converts a big.Int into a valid netip.Addr.
func bigIntToIP6(n *big.Int) netip.Addr {
	bytes := n.Bytes()
	var b [16]byte
	if len(bytes) <= 16 {
		copy(b[16-len(bytes):], bytes)
	}
	return netip.AddrFrom16(b)
}

// prefixToIPv6Range translates an IPv6 netip.Prefix into inclusive [Start, End] big.Ints.
func prefixToIPv6Range(p netip.Prefix) IPv6Range {
	masked := p.Masked()
	b := masked.Addr().As16()
	start := ip6ToBigInt(b)
	hostBits := 128 - p.Bits()

	end := new(big.Int).Set(start)
	if hostBits > 0 {
		span := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
		span.Sub(span, big.NewInt(1))
		end.Add(end, span)
	}

	return IPv6Range{Start: start, End: end}
}

// MergeIPv4Ranges sorts and collapses overlapping and adjacent IPv4 intervals in O(N log N) time.
func MergeIPv4Ranges(ranges []IPv4Range) []IPv4Range {
	if len(ranges) <= 1 {
		return ranges
	}

	sorted := make([]IPv4Range, len(ranges))
	copy(sorted, ranges)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start == sorted[j].Start {
			return sorted[i].End < sorted[j].End
		}
		return sorted[i].Start < sorted[j].Start
	})

	merged := make([]IPv4Range, 0, len(sorted))
	merged = append(merged, sorted[0])

	for i := 1; i < len(sorted); i++ {
		lastIdx := len(merged) - 1
		curr := sorted[i]

		if uint64(curr.Start) <= uint64(merged[lastIdx].End)+1 {
			if curr.End > merged[lastIdx].End {
				merged[lastIdx].End = curr.End
			}
		} else {
			merged = append(merged, curr)
		}
	}

	return merged
}

// MergeIPv6Ranges merges overlapping and contiguous IPv6 ranges accurately.
func MergeIPv6Ranges(ranges []IPv6Range) []IPv6Range {
	if len(ranges) <= 1 {
		return ranges
	}

	sorted := make([]IPv6Range, len(ranges))
	copy(sorted, ranges)
	sort.Slice(sorted, func(i, j int) bool {
		cmp := sorted[i].Start.Cmp(sorted[j].Start)
		if cmp == 0 {
			return sorted[i].End.Cmp(sorted[j].End) < 0
		}
		return cmp < 0
	})

	one := big.NewInt(1)
	merged := make([]IPv6Range, 0, len(sorted))
	merged = append(merged, sorted[0])

	for i := 1; i < len(sorted); i++ {
		lastIdx := len(merged) - 1
		curr := sorted[i]

		threshold := new(big.Int).Add(merged[lastIdx].End, one)
		if curr.Start.Cmp(threshold) <= 0 {
			if curr.End.Cmp(merged[lastIdx].End) > 0 {
				merged[lastIdx].End = curr.End
			}
		} else {
			merged = append(merged, curr)
		}
	}

	return merged
}

// RangeToIPv4Prefixes converts an arbitrary [start, end] IPv4 range into minimal CIDRs.
func RangeToIPv4Prefixes(start, end uint32) []netip.Prefix {
	var prefixes []netip.Prefix
	cur := uint64(start)
	maxEnd := uint64(end)

	for cur <= maxEnd {
		var maxShift uint = 32
		if cur != 0 {
			maxShift = uint(bits.TrailingZeros32(uint32(cur)))
		}
		diff := maxEnd - cur + 1
		diffShift := uint(bits.Len64(diff) - 1)
		if diffShift < maxShift {
			maxShift = diffShift
		}

		pLen := 32 - int(maxShift)
		ip := uint32ToIP4(uint32(cur))
		prefixes = append(prefixes, netip.PrefixFrom(ip, pLen))
		cur += uint64(1) << maxShift
	}

	return prefixes
}

// RangeToIPv6Prefixes converts an arbitrary [start, end] IPv6 range into minimal CIDRs.
func RangeToIPv6Prefixes(start, end *big.Int) []netip.Prefix {
	var prefixes []netip.Prefix
	cur := new(big.Int).Set(start)
	one := big.NewInt(1)

	for cur.Cmp(end) <= 0 {
		var maxShift uint = 128
		if cur.Sign() != 0 {
			maxShift = cur.TrailingZeroBits()
		}
		diff := new(big.Int).Sub(end, cur)
		diff.Add(diff, one)
		diffShift := uint(diff.BitLen() - 1)
		if diffShift < maxShift {
			maxShift = diffShift
		}
		if maxShift > 128 {
			maxShift = 128
		}

		pLen := 128 - int(maxShift)
		ip := bigIntToIP6(cur)
		prefixes = append(prefixes, netip.PrefixFrom(ip, pLen))

		step := new(big.Int).Lsh(one, maxShift)
		cur.Add(cur, step)
	}

	return prefixes
}

// ParseToken parses a single CIDR, IP address, or hyphenated IP range.
func ParseToken(token string) (hasV4 bool, r4 IPv4Range, hasV6 bool, r6 IPv6Range, err error) {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, "\"',;()[]")
	if token == "" {
		return false, r4, false, r6, fmt.Errorf("empty token")
	}

	// Range format: <start_ip>-<end_ip>
	if strings.Contains(token, "-") {
		parts := strings.SplitN(token, "-", 2)
		startIP, err1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
		endIP, err2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err1 == nil && err2 == nil {
			startIP = startIP.WithZone("")
			endIP = endIP.WithZone("")
			if startIP.Is4() && endIP.Is4() {
				s := ip4ToUint32(startIP.As4())
				e := ip4ToUint32(endIP.As4())
				if s > e {
					s, e = e, s
				}
				return true, IPv4Range{Start: s, End: e}, false, r6, nil
			} else if startIP.Is6() && endIP.Is6() {
				s := ip6ToBigInt(startIP.As16())
				e := ip6ToBigInt(endIP.As16())
				if s.Cmp(e) > 0 {
					s, e = e, s
				}
				return false, r4, true, IPv6Range{Start: s, End: e}, nil
			}
		}
	}

	// Strip IPv6 zone identifier if present in token (e.g. fe80::1%eth0 or fe80::%eth0/64)
	if idx := strings.Index(token, "%"); idx != -1 {
		if slashIdx := strings.Index(token[idx:], "/"); slashIdx != -1 {
			token = token[:idx] + token[idx+slashIdx:]
		} else {
			token = token[:idx]
		}
	}

	// Handle dotted netmask notation: e.g. 192.168.1.0/255.255.255.0
	if strings.Contains(token, "/") {
		parts := strings.SplitN(token, "/", 2)
		if strings.Contains(parts[1], ".") {
			if m := net.ParseIP(parts[1]).To4(); m != nil {
				if ones, bits := net.IPMask(m).Size(); bits == 32 && ones >= 0 {
					token = fmt.Sprintf("%s/%d", parts[0], ones)
				}
			}
		}
	}

	// Plain IP or CIDR
	if !strings.Contains(token, "/") {
		if ip, err := netip.ParseAddr(token); err == nil {
			if ip.Is4() {
				token = token + "/32"
			} else if ip.Is6() {
				token = token + "/128"
			}
		}
	}

	prefix, err := netip.ParsePrefix(token)
	if err != nil {
		return false, r4, false, r6, err
	}

	if prefix.Addr().Is4() {
		return true, prefixToIPv4Range(prefix), false, r6, nil
	} else if prefix.Addr().Is6() {
		return false, r4, true, prefixToIPv6Range(prefix), nil
	}

	return false, r4, false, r6, fmt.Errorf("unknown address family")
}

// IPCounter orchestrates ingestion, normalization, interval merging, and counting.
type IPCounter struct {
	v4Ranges     []IPv4Range
	v6Ranges     []IPv6Range
	details      []PrefixDetail
	trackDetails bool
}

// NewIPCounter initializes a clean IPCounter instance.
func NewIPCounter() *IPCounter {
	return &IPCounter{
		v4Ranges: make([]IPv4Range, 0, 16),
		v6Ranges: make([]IPv6Range, 0, 16),
	}
}

// SetTrackDetails controls whether PrefixDetail metadata is collected for each entry.
func (c *IPCounter) SetTrackDetails(track bool) {
	c.trackDetails = track
}

// Add processes a token representing an IP, CIDR, or range.
func (c *IPCounter) Add(token string) error {
	hasV4, r4, hasV6, r6, err := ParseToken(token)
	if err != nil {
		return err
	}

	if hasV4 {
		c.v4Ranges = append(c.v4Ranges, r4)
		if c.trackDetails {
			count := uint64(r4.End-r4.Start) + 1
			c.details = append(c.details, PrefixDetail{
				Raw:          token,
				Version:      4,
				StartAddress: uint32ToIP4(r4.Start).String(),
				EndAddress:   uint32ToIP4(r4.End).String(),
				CountStr:     strconv.FormatUint(count, 10),
			})
		}
	} else if hasV6 {
		c.v6Ranges = append(c.v6Ranges, r6)
		if c.trackDetails {
			one := big.NewInt(1)
			count := new(big.Int).Sub(r6.End, r6.Start)
			count.Add(count, one)
			c.details = append(c.details, PrefixDetail{
				Raw:          token,
				Version:      6,
				StartAddress: bigIntToIP6(r6.Start).String(),
				EndAddress:   bigIntToIP6(r6.End).String(),
				CountStr:     count.String(),
			})
		}
	}
	return nil
}

// Calculate consolidates ranges, eliminates duplicates/overlaps, and computes exact counts.
func (c *IPCounter) Calculate() AggregationResult {
	merged4 := MergeIPv4Ranges(c.v4Ranges)
	merged6 := MergeIPv6Ranges(c.v6Ranges)

	var totalV4 uint64
	for _, r := range merged4 {
		totalV4 += uint64(r.End-r.Start) + 1
	}

	totalV6 := new(big.Int)
	one := big.NewInt(1)
	diff := new(big.Int)
	for _, r := range merged6 {
		diff.Sub(r.End, r.Start)
		diff.Add(diff, one)
		totalV6.Add(totalV6, diff)
	}

	combined := new(big.Int).SetUint64(totalV4)
	combined.Add(combined, totalV6)

	var mergedCIDRs []string
	for _, r := range merged4 {
		for _, p := range RangeToIPv4Prefixes(r.Start, r.End) {
			mergedCIDRs = append(mergedCIDRs, p.String())
		}
	}
	for _, r := range merged6 {
		for _, p := range RangeToIPv6Prefixes(r.Start, r.End) {
			mergedCIDRs = append(mergedCIDRs, p.String())
		}
	}

	return AggregationResult{
		TotalIPv4Count:  totalV4,
		TotalIPv6Count:  totalV6,
		TotalCombined:   combined,
		IPv4RangesInput: len(c.v4Ranges),
		IPv4MergedCount: len(merged4),
		IPv6RangesInput: len(c.v6Ranges),
		IPv6MergedCount: len(merged6),
		MergedIPv4:      merged4,
		MergedIPv6:      merged6,
		MergedCIDRs:     mergedCIDRs,
		Details:         c.details,
	}
}

// formatWithCommas formats a numeric string with standard thousand-separators.
func formatWithCommas(s string) string {
	n := len(s)
	if n <= 3 {
		return s
	}
	var b strings.Builder
	rem := n % 3
	if rem > 0 {
		b.WriteString(s[:rem])
		if rem < n {
			b.WriteByte(',')
		}
	}
	for i := rem; i < n; i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < n {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// formatMetric returns formatted string with human-readable formatting if requested.
func formatMetric(val *big.Int, human bool) string {
	if val == nil {
		return "0"
	}
	raw := val.String()
	if !human {
		return raw
	}
	return formatWithCommas(raw)
}

func scanNetblockStream(r io.Reader, extractText bool, onToken func(string)) error {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		if extractText {
			matches := cidrExtractorRegex.FindAllString(line, -1)
			for _, match := range matches {
				onToken(match)
			}
			dottedMatches := reDottedCIDR.FindAllString(line, -1)
			for _, match := range dottedMatches {
				onToken(match)
			}
		} else {
			tokens := strings.Fields(line)
			for _, tok := range tokens {
				onToken(tok)
			}
		}
	}
	return scanner.Err()
}

func isNetblockCount(phrase string) bool {
	p := strings.ToLower(strings.TrimSpace(phrase))
	p = strings.Trim(p, "!?.")
	switch p {
	case "ip count", "count ip", "count ips", "ips count",
		"count total ips", "count total ip", "count total ip addresses", "total ips count",
		"total ips", "total ip", "ip total", "ips total",
		"netmask count", "count netmask", "count netmasks", "netmasks count",
		"cidr count", "count cidr", "count cidrs", "cidrs count",
		"count", "ip-count", "count-ips", "netmask-count", "cidr-count",
		"count ip addresses", "count all ips", "count all ip addresses",
		"count ips total", "count ip total", "ip address count", "ip addresses count":
		return true
	}
	norm := normalizeQuery(p)
	switch norm {
	case "ip count", "ips count", "total ips", "total ip", "ip addresses count", "ip address count",
		"netmask count", "netmasks count", "cidr count", "cidrs count",
		"count":
		return true
	}
	return false
}

func isNetblockMerge(phrase string) bool {
	p := strings.ToLower(strings.TrimSpace(phrase))
	p = strings.Trim(p, "!?.")
	switch p {
	case "merge ips", "merge ip", "ip merge", "ips merge", "merge ip addresses",
		"netmask merge", "netmasks merge", "merge netmask", "merge netmasks",
		"cidr merge", "cidrs merge", "merge cidr", "merge cidrs",
		"merge subnets", "subnet merge", "subnets merge", "merge subnet",
		"coalesce ips", "coalesce ip", "ip coalesce", "coalesce netmasks", "coalesce cidrs",
		"merge", "coalesce", "merge-ips", "netmask-merge", "cidr-merge",
		"merge all ips", "merge all netmasks", "merge all cidrs":
		return true
	}
	norm := normalizeQuery(p)
	switch norm {
	case "merge ips", "ips merge", "merge netmask", "merge netmasks", "netmask merge",
		"merge cidrs", "merge cidr", "cidr merge", "cidrs merge",
		"merge subnets", "subnet merge", "merge":
		return true
	}
	return false
}

type ParsedCLI struct {
	PrintWholeLine bool
	AfterCount     int
	BeforeCount    int
	ShowLineNum    bool
	UniqueOnly     bool
	CountOnly      bool
	ColorFlag      string

	HumanFormat   bool
	JSONOutput    bool
	ShowDetails   bool
	MergeMode     bool
	ExtractMode   bool
	FilePath      string
	HelpRequested bool

	PositionalArgs []string
}

func parseCommandLine(rawArgs []string) (ParsedCLI, error) {
	var p ParsedCLI
	p.ColorFlag = "auto"

	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]

		if arg == "-" {
			p.PositionalArgs = append(p.PositionalArgs, arg)
			continue
		}

		if strings.HasPrefix(arg, "-") {
			flagName := strings.TrimLeft(arg, "-")
			var flagVal string
			hasVal := false
			if strings.Contains(flagName, "=") {
				parts := strings.SplitN(flagName, "=", 2)
				flagName = parts[0]
				flagVal = parts[1]
				hasVal = true
			}

			switch flagName {
			case "line", "L", "whole-line":
				p.PrintWholeLine = true
			case "n":
				p.ShowLineNum = true
			case "u":
				p.UniqueOnly = true
			case "c":
				p.CountOnly = true
			case "h":
				p.HumanFormat = true
			case "help":
				p.HelpRequested = true
			case "json":
				p.JSONOutput = true
			case "details":
				p.ShowDetails = true
			case "merge":
				p.MergeMode = true
			case "x", "extract":
				p.ExtractMode = true
			case "A":
				if hasVal {
					val, err := strconv.Atoi(flagVal)
					if err != nil {
						return p, fmt.Errorf("invalid value for -A: %w", err)
					}
					p.AfterCount = val
				} else if i+1 < len(rawArgs) {
					i++
					val, err := strconv.Atoi(rawArgs[i])
					if err != nil {
						return p, fmt.Errorf("invalid value for -A: %w", err)
					}
					p.AfterCount = val
				} else {
					return p, fmt.Errorf("flag -A requires an argument")
				}
			case "B":
				if hasVal {
					val, err := strconv.Atoi(flagVal)
					if err != nil {
						return p, fmt.Errorf("invalid value for -B: %w", err)
					}
					p.BeforeCount = val
				} else if i+1 < len(rawArgs) {
					i++
					val, err := strconv.Atoi(rawArgs[i])
					if err != nil {
						return p, fmt.Errorf("invalid value for -B: %w", err)
					}
					p.BeforeCount = val
				} else {
					return p, fmt.Errorf("flag -B requires an argument")
				}
			case "color":
				if hasVal {
					p.ColorFlag = flagVal
				} else if i+1 < len(rawArgs) {
					i++
					p.ColorFlag = rawArgs[i]
				} else {
					return p, fmt.Errorf("flag --color requires an argument")
				}
			case "f":
				if hasVal {
					p.FilePath = flagVal
				} else if i+1 < len(rawArgs) {
					i++
					p.FilePath = rawArgs[i]
				} else {
					return p, fmt.Errorf("flag -f requires an argument")
				}
			default:
				allCharsValid := true
				for _, ch := range flagName {
					switch ch {
					case 'n':
						p.ShowLineNum = true
					case 'u':
						p.UniqueOnly = true
					case 'c':
						p.CountOnly = true
					case 'L':
						p.PrintWholeLine = true
					case 'h':
						p.HumanFormat = true
					case 'x':
						p.ExtractMode = true
					default:
						allCharsValid = false
					}
				}
				if !allCharsValid {
					return p, fmt.Errorf("unknown flag: %s", arg)
				}
			}
		} else {
			p.PositionalArgs = append(p.PositionalArgs, arg)
		}
	}

	return p, nil
}

func runNetblock(isMerge bool, p ParsedCLI) {
	counter := NewIPCounter()
	counter.SetTrackDetails(p.ShowDetails || p.JSONOutput)

	var pendingIP string
	var pendingDash bool

	consumeToken := func(tok string) {
		tokClean := strings.Trim(tok, "\"',;()[]")
		if tokClean == "" {
			return
		}

		if tokClean == "-" {
			if pendingIP != "" {
				pendingDash = true
			}
			return
		}

		if pendingDash {
			// Check if previous IP and current token form an inclusive range: startIP-endIP
			p1, err1 := netip.ParseAddr(strings.Trim(pendingIP, "\"',;()[]"))
			p2, err2 := netip.ParseAddr(tokClean)
			if err1 == nil && err2 == nil && ((p1.Is4() && p2.Is4()) || (p1.Is6() && p2.Is6())) {
				combined := pendingIP + "-" + tokClean
				pendingIP = ""
				pendingDash = false
				if err := counter.Add(combined); err != nil && !p.ExtractMode {
					fmt.Fprintf(os.Stderr, "nlgrep: warning: skipping invalid entry %q: %v\n", combined, err)
				}
				return
			}
			// Not a valid pair: commit pendingIP
			if err := counter.Add(pendingIP); err != nil && !p.ExtractMode {
				fmt.Fprintf(os.Stderr, "nlgrep: warning: skipping invalid entry %q: %v\n", pendingIP, err)
			}
			pendingIP = ""
			pendingDash = false
		}

		if pendingIP != "" {
			if err := counter.Add(pendingIP); err != nil && !p.ExtractMode {
				fmt.Fprintf(os.Stderr, "nlgrep: warning: skipping invalid entry %q: %v\n", pendingIP, err)
			}
			pendingIP = ""
		}

		// If this token is an IP address without range/prefix, hold it temporarily
		// in case the subsequent token is "-" (e.g. "10.0.0.1 - 10.0.0.10")
		if !strings.Contains(tokClean, "-") && !strings.Contains(tokClean, "/") {
			if pAddr, err := netip.ParseAddr(tokClean); err == nil && (pAddr.Is4() || pAddr.Is6()) {
				pendingIP = tokClean
				return
			}
		}

		if err := counter.Add(tokClean); err != nil {
			if errRaw := counter.Add(tok); errRaw != nil {
				if !p.ExtractMode {
					fmt.Fprintf(os.Stderr, "nlgrep: warning: skipping invalid entry %q: %v\n", tok, err)
				}
			}
		}
	}

	flushPending := func() {
		if pendingDash && pendingIP != "" {
			if err := counter.Add(pendingIP); err != nil && !p.ExtractMode {
				fmt.Fprintf(os.Stderr, "nlgrep: warning: skipping invalid entry %q: %v\n", pendingIP, err)
			}
			pendingIP = ""
			pendingDash = false
		} else if pendingIP != "" {
			if err := counter.Add(pendingIP); err != nil && !p.ExtractMode {
				fmt.Fprintf(os.Stderr, "nlgrep: warning: skipping invalid entry %q: %v\n", pendingIP, err)
			}
			pendingIP = ""
		}
	}

	if p.FilePath != "" {
		f, err := os.Open(p.FilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nlgrep: failed to open file: %v\n", err)
			os.Exit(1)
		}
		_ = scanNetblockStream(f, p.ExtractMode, consumeToken)
		flushPending()
		f.Close()
	}

	hasStdinDash := false
	hasPositionalInput := false
	for i := 0; i < len(p.PositionalArgs); i++ {
		arg := p.PositionalArgs[i]
		if arg == "-" {
			if pendingIP != "" && i+1 < len(p.PositionalArgs) {
				next := p.PositionalArgs[i+1]
				p1, err1 := netip.ParseAddr(strings.Trim(pendingIP, "\"',;()[]"))
				p2, err2 := netip.ParseAddr(strings.Trim(next, "\"',;()[]"))
				if err1 == nil && err2 == nil && ((p1.Is4() && p2.Is4()) || (p1.Is6() && p2.Is6())) {
					pendingDash = true
					continue
				}
			}
			flushPending()
			hasStdinDash = true
			continue
		}
		if fi, err := os.Stat(arg); err == nil && !fi.IsDir() {
			hasPositionalInput = true
			flushPending()
			f, err := os.Open(arg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "nlgrep: failed to open file: %v\n", err)
				os.Exit(1)
			}
			_ = scanNetblockStream(f, p.ExtractMode, consumeToken)
			flushPending()
			f.Close()
		} else {
			hasPositionalInput = true
			if p.ExtractMode {
				matches := cidrExtractorRegex.FindAllString(arg, -1)
				for _, match := range matches {
					consumeToken(match)
				}
				dottedMatches := reDottedCIDR.FindAllString(arg, -1)
				for _, match := range dottedMatches {
					consumeToken(match)
				}
			} else {
				for _, tok := range strings.Fields(arg) {
					consumeToken(tok)
				}
			}
		}
	}
	flushPending()

	if hasStdinDash || (!hasPositionalInput && p.FilePath == "") {
		_ = scanNetblockStream(os.Stdin, p.ExtractMode, consumeToken)
		flushPending()
	}

	res := counter.Calculate()

	if p.JSONOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}

	if p.ShowDetails {
		fmt.Println("-----------------------------------------------------------------------------------------")
		fmt.Printf("%-22s %-18s %-18s %15s\n", "Prefix / Target", "Start IP", "End IP", "Addresses")
		fmt.Println("-----------------------------------------------------------------------------------------")
		for _, d := range res.Details {
			c := d.CountStr
			if p.HumanFormat {
				c = formatWithCommas(c)
			}
			fmt.Printf("%-22s %-18s %-18s %15s\n", d.Raw, d.StartAddress, d.EndAddress, c)
		}
		fmt.Println("-----------------------------------------------------------------------------------------")
		fmt.Printf("Total IPv4 Prefixes Input : %d (Merged into %d contiguous blocks)\n", res.IPv4RangesInput, res.IPv4MergedCount)
		if res.IPv6RangesInput > 0 {
			fmt.Printf("Total IPv6 Prefixes Input : %d (Merged into %d contiguous blocks)\n", res.IPv6RangesInput, res.IPv6MergedCount)
		}
		fmt.Printf("Total Unique Addresses    : %s\n", formatMetric(res.TotalCombined, p.HumanFormat))
		return
	}

	if isMerge {
		for _, cidr := range res.MergedCIDRs {
			fmt.Println(cidr)
		}
		return
	}

	fmt.Println(formatMetric(res.TotalCombined, p.HumanFormat))
}

type CommandMode int

const (
	ModeUnknown CommandMode = iota
	ModeHelp
	ModeNetblockCount
	ModeNetblockMerge
	ModeExtract
)

func isLikelyTarget(arg string) bool {
	if arg == "-" {
		return true
	}
	if fi, err := os.Stat(arg); err == nil && !fi.IsDir() {
		return true
	}
	if strings.ContainsAny(arg, ".:/") {
		return true
	}
	if strings.Contains(arg, "-") && strings.ContainsAny(arg, "0123456789") {
		return true
	}
	if hasV4, _, hasV6, _, _ := ParseToken(arg); hasV4 || hasV6 {
		return true
	}
	return false
}

func run(args []string) int {
	parsed, err := parseCommandLine(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		PrintHelp()
		return 1
	}

	if len(args) == 0 {
		PrintHelp()
		return 1
	}

	if parsed.HelpRequested {
		PrintHelp()
		return 0
	}

	if len(parsed.PositionalArgs) == 0 && !parsed.MergeMode && !parsed.JSONOutput && !parsed.ShowDetails {
		if parsed.HumanFormat {
			PrintHelp()
			return 0
		}
	}

	if len(parsed.PositionalArgs) > 0 {
		first := strings.ToLower(parsed.PositionalArgs[0])
		if first == "help" || first == "list" {
			PrintHelp()
			return 0
		}
	}

	mode := ModeUnknown
	matchedWords := 0
	var selectedExtractor *Extractor

	if parsed.MergeMode {
		mode = ModeNetblockMerge
	}

	maxN := 0
	for _, arg := range parsed.PositionalArgs {
		if isLikelyTarget(arg) {
			break
		}
		maxN++
	}
	if maxN > 4 {
		maxN = 4
	}
	if maxN == 0 && len(parsed.PositionalArgs) > 0 {
		maxN = 1
	}

	if mode == ModeUnknown {
		// Tier 1: Exact matches (longest first)
		for n := maxN; n >= 1; n-- {
			phrase := strings.Join(parsed.PositionalArgs[:n], " ")
			if isNetblockMerge(phrase) {
				mode = ModeNetblockMerge
				matchedWords = n
				break
			}
			if isNetblockCount(phrase) {
				mode = ModeNetblockCount
				matchedWords = n
				break
			}
			if ext := ResolveIntentExact(phrase); ext != nil {
				mode = ModeExtract
				matchedWords = n
				selectedExtractor = ext
				break
			}
		}
	}

	if mode == ModeUnknown {
		// Tier 2: Fuzzy / natural language query fallback (longest first)
		for n := maxN; n >= 1; n-- {
			phrase := strings.Join(parsed.PositionalArgs[:n], " ")
			if ext := ResolveIntent(phrase); ext != nil {
				mode = ModeExtract
				matchedWords = n
				selectedExtractor = ext
				break
			}
		}
	}

	if mode == ModeUnknown {
		if parsed.JSONOutput || parsed.ShowDetails {
			mode = ModeNetblockCount
		} else if len(parsed.PositionalArgs) > 0 {
			if hasV4, _, hasV6, _, _ := ParseToken(parsed.PositionalArgs[0]); hasV4 || hasV6 {
				mode = ModeNetblockCount
			}
		}
	}

	switch mode {
	case ModeNetblockMerge:
		parsed.PositionalArgs = parsed.PositionalArgs[matchedWords:]
		runNetblock(true, parsed)
		return 0

	case ModeNetblockCount:
		parsed.PositionalArgs = parsed.PositionalArgs[matchedWords:]
		runNetblock(false, parsed)
		return 0

	case ModeExtract:
		fileNames := parsed.PositionalArgs[matchedWords:]
		var cfg Config
		cfg.PrintWholeLine = parsed.PrintWholeLine
		cfg.AfterCount = parsed.AfterCount
		cfg.BeforeCount = parsed.BeforeCount
		cfg.ShowLineNum = parsed.ShowLineNum
		cfg.UniqueOnly = parsed.UniqueOnly
		cfg.CountOnly = parsed.CountOnly
		if matchedWords > 0 && strings.HasPrefix(strings.ToLower(parsed.PositionalArgs[0]), "count") {
			cfg.CountOnly = true
		}

		switch parsed.ColorFlag {
		case "always":
			cfg.Color = true
		case "never":
			cfg.Color = false
		default:
			fileInfo, _ := os.Stdout.Stat()
			cfg.Color = (fileInfo.Mode() & os.ModeCharDevice) != 0
		}

		if cfg.AfterCount > 0 || cfg.BeforeCount > 0 {
			cfg.PrintWholeLine = true
		}

		var inputs []inputSource
		if len(fileNames) == 0 {
			inputs = append(inputs, inputSource{name: "(standard input)", reader: os.Stdin})
		} else {
			for _, fn := range fileNames {
				f, err := os.Open(fn)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", fn, err)
					return 3
				}
				defer f.Close()
				inputs = append(inputs, inputSource{name: fn, reader: f})
			}
		}

		totalCount := 0
		seen := make(map[string]bool)

		for _, in := range inputs {
			cnt := processStream(in, selectedExtractor, cfg, seen)
			totalCount += cnt
		}

		if cfg.CountOnly {
			fmt.Println(totalCount)
		}
		return 0

	default:
		rawQuery := ""
		if len(parsed.PositionalArgs) > 0 {
			rawQuery = parsed.PositionalArgs[0]
		}
		fmt.Fprintf(os.Stderr, "Error: unrecognized data type or query: %q\n", rawQuery)
		fmt.Fprintf(os.Stderr, "Run 'nlgrep list' to see all supported data types.\n")
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}
