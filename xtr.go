package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
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
	reNameHonorific = regexp.MustCompile(`\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Rev\.|Hon\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b`)
	reSubject       = regexp.MustCompile(`(?i)^(?:\s*(?:subject|re|fwd|fw)):\s*(.+)`)
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

func ResolveIntent(rawQuery string) *Extractor {
	q := normalizeQuery(rawQuery)
	if q == "" {
		return nil
	}

	// 1. Exact match on ID or Alias
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
				for _, aw := range aliasWords {
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

	// 3. Fuzzy Levenshtein match for typos (distance <= 2)
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

	return nil
}

func PrintHelp() {
	fmt.Fprintf(os.Stderr, "xtr - Fast, standalone semantic data extractor for Linux\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  xtr [options] <data-type | \"natural language query\"> [file ...]\n")
	fmt.Fprintf(os.Stderr, "  cat input.txt | xtr [options] <data-type | \"query\">\n\n")

	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  --line, -L, -whole-line   Print the ENTIRE line containing the pattern (default: pattern only)\n")
	fmt.Fprintf(os.Stderr, "  -A <number>               Print <number> lines after and including the matching line\n")
	fmt.Fprintf(os.Stderr, "  -B <number>               Print <number> lines before and including the matching line\n")
	fmt.Fprintf(os.Stderr, "  -n                        Show 1-based line numbers\n")
	fmt.Fprintf(os.Stderr, "  -u                        Deduplicate matching values\n")
	fmt.Fprintf(os.Stderr, "  -c                        Print only count of matches\n")
	fmt.Fprintf(os.Stderr, "  --color                   Highlight matched patterns (default: auto)\n\n")

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

	fmt.Fprintf(os.Stderr, "\nNatural Language Examples:\n")
	fmt.Fprintf(os.Stderr, "  xtr urls access.log\n")
	fmt.Fprintf(os.Stderr, "  xtr \"find all email addresses\" contacts.txt\n")
	fmt.Fprintf(os.Stderr, "  xtr --line \"show credit cards\" dump.sql\n")
	fmt.Fprintf(os.Stderr, "  xtr -B 2 -A 3 urls server.log\n")
	fmt.Fprintf(os.Stderr, "  cat syslog | xtr -n ips\n")
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

func main() {
	var cfg Config

	flag.BoolVar(&cfg.PrintWholeLine, "line", false, "Print entire line containing match")
	flag.BoolVar(&cfg.PrintWholeLine, "L", false, "Print entire line containing match (alias for --line)")
	flag.BoolVar(&cfg.PrintWholeLine, "whole-line", false, "Print entire line containing match (alias for --line)")
	flag.IntVar(&cfg.AfterCount, "A", 0, "Number of lines after and including the matching line")
	flag.IntVar(&cfg.BeforeCount, "B", 0, "Number of lines before and including the matching line")
	flag.BoolVar(&cfg.ShowLineNum, "n", false, "Prefix each output line with 1-based line number")
	flag.BoolVar(&cfg.UniqueOnly, "u", false, "Deduplicate matches")
	flag.BoolVar(&cfg.CountOnly, "c", false, "Print only count of matched items")
	colorFlag := flag.String("color", "auto", "Colorize output: always, never, auto")

	flag.Usage = PrintHelp
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		PrintHelp()
		os.Exit(1)
	}

	query := args[0]
	if query == "list" || query == "help" || query == "--help" || query == "-h" {
		PrintHelp()
		os.Exit(0)
	}

	extractor := ResolveIntent(query)
	if extractor == nil {
		fmt.Fprintf(os.Stderr, "Error: unrecognized data type or query: %q\n", query)
		fmt.Fprintf(os.Stderr, "Run 'xtr list' to see all supported data types.\n")
		os.Exit(2)
	}

	switch *colorFlag {
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

	fileNames := args[1:]
	var inputs []inputSource
	if len(fileNames) == 0 {
		inputs = append(inputs, inputSource{name: "(standard input)", reader: os.Stdin})
	} else {
		for _, fn := range fileNames {
			f, err := os.Open(fn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", fn, err)
				os.Exit(3)
			}
			defer f.Close()
			inputs = append(inputs, inputSource{name: fn, reader: f})
		}
	}

	totalCount := 0
	seen := make(map[string]bool)

	for _, in := range inputs {
		cnt := processStream(in, extractor, cfg, seen)
		totalCount += cnt
	}

	if cfg.CountOnly {
		fmt.Println(totalCount)
	}
}
