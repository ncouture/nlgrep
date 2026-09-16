package main

import (
	"bytes"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var testBinary string

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "xtr_test_*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	testBinary = filepath.Join(tmpDir, "nlgrep")
	buildCmd := exec.Command("go", "build", "-o", testBinary, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build test binary: %v: %s\n", err, string(out))
		os.Exit(1)
	}

	exitCode := m.Run()
	os.Exit(exitCode)
}

// TestOriginal29Extractors verifies that all 29 pre-existing extractors plus cidrs exist and function.
func TestOriginal29Extractors(t *testing.T) {
	expectedExtractors := []string{
		"urls", "emails", "phone_numbers", "ips", "credit_cards",
		"ibans", "uuids", "mac_addresses", "cves", "dois",
		"semver", "ssns", "crypto", "vins", "isbns",
		"hashes", "dates", "coordinates", "cron", "asns",
		"currencies", "domains", "jsonpath", "xpath", "metar",
		"chess_fen", "user_agents", "names", "subjects", "cidrs",
	}

	for _, id := range expectedExtractors {
		ext := ResolveIntent(id)
		if ext == nil {
			t.Errorf("expected extractor %q to be resolved by ResolveIntent, got nil", id)
		} else if ext.ID != id {
			t.Errorf("resolved extractor ID %q does not match expected %q", ext.ID, id)
		}
	}
}

// TestExtractorSanity checks sample matches for each key category.
func TestExtractorSanity(t *testing.T) {
	tests := []struct {
		extractorID string
		input       string
		expected    string
	}{
		{"urls", "Visit https://example.com/api today", "https://example.com/api"},
		{"emails", "Contact test@example.com for info", "test@example.com"},
		{"phone_numbers", "Call +1-555-123-4567 now", "+1-555-123-4567"},
		{"ips", "Server at 192.168.1.1 online", "192.168.1.1"},
		{"cidrs", "Subnet 10.0.0.0/24 configured", "10.0.0.0/24"},
		{"cidrs", "IPv6 prefix 2001:db8::/32 configured", "2001:db8::/32"},
		{"cidrs", "Netmask 255.255.255.0 configured", "255.255.255.0"},
		{"uuids", "ID: 123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174000"},
		{"cves", "Found CVE-2021-44228 in log", "CVE-2021-44228"},
		{"semver", "Release v1.2.3-beta.1 available", "v1.2.3-beta.1"},
		{"domains", "Host api.github.com reachable", "api.github.com"},
	}

	for _, tc := range tests {
		ext := ResolveIntent(tc.extractorID)
		if ext == nil {
			t.Fatalf("extractor %q not found", tc.extractorID)
		}
		matches := ext.Extract(tc.input)
		if len(matches) == 0 {
			t.Errorf("extractor %q found no matches in %q", tc.extractorID, tc.input)
		} else if matches[0].Value != tc.expected {
			t.Errorf("extractor %q match = %q, expected %q", tc.extractorID, matches[0].Value, tc.expected)
		}
	}
}

// TestSubcommandRouting tests natural language queries and routing.
func TestSubcommandRouting(t *testing.T) {
	countPhrases := []string{
		"ip count", "count total ips", "netmask count", "count ips",
		"count ip addresses", "total ips", "count", "cidr count",
	}
	for _, p := range countPhrases {
		if !isNetblockCount(p) {
			t.Errorf("expected %q to be recognized as netblock count", p)
		}
	}

	mergePhrases := []string{
		"merge ips", "netmask merge", "merge netmasks", "merge cidrs",
		"merge subnets", "merge", "coalesce ips",
	}
	for _, p := range mergePhrases {
		if !isNetblockMerge(p) {
			t.Errorf("expected %q to be recognized as netblock merge", p)
		}
	}

	// Extraction phrases must NOT be recognized as count or merge
	extractPhrases := []string{
		"get ip addresses", "get ipv4", "get netmask", "get cidrs",
		"find emails", "urls", "cves",
	}
	for _, p := range extractPhrases {
		if isNetblockCount(p) {
			t.Errorf("expected %q NOT to be recognized as netblock count", p)
		}
		if isNetblockMerge(p) {
			t.Errorf("expected %q NOT to be recognized as netblock merge", p)
		}
	}
}

// TestParseToken tests token parsing for IPv4, IPv6, ranges, and CIDRs.
func TestParseToken(t *testing.T) {
	// IPv4 single
	has4, r4, has6, _, err := ParseToken("192.168.1.1")
	if err != nil || !has4 || has6 || r4.Start != r4.End {
		t.Errorf("failed to parse IPv4 single: %v", err)
	}

	// IPv4 CIDR
	has4, r4, has6, _, err = ParseToken("10.0.0.0/24")
	if err != nil || !has4 || has6 || r4.End-r4.Start+1 != 256 {
		t.Errorf("failed to parse IPv4 CIDR: %v", err)
	}

	// IPv4 range
	has4, r4, has6, _, err = ParseToken("10.0.0.1-10.0.0.10")
	if err != nil || !has4 || has6 || r4.End-r4.Start+1 != 10 {
		t.Errorf("failed to parse IPv4 range: %v", err)
	}

	// IPv4 inverted range
	has4, r4, has6, _, err = ParseToken("10.0.0.10-10.0.0.1")
	if err != nil || !has4 || has6 || r4.End-r4.Start+1 != 10 {
		t.Errorf("failed to parse inverted IPv4 range: %v", err)
	}

	// IPv4 dotted netmask
	has4, r4, has6, _, err = ParseToken("192.168.1.0/255.255.255.0")
	if err != nil || !has4 || has6 || r4.End-r4.Start+1 != 256 {
		t.Errorf("failed to parse dotted netmask: %v", err)
	}

	// IPv6 single
	has4, _, has6, r6, err := ParseToken("2001:db8::1")
	if err != nil || has4 || !has6 || r6.Start.Cmp(r6.End) != 0 {
		t.Errorf("failed to parse IPv6 single: %v", err)
	}

	// IPv6 CIDR
	has4, _, has6, r6, err = ParseToken("2001:db8::/120")
	if err != nil || has4 || !has6 {
		t.Errorf("failed to parse IPv6 CIDR: %v", err)
	}
	diff := new(big.Int).Sub(r6.End, r6.Start)
	diff.Add(diff, big.NewInt(1))
	if diff.Int64() != 256 {
		t.Errorf("expected 256 addresses for /120, got %s", diff.String())
	}

	// IPv6 range
	has4, _, has6, r6, err = ParseToken("2001:db8::1-2001:db8::10")
	if err != nil || has4 || !has6 {
		t.Errorf("failed to parse IPv6 range: %v", err)
	}
	diff = new(big.Int).Sub(r6.End, r6.Start)
	diff.Add(diff, big.NewInt(1))
	if diff.Int64() != 16 {
		t.Errorf("expected 16 addresses for 2001:db8::1-2001:db8::10, got %s", diff.String())
	}
}

// TestIntervalCoalescingIPv4 tests merging contiguous and overlapping IPv4 intervals.
func TestIntervalCoalescingIPv4(t *testing.T) {
	c := NewIPCounter()
	_ = c.Add("10.0.0.0/24")
	_ = c.Add("10.0.1.0/24")
	res := c.Calculate()

	if res.TotalCombined.Int64() != 512 {
		t.Errorf("expected 512 addresses, got %s", res.TotalCombined.String())
	}
	if len(res.MergedCIDRs) != 1 || res.MergedCIDRs[0] != "10.0.0.0/23" {
		t.Errorf("expected merged CIDR 10.0.0.0/23, got %v", res.MergedCIDRs)
	}
}

// TestIntervalCoalescingOverlappingIPv4 tests duplicate/overlapping address elimination.
func TestIntervalCoalescingOverlappingIPv4(t *testing.T) {
	c := NewIPCounter()
	_ = c.Add("10.0.0.0/24")
	_ = c.Add("10.0.0.128/25")
	_ = c.Add("10.0.0.50")
	res := c.Calculate()

	if res.TotalCombined.Int64() != 256 {
		t.Errorf("expected 256 addresses after deduplication, got %s", res.TotalCombined.String())
	}
	if len(res.MergedCIDRs) != 1 || res.MergedCIDRs[0] != "10.0.0.0/24" {
		t.Errorf("expected merged CIDR 10.0.0.0/24, got %v", res.MergedCIDRs)
	}
}

// TestIntervalCoalescingIPv6 tests merging IPv6 ranges.
func TestIntervalCoalescingIPv6(t *testing.T) {
	c := NewIPCounter()
	_ = c.Add("2001:db8::/64")
	_ = c.Add("2001:db8:0:1::/64")
	res := c.Calculate()

	if len(res.MergedCIDRs) != 1 || res.MergedCIDRs[0] != "2001:db8::/63" {
		t.Errorf("expected merged CIDR 2001:db8::/63, got %v", res.MergedCIDRs)
	}

	// 2^65 = 36893488147419103232
	expectedCount := "36893488147419103232"
	if res.TotalCombined.String() != expectedCount {
		t.Errorf("expected %s addresses, got %s", expectedCount, res.TotalCombined.String())
	}
}

// TestRangeToPrefixes verifies range to minimal CIDR decomposition.
func TestRangeToPrefixes(t *testing.T) {
	// IPv4 [10.0.0.0, 10.0.1.255] -> 10.0.0.0/23
	start4 := ip4ToUint32(netip.MustParseAddr("10.0.0.0").As4())
	end4 := ip4ToUint32(netip.MustParseAddr("10.0.1.255").As4())
	p4 := RangeToIPv4Prefixes(start4, end4)
	if len(p4) != 1 || p4[0].String() != "10.0.0.0/23" {
		t.Errorf("RangeToIPv4Prefixes failed, got %v", p4)
	}

	// IPv6 [2001:db8::, 2001:db8:0:1:ffff:ffff:ffff:ffff] -> 2001:db8::/63
	start6 := ip6ToBigInt(netip.MustParseAddr("2001:db8::").As16())
	end6 := ip6ToBigInt(netip.MustParseAddr("2001:db8:0:1:ffff:ffff:ffff:ffff").As16())
	p6 := RangeToIPv6Prefixes(start6, end6)
	if len(p6) != 1 || p6[0].String() != "2001:db8::/63" {
		t.Errorf("RangeToIPv6Prefixes failed, got %v", p6)
	}
}

// TestFormatWithCommas verifies thousand separator formatting.
func TestFormatWithCommas(t *testing.T) {
	cases := map[string]string{
		"0":                    "0",
		"12":                   "12",
		"123":                  "123",
		"1234":                 "1,234",
		"12345":                "12,345",
		"123456":               "123,456",
		"1234567":              "1,234,567",
		"18446744073709551616": "18,446,744,073,709,551,616",
	}
	for in, exp := range cases {
		out := formatWithCommas(in)
		if out != exp {
			t.Errorf("formatWithCommas(%q) = %q, expected %q", in, out, exp)
		}
	}
}

// TestCLIEndToEnd verifies CLI execution of all acceptance criteria scenarios.
func TestCLIEndToEnd(t *testing.T) {
	binary := testBinary

	// Scenario 1: Pipe extraction to IP counting
	cmd1 := exec.Command(binary, "get", "ip", "addresses")
	cmd1.Stdin = strings.NewReader("192.168.1.10\n192.168.1.11\n192.168.1.10\n")
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("cmd1 failed: %v", err)
	}
	cmd1Count := exec.Command(binary, "ip", "count")
	cmd1Count.Stdin = bytes.NewReader(out1)
	out1Count, err := cmd1Count.Output()
	if err != nil {
		t.Fatalf("cmd1Count failed: %v", err)
	}
	if strings.TrimSpace(string(out1Count)) != "2" {
		t.Errorf("Scenario 1 failed: expected 2, got %q", string(out1Count))
	}

	// Scenario 2: CIDR extraction piped to merge
	cmd2 := exec.Command(binary, "merge", "ips")
	cmd2.Stdin = strings.NewReader("10.0.0.0/24\n10.0.1.0/24\n")
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("cmd2 failed: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "10.0.0.0/23" {
		t.Errorf("Scenario 2 failed: expected 10.0.0.0/23, got %q", string(out2))
	}

	// Scenario 3: Multi-stage pipeline get netmask | netmask merge | ip count
	cmd3Stage1 := exec.Command(binary, "get", "netmask")
	cmd3Stage1.Stdin = strings.NewReader("172.16.0.0/24\n172.16.1.0/24\n")
	out3Stage1, err := cmd3Stage1.Output()
	if err != nil {
		t.Fatalf("cmd3Stage1 failed: %v", err)
	}

	cmd3Stage2 := exec.Command(binary, "netmask", "merge")
	cmd3Stage2.Stdin = bytes.NewReader(out3Stage1)
	out3Stage2, err := cmd3Stage2.Output()
	if err != nil {
		t.Fatalf("cmd3Stage2 failed: %v", err)
	}

	cmd3Stage3 := exec.Command(binary, "ip", "count")
	cmd3Stage3.Stdin = bytes.NewReader(out3Stage2)
	out3Stage3, err := cmd3Stage3.Output()
	if err != nil {
		t.Fatalf("cmd3Stage3 failed: %v", err)
	}
	if strings.TrimSpace(string(out3Stage3)) != "512" {
		t.Errorf("Scenario 3 failed: expected 512, got %q", string(out3Stage3))
	}

	// Scenario 4: Hyphenated range positional argument
	cmd4 := exec.Command(binary, "ip", "count", "10.0.0.1-10.0.0.10")
	out4, err := cmd4.Output()
	if err != nil {
		t.Fatalf("cmd4 failed: %v", err)
	}
	if strings.TrimSpace(string(out4)) != "10" {
		t.Errorf("Scenario 4 failed: expected 10, got %q", string(out4))
	}

	// Scenario 5: Backward compatibility extractor
	cmd5 := exec.Command(binary, "emails")
	cmd5.Stdin = strings.NewReader("test@example.com\n")
	out5, err := cmd5.Output()
	if err != nil {
		t.Fatalf("cmd5 failed: %v", err)
	}
	if strings.TrimSpace(string(out5)) != "test@example.com" {
		t.Errorf("Scenario 5 failed: expected test@example.com, got %q", string(out5))
	}
}

// TestExtractorFlags tests flags like -u, -n, -c, --line.
func TestExtractorFlags(t *testing.T) {
	binary := testBinary

	// Test -u (unique)
	cmdU := exec.Command(binary, "-u", "emails")
	cmdU.Stdin = strings.NewReader("a@b.com\na@b.com\nb@c.com\n")
	outU, err := cmdU.Output()
	if err != nil {
		t.Fatalf("-u failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(outU)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 unique emails, got %d: %v", len(lines), lines)
	}

	// Test -c (count matches)
	cmdC := exec.Command(binary, "-c", "emails")
	cmdC.Stdin = strings.NewReader("a@b.com\na@b.com\nb@c.com\n")
	outC, err := cmdC.Output()
	if err != nil {
		t.Fatalf("-c failed: %v", err)
	}
	if strings.TrimSpace(string(outC)) != "3" {
		t.Errorf("expected count 3, got %q", string(outC))
	}

	// Test -n (line numbers)
	cmdN := exec.Command(binary, "-n", "emails")
	cmdN.Stdin = strings.NewReader("first line\nsecond line a@b.com\n")
	outN, err := cmdN.Output()
	if err != nil {
		t.Fatalf("-n failed: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(outN)), "2:a@b.com") {
		t.Errorf("expected line number 2, got %q", string(outN))
	}

	// Test --line (whole line)
	cmdLine := exec.Command(binary, "--line", "emails")
	cmdLine.Stdin = strings.NewReader("user info: a@b.com active\n")
	outLine, err := cmdLine.Output()
	if err != nil {
		t.Fatalf("--line failed: %v", err)
	}
	if strings.TrimSpace(string(outLine)) != "user info: a@b.com active" {
		t.Errorf("expected whole line, got %q", string(outLine))
	}
}

// TestNetblockFlags tests -h, --json, and --details for netblock operations.
func TestNetblockFlags(t *testing.T) {
	binary := testBinary

	// -h
	cmdH := exec.Command(binary, "ip", "count", "-h", "10.0.0.0/16")
	outH, err := cmdH.Output()
	if err != nil {
		t.Fatalf("-h failed: %v", err)
	}
	if strings.TrimSpace(string(outH)) != "65,536" {
		t.Errorf("expected 65,536, got %q", string(outH))
	}

	// --json
	cmdJSON := exec.Command(binary, "ip", "count", "--json", "10.0.0.0/24", "10.0.1.0/24")
	outJSON, err := cmdJSON.Output()
	if err != nil {
		t.Fatalf("--json failed: %v", err)
	}
	if !strings.Contains(string(outJSON), `"total_unique_ips": 512`) {
		t.Errorf("expected JSON to contain total_unique_ips: 512, got %q", string(outJSON))
	}
	if !strings.Contains(string(outJSON), `"10.0.0.0/23"`) {
		t.Errorf("expected JSON to contain merged CIDR 10.0.0.0/23, got %q", string(outJSON))
	}

	// --details
	cmdDetails := exec.Command(binary, "ip", "count", "--details", "10.0.0.0/24")
	outDetails, err := cmdDetails.Output()
	if err != nil {
		t.Fatalf("--details failed: %v", err)
	}
	if !strings.Contains(string(outDetails), "Total Unique Addresses    : 256") {
		t.Errorf("expected details to contain total unique addresses 256, got %q", string(outDetails))
	}
}

// TestFileAndPipedInput tests file positional argument and file via -f flag.
func TestFileAndPipedInput(t *testing.T) {
	binary := testBinary
	tmpFile, err := os.CreateTemp("", "test_subnets_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	_, _ = tmpFile.WriteString("192.168.0.0/24\n192.168.1.0/24\n")
	_ = tmpFile.Close()

	// Positional file
	cmd1 := exec.Command(binary, "ip", "count", tmpFile.Name())
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("positional file failed: %v", err)
	}
	if strings.TrimSpace(string(out1)) != "512" {
		t.Errorf("expected 512, got %q", string(out1))
	}

	// File via -f
	cmd2 := exec.Command(binary, "ip", "count", "-f", tmpFile.Name())
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("-f file failed: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "512" {
		t.Errorf("expected 512, got %q", string(out2))
	}
}

// TestLeadingCompressedIPv6CIDRs tests ::/0, ::1/128 and leading-colon CIDRs.
func TestLeadingCompressedIPv6CIDRs(t *testing.T) {
	binary := testBinary

	// Extraction via get cidrs
	cmd1 := exec.Command(binary, "get", "cidrs")
	cmd1.Stdin = strings.NewReader("::/0\n::1/128\n2001:db8::/32\n")
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("cmd1 failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out1)), "\n")
	if len(lines) != 3 || lines[0] != "::/0" || lines[1] != "::1/128" || lines[2] != "2001:db8::/32" {
		t.Errorf("expected [::/0 ::1/128 2001:db8::/32], got %v", lines)
	}

	// Counting via -x
	cmd2 := exec.Command(binary, "ip", "count", "-x")
	cmd2.Stdin = strings.NewReader("Freeform text with ::1/128 and 10.0.0.0/24 inside")
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("cmd2 failed: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "257" {
		t.Errorf("expected 257 (256+1), got %q", string(out2))
	}
}

// TestDottedCIDRExtraction tests dotted subnet masks with -x.
func TestDottedCIDRExtraction(t *testing.T) {
	binary := testBinary
	cmd := exec.Command(binary, "ip", "count", "-x")
	cmd.Stdin = strings.NewReader("Config interface 192.168.1.0/255.255.255.0 enabled")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cmd failed: %v", err)
	}
	if strings.TrimSpace(string(out)) != "256" {
		t.Errorf("expected 256 addresses for dotted CIDR, got %q", string(out))
	}
}

// TestIPv6ZoneIdentifiers verifies parsing of scoped IPv6 addresses.
func TestIPv6ZoneIdentifiers(t *testing.T) {
	binary := testBinary

	// Single IP with zone
	cmd1 := exec.Command(binary, "ip", "count", "fe80::1%eth0")
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("cmd1 failed: %v", err)
	}
	if strings.TrimSpace(string(out1)) != "1" {
		t.Errorf("expected 1, got %q", string(out1))
	}

	// CIDR with zone
	cmd2 := exec.Command(binary, "ip", "count", "fe80::%eth0/64")
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("cmd2 failed: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "18446744073709551616" {
		t.Errorf("expected 18446744073709551616, got %q", string(out2))
	}

	// Range with zones
	cmd3 := exec.Command(binary, "ip", "count", "fe80::1%eth0-fe80::10%eth0")
	out3, err := cmd3.Output()
	if err != nil {
		t.Fatalf("cmd3 failed: %v", err)
	}
	if strings.TrimSpace(string(out3)) != "16" {
		t.Errorf("expected 16, got %q", string(out3))
	}
}

// TestSpacedHyphenRanges verifies ranges with whitespace around hyphen.
func TestSpacedHyphenRanges(t *testing.T) {
	binary := testBinary

	// CLI argument
	cmd1 := exec.Command(binary, "ip", "count", "10.0.0.1", "-", "10.0.0.10")
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("cmd1 failed: %v", err)
	}
	if strings.TrimSpace(string(out1)) != "10" {
		t.Errorf("expected 10, got %q", string(out1))
	}

	// Piped input
	cmd2 := exec.Command(binary, "ip", "count")
	cmd2.Stdin = strings.NewReader("10.0.0.1 - 10.0.0.10\n")
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("cmd2 failed: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "10" {
		t.Errorf("expected 10, got %q", string(out2))
	}
}

// TestBracketedAddresses verifies bracketed IPv6 parsing.
func TestBracketedAddresses(t *testing.T) {
	binary := testBinary
	cmd := exec.Command(binary, "ip", "count", "[2001:db8::1]")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cmd failed: %v", err)
	}
	if strings.TrimSpace(string(out)) != "1" {
		t.Errorf("expected 1, got %q", string(out))
	}
}

// TestNaturalLanguagePrecedence verifies multi-word extractor queries are not hijacked by netblock.
func TestNaturalLanguagePrecedence(t *testing.T) {
	binary := testBinary

	// "count emails"
	cmd1 := exec.Command(binary, "count", "emails")
	cmd1.Stdin = strings.NewReader("user@example.com\nother@example.com\n")
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("cmd1 failed: %v", err)
	}
	if strings.TrimSpace(string(out1)) != "2" {
		t.Errorf("expected 2, got %q", string(out1))
	}

	// "merge emails"
	cmd2 := exec.Command(binary, "merge", "emails")
	cmd2.Stdin = strings.NewReader("user@example.com\n")
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("cmd2 failed: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "user@example.com" {
		t.Errorf("expected user@example.com, got %q", string(out2))
	}

	// "count urls"
	cmd3 := exec.Command(binary, "count", "urls")
	cmd3.Stdin = strings.NewReader("https://example.com\nhttps://example.org\n")
	out3, err := cmd3.Output()
	if err != nil {
		t.Fatalf("cmd3 failed: %v", err)
	}
	if strings.TrimSpace(string(out3)) != "2" {
		t.Errorf("expected 2, got %q", string(out3))
	}
}

// TestTargetFilesWithoutExtension tests passing file targets that lack file extensions.
func TestTargetFilesWithoutExtension(t *testing.T) {
	binary := testBinary

	tmpDir, err := os.MkdirTemp("", "xtr_noext_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	ipFile := filepath.Join(tmpDir, "targets")
	if err := os.WriteFile(ipFile, []byte("10.0.0.0/24\n10.0.1.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}

	emailFile := filepath.Join(tmpDir, "contacts")
	if err := os.WriteFile(emailFile, []byte("support at info@example.com for help\n"), 0644); err != nil {
		t.Fatal(err)
	}

	urlFile := filepath.Join(tmpDir, "urlslist")
	if err := os.WriteFile(urlFile, []byte("Check https://example.com/status\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. nlgrep ip count targets
	cmd1 := exec.Command(binary, "ip", "count", ipFile)
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("cmd1 failed: %v", err)
	}
	if strings.TrimSpace(string(out1)) != "512" {
		t.Errorf("expected 512, got %q", string(out1))
	}

	// 2. nlgrep merge ips targets
	cmd2 := exec.Command(binary, "merge", "ips", ipFile)
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("cmd2 failed: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "10.0.0.0/23" {
		t.Errorf("expected 10.0.0.0/23, got %q", string(out2))
	}

	// 3. nlgrep emails contacts
	cmd3 := exec.Command(binary, "emails", emailFile)
	out3, err := cmd3.Output()
	if err != nil {
		t.Fatalf("cmd3 failed: %v", err)
	}
	if strings.TrimSpace(string(out3)) != "info@example.com" {
		t.Errorf("expected info@example.com, got %q", string(out3))
	}

	// 4. nlgrep urls urlslist
	cmd4 := exec.Command(binary, "urls", urlFile)
	out4, err := cmd4.Output()
	if err != nil {
		t.Fatalf("cmd4 failed: %v", err)
	}
	if strings.TrimSpace(string(out4)) != "https://example.com/status" {
		t.Errorf("expected https://example.com/status, got %q", string(out4))
	}
}

// TestStdinDashInterchangeability verifies explicit stdin dash handling with arguments and merges.
func TestStdinDashInterchangeability(t *testing.T) {
	binary := testBinary

	// 1. echo "10.0.0.0/24" | nlgrep merge ips -
	cmd1 := exec.Command(binary, "merge", "ips", "-")
	cmd1.Stdin = strings.NewReader("10.0.0.0/24\n")
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("cmd1 failed: %v", err)
	}
	if strings.TrimSpace(string(out1)) != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %q", string(out1))
	}

	// 2. echo -e "10.0.0.0/24\n10.0.1.0/24" | nlgrep ip count -
	cmd2 := exec.Command(binary, "ip", "count", "-")
	cmd2.Stdin = strings.NewReader("10.0.0.0/24\n10.0.1.0/24\n")
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("cmd2 failed: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "512" {
		t.Errorf("expected 512, got %q", string(out2))
	}

	// 3. echo "10.0.0.1" | nlgrep ip count - 10.0.0.2
	cmd3 := exec.Command(binary, "ip", "count", "-", "10.0.0.2")
	cmd3.Stdin = strings.NewReader("10.0.0.1\n")
	out3, err := cmd3.Output()
	if err != nil {
		t.Fatalf("cmd3 failed: %v", err)
	}
	if strings.TrimSpace(string(out3)) != "2" {
		t.Errorf("expected 2, got %q", string(out3))
	}

	// 4. echo "10.0.0.1" | nlgrep ip count 10.0.0.2 -
	cmd4 := exec.Command(binary, "ip", "count", "10.0.0.2", "-")
	cmd4.Stdin = strings.NewReader("10.0.0.1\n")
	out4, err := cmd4.Output()
	if err != nil {
		t.Fatalf("cmd4 failed: %v", err)
	}
	if strings.TrimSpace(string(out4)) != "2" {
		t.Errorf("expected 2, got %q", string(out4))
	}
}

// TestStreamingMemoryOptimization verifies that IPCounter avoids detail allocation when disabled.
func TestStreamingMemoryOptimization(t *testing.T) {
	c := NewIPCounter()
	c.SetTrackDetails(false)

	for i := 0; i < 50000; i++ {
		b2 := byte(i >> 8)
		b3 := byte(i & 0xFF)
		cidr := fmt.Sprintf("10.%d.%d.0/24", b2, b3)
		if err := c.Add(cidr); err != nil {
			t.Fatalf("unexpected error adding cidr: %v", err)
		}
	}

	res := c.Calculate()
	if len(res.Details) != 0 {
		t.Errorf("expected 0 details when trackDetails=false, got %d", len(res.Details))
	}
	if res.TotalCombined.Int64() != 50000*256 {
		t.Errorf("expected %d addresses, got %s", 50000*256, res.TotalCombined.String())
	}
}

// TestRound3AdversarialEdgeCases tests edge cases, full boundaries, comments, and mixed address families.
func TestRound3AdversarialEdgeCases(t *testing.T) {
	binary := testBinary

	// 1. Multiple positional ranges
	cmd1 := exec.Command(binary, "ip", "count", "10.0.0.1-10.0.0.5", "10.0.0.10-10.0.0.15")
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("cmd1 failed: %v", err)
	}
	if strings.TrimSpace(string(out1)) != "11" {
		t.Errorf("expected 11, got %q", string(out1))
	}

	// 2. Full IPv4 boundary: 0.0.0.0-255.255.255.255
	cmd2Count := exec.Command(binary, "ip", "count", "0.0.0.0-255.255.255.255")
	out2Count, err := cmd2Count.Output()
	if err != nil {
		t.Fatalf("cmd2Count failed: %v", err)
	}
	if strings.TrimSpace(string(out2Count)) != "4294967296" {
		t.Errorf("expected 4294967296, got %q", string(out2Count))
	}
	cmd2Merge := exec.Command(binary, "merge", "ips", "0.0.0.0-255.255.255.255")
	out2Merge, err := cmd2Merge.Output()
	if err != nil {
		t.Fatalf("cmd2Merge failed: %v", err)
	}
	if strings.TrimSpace(string(out2Merge)) != "0.0.0.0/0" {
		t.Errorf("expected 0.0.0.0/0, got %q", string(out2Merge))
	}

	// 3. Full IPv6 boundary: ::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
	cmd3Count := exec.Command(binary, "ip", "count", "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	out3Count, err := cmd3Count.Output()
	if err != nil {
		t.Fatalf("cmd3Count failed: %v", err)
	}
	if strings.TrimSpace(string(out3Count)) != "340282366920938463463374607431768211456" {
		t.Errorf("expected 340282366920938463463374607431768211456, got %q", string(out3Count))
	}
	cmd3Merge := exec.Command(binary, "merge", "ips", "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	out3Merge, err := cmd3Merge.Output()
	if err != nil {
		t.Fatalf("cmd3Merge failed: %v", err)
	}
	if strings.TrimSpace(string(out3Merge)) != "::/0" {
		t.Errorf("expected ::/0, got %q", string(out3Merge))
	}

	// 4. Mixed IPv4 and IPv6 input
	cmd4Merge := exec.Command(binary, "merge", "ips", "10.0.0.0/24", "2001:db8::/64")
	out4Merge, err := cmd4Merge.Output()
	if err != nil {
		t.Fatalf("cmd4Merge failed: %v", err)
	}
	lines4 := strings.Split(strings.TrimSpace(string(out4Merge)), "\n")
	if len(lines4) != 2 || lines4[0] != "10.0.0.0/24" || lines4[1] != "2001:db8::/64" {
		t.Errorf("expected [10.0.0.0/24 2001:db8::/64], got %v", lines4)
	}

	// 5. Comments and blank lines in streamed input
	cmd5 := exec.Command(binary, "ip", "count")
	cmd5.Stdin = strings.NewReader("# Header comment\n\n10.0.0.0/24\n// Another comment\n10.0.1.0/24\n")
	out5, err := cmd5.Output()
	if err != nil {
		t.Fatalf("cmd5 failed: %v", err)
	}
	if strings.TrimSpace(string(out5)) != "512" {
		t.Errorf("expected 512, got %q", string(out5))
	}

	// 6. Subcommand with flag prefix: nlgrep -h count total ips 10.0.0.0/16
	cmd6 := exec.Command(binary, "-h", "count", "total", "ips", "10.0.0.0/16")
	out6, err := cmd6.Output()
	if err != nil {
		t.Fatalf("cmd6 failed: %v", err)
	}
	if strings.TrimSpace(string(out6)) != "65,536" {
		t.Errorf("expected 65,536, got %q", string(out6))
	}

	// 7. Multi-stage freeform extraction -> merge -> count
	cmd7Stage1 := exec.Command(binary, "get", "cidrs")
	cmd7Stage1.Stdin = strings.NewReader("Interface configured on 10.0.0.0/24 and 10.0.1.0/24\n")
	out7Stage1, err := cmd7Stage1.Output()
	if err != nil {
		t.Fatalf("cmd7Stage1 failed: %v", err)
	}

	cmd7Stage2 := exec.Command(binary, "merge", "ips")
	cmd7Stage2.Stdin = bytes.NewReader(out7Stage1)
	out7Stage2, err := cmd7Stage2.Output()
	if err != nil {
		t.Fatalf("cmd7Stage2 failed: %v", err)
	}

	cmd7Stage3 := exec.Command(binary, "ip", "count")
	cmd7Stage3.Stdin = bytes.NewReader(out7Stage2)
	out7Stage3, err := cmd7Stage3.Output()
	if err != nil {
		t.Fatalf("cmd7Stage3 failed: %v", err)
	}
	if strings.TrimSpace(string(out7Stage3)) != "512" {
		t.Errorf("expected 512, got %q", string(out7Stage3))
	}
}


