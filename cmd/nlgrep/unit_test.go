package main

import (
	"bytes"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
)

func TestIsLuhnValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"4532015112830366", true},  // valid Visa test number
		{"4532015112830367", false}, // bad check digit
		{"12345", false},            // too short
		{"12345678901234567890", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLuhnValid(c.in); got != c.want {
			t.Errorf("isLuhnValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsIBANValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"GB29NWBK60161331926819", true},
		{"GB29NWBK60161331926818", false}, // bad checksum
		{"TOO-SHORT", false},
		{"GB29NWBK6016133192681!", false}, // invalid char
	}
	for _, c := range cases {
		if got := isIBANValid(c.in); got != c.want {
			t.Errorf("isIBANValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsISBNValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0-306-40615-2", true},   // valid ISBN-10
		{"0-306-40615-3", false},  // bad check digit
		{"978-0-306-40615-7", true}, // valid ISBN-13
		{"978-0-306-40615-8", false},
		{"123", false}, // wrong length
	}
	for _, c := range cases {
		if got := isISBNValid(c.in); got != c.want {
			t.Errorf("isISBNValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsVINValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1HGCM82633A004352", true},
		{"1HGCM82633A004353", false}, // bad check digit
		{"1HGCM82633A00435", false},  // too short
		{"1HGCM8Q633A004352", false}, // contains forbidden Q
	}
	for _, c := range cases {
		if got := isVINValid(c.in); got != c.want {
			t.Errorf("isVINValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsSSNValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"123-45-6789", true},
		{"000-45-6789", false}, // area 0
		{"666-45-6789", false}, // area 666
		{"900-45-6789", false}, // area >= 900
		{"123-00-6789", false}, // group 0
		{"123-45-0000", false}, // serial 0
		{"not-a-ssn", false},
		{"123-45", false},
	}
	for _, c := range cases {
		if got := isSSNValid(c.in); got != c.want {
			t.Errorf("isSSNValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"kitten", "sitting", 3},
		{"emails", "emails", 0},
		{"emails", "emal", 2},
	}
	for _, c := range cases {
		if got := levenshtein(c.a, c.b); got != c.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPrintHelpNoPanic(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = old }()

	PrintHelp()

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stderr = old

	if !strings.Contains(buf.String(), "nlgrep") {
		t.Error("expected PrintHelp output to mention nlgrep")
	}
}

func TestHighlightMatch(t *testing.T) {
	line := "contact test@example.com now"
	matches := []MatchResult{{Value: "test@example.com", Start: 8, End: 25}}

	if got := highlightMatch(line, matches, false); got != line {
		t.Errorf("highlightMatch with useColor=false should return line unchanged, got %q", got)
	}

	got := highlightMatch(line, matches, true)
	if !strings.Contains(got, colorRed) || !strings.Contains(got, colorReset) {
		t.Errorf("highlightMatch with useColor=true should wrap match in color codes, got %q", got)
	}
	if !strings.Contains(got, "test@example.com") {
		t.Errorf("highlightMatch should preserve matched value, got %q", got)
	}

	if got := highlightMatch(line, nil, true); got != line {
		t.Errorf("highlightMatch with no matches should return line unchanged, got %q", got)
	}
}

func TestFormatMetric(t *testing.T) {
	if got := formatMetric(nil, false); got != "0" {
		t.Errorf("formatMetric(nil, false) = %q, want %q", got, "0")
	}
	v := big.NewInt(1234567)
	if got := formatMetric(v, false); got != "1234567" {
		t.Errorf("formatMetric(v, false) = %q, want %q", got, "1234567")
	}
	if got := formatMetric(v, true); got != "1,234,567" {
		t.Errorf("formatMetric(v, true) = %q, want %q", got, "1,234,567")
	}
}

func TestScanNetblockStream(t *testing.T) {
	input := "10.0.0.0/24\n# comment line\n\n// another comment\n10.0.1.0/24 10.0.2.0/24\n"
	var tokens []string
	err := scanNetblockStream(strings.NewReader(input), false, func(tok string) {
		tokens = append(tokens, tok)
	})
	if err != nil {
		t.Fatalf("scanNetblockStream returned error: %v", err)
	}
	want := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}
	if len(tokens) != len(want) {
		t.Fatalf("got %d tokens %v, want %d tokens %v", len(tokens), tokens, len(want), want)
	}
	for i, w := range want {
		if tokens[i] != w {
			t.Errorf("token[%d] = %q, want %q", i, tokens[i], w)
		}
	}
}

func TestScanNetblockStreamExtractMode(t *testing.T) {
	input := "some prefix 10.0.0.0/24 embedded in text and 10.0.0.0/255.255.255.0 too\n"
	var tokens []string
	err := scanNetblockStream(strings.NewReader(input), true, func(tok string) {
		tokens = append(tokens, tok)
	})
	if err != nil {
		t.Fatalf("scanNetblockStream returned error: %v", err)
	}
	if len(tokens) == 0 {
		t.Fatal("expected at least one extracted token")
	}
	found := false
	for _, tok := range tokens {
		if tok == "10.0.0.0/24" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find 10.0.0.0/24 among tokens, got %v", tokens)
	}
}

func TestParseCommandLine(t *testing.T) {
	p, err := parseCommandLine([]string{"-n", "-u", "-c", "emails", "file.txt"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if !p.ShowLineNum || !p.UniqueOnly || !p.CountOnly {
		t.Errorf("expected -n -u -c flags to be set, got %+v", p)
	}
	if len(p.PositionalArgs) != 2 || p.PositionalArgs[0] != "emails" || p.PositionalArgs[1] != "file.txt" {
		t.Errorf("unexpected positional args: %v", p.PositionalArgs)
	}
}

func TestParseCommandLineNetblockFlags(t *testing.T) {
	p, err := parseCommandLine([]string{"-h", "--json", "--details", "--merge", "-x", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if !p.HumanFormat || !p.JSONOutput || !p.ShowDetails || !p.MergeMode || !p.ExtractMode {
		t.Errorf("expected all netblock flags set, got %+v", p)
	}
}

func TestParseCommandLineDash(t *testing.T) {
	p, err := parseCommandLine([]string{"-"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if len(p.PositionalArgs) != 1 || p.PositionalArgs[0] != "-" {
		t.Errorf("expected dash to be treated as positional arg, got %v", p.PositionalArgs)
	}
}

func TestParseCommandLineColorAndHelp(t *testing.T) {
	p, err := parseCommandLine([]string{"--color=always"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if p.ColorFlag != "always" {
		t.Errorf("expected ColorFlag=always, got %q", p.ColorFlag)
	}

	p2, err := parseCommandLine([]string{"--help"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if !p2.HelpRequested {
		t.Error("expected --help to set HelpRequested")
	}
}

func TestParseCommandLineContextFlags(t *testing.T) {
	p, err := parseCommandLine([]string{"-A", "3", "-B=2", "emails"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if p.AfterCount != 3 || p.BeforeCount != 2 {
		t.Errorf("expected AfterCount=3 BeforeCount=2, got %+v", p)
	}
}

func TestParseCommandLineCombinedShortFlags(t *testing.T) {
	p, err := parseCommandLine([]string{"-nuc", "emails"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if !p.ShowLineNum || !p.UniqueOnly || !p.CountOnly {
		t.Errorf("expected combined -nuc to set all three flags, got %+v", p)
	}
}

func TestParseCommandLineFileFlag(t *testing.T) {
	p, err := parseCommandLine([]string{"-f", "subnets.txt"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if p.FilePath != "subnets.txt" {
		t.Errorf("expected FilePath=subnets.txt, got %q", p.FilePath)
	}

	p2, err := parseCommandLine([]string{"-f=other.txt"})
	if err != nil {
		t.Fatalf("parseCommandLine returned error: %v", err)
	}
	if p2.FilePath != "other.txt" {
		t.Errorf("expected FilePath=other.txt, got %q", p2.FilePath)
	}
}

func TestParseCommandLineErrors(t *testing.T) {
	cases := [][]string{
		{"-A"},              // missing value
		{"-A", "notanum"},   // bad value
		{"-A=notanum"},      // bad value with =
		{"-B"},              // missing value
		{"-B", "notanum"},   // bad value
		{"--color"},         // missing value
		{"-f"},              // missing value
		{"-z"},              // unknown flag
	}
	for _, args := range cases {
		if _, err := parseCommandLine(args); err == nil {
			t.Errorf("parseCommandLine(%v) expected error, got nil", args)
		}
	}
}

func TestIsLikelyTarget(t *testing.T) {
	if !isLikelyTarget("-") {
		t.Error(`isLikelyTarget("-") should be true`)
	}
	if !isLikelyTarget("192.168.0.1") {
		t.Error("isLikelyTarget should recognize an IP address")
	}
	if !isLikelyTarget("10.0.0.0/24") {
		t.Error("isLikelyTarget should recognize a CIDR")
	}
	if isLikelyTarget("emails") {
		t.Error(`isLikelyTarget("emails") should be false`)
	}

	tmp, err := os.CreateTemp("", "isLikelyTarget_*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()
	if !isLikelyTarget(tmp.Name()) {
		t.Errorf("isLikelyTarget should recognize existing file %q", tmp.Name())
	}
}

func TestProcessStreamBasic(t *testing.T) {
	ext := ResolveIntentExact("emails")
	if ext == nil {
		t.Fatal("expected emails extractor to be found")
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	in := inputSource{name: "test", reader: strings.NewReader("a@b.com\nno match here\nc@d.com\n")}
	cfg := Config{}
	seen := make(map[string]bool)
	count := processStream(in, ext, cfg, seen)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	if count != 2 {
		t.Errorf("expected 2 matches, got %d", count)
	}
	out := buf.String()
	if !strings.Contains(out, "a@b.com") || !strings.Contains(out, "c@d.com") {
		t.Errorf("expected output to contain both emails, got %q", out)
	}
}

func TestProcessStreamContextLines(t *testing.T) {
	ext := ResolveIntentExact("emails")
	if ext == nil {
		t.Fatal("expected emails extractor to be found")
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	in := inputSource{name: "test", reader: strings.NewReader("line1\na@b.com\nline3\nline4\n")}
	cfg := Config{AfterCount: 2, BeforeCount: 1, ShowLineNum: true}
	seen := make(map[string]bool)
	count := processStream(in, ext, cfg, seen)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	if count != 1 {
		t.Errorf("expected 1 match, got %d", count)
	}
	out := buf.String()
	if !strings.Contains(out, "a@b.com") {
		t.Errorf("expected context output to contain the match, got %q", out)
	}
}

func TestRunNetblockCount(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	p := ParsedCLI{PositionalArgs: []string{"10.0.0.0/24", "10.0.1.0/24"}}
	runNetblock(false, p)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	out := strings.TrimSpace(buf.String())
	if out != "512" {
		t.Errorf("runNetblock count = %q, want %q", out, "512")
	}
}

func TestRunNetblockMerge(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	p := ParsedCLI{PositionalArgs: []string{"10.0.0.0/24", "10.0.1.0/24"}}
	runNetblock(true, p)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	out := strings.TrimSpace(buf.String())
	if out != "10.0.0.0/23" {
		t.Errorf("runNetblock merge = %q, want %q", out, "10.0.0.0/23")
	}
}

func TestRunNetblockJSON(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	p := ParsedCLI{PositionalArgs: []string{"10.0.0.0/24"}, JSONOutput: true}
	runNetblock(false, p)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	if !strings.Contains(buf.String(), "total_unique_ips") {
		t.Errorf("expected JSON output to contain total_unique_ips field, got %q", buf.String())
	}
}

func TestIPCounterAddIPv6Details(t *testing.T) {
	c := NewIPCounter()
	c.SetTrackDetails(true)
	if err := c.Add("2001:db8::/126"); err != nil {
		t.Fatalf("Add(ipv6) returned error: %v", err)
	}
	res := c.Calculate()
	if len(res.Details) != 1 || res.Details[0].Version != 6 {
		t.Errorf("expected one ipv6 detail entry, got %+v", res.Details)
	}
}

func TestIPCounterAddInvalid(t *testing.T) {
	c := NewIPCounter()
	if err := c.Add("not-an-ip-or-cidr!!"); err == nil {
		t.Error("expected Add to return error for invalid token")
	}
}

func TestResolveIntentFuzzyAndSubstring(t *testing.T) {
	// Tier 2: substring/token-overlap match against aliases.
	if ext := ResolveIntent("show me all email addresses"); ext == nil || ext.ID != "emails" {
		t.Errorf("expected fuzzy match to resolve to emails extractor, got %+v", ext)
	}
	// Tier 3: Levenshtein typo tolerance.
	if ext := ResolveIntent("emails"); ext == nil || ext.ID != "emails" {
		t.Errorf("expected exact-ish match for emails, got %+v", ext)
	}
	if ext := ResolveIntent("emals"); ext == nil {
		t.Error("expected typo 'emals' to fuzzy-resolve to an extractor")
	}
	if ext := ResolveIntent("zzqxw plonkfrobnicate"); ext != nil {
		t.Errorf("expected no match for gibberish query, got %+v", ext)
	}
	if ext := ResolveIntent(""); ext != nil {
		t.Errorf("expected no match for empty query, got %+v", ext)
	}
}

func TestRunNetblockFileInput(t *testing.T) {
	tmp, err := os.CreateTemp("", "netblock_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString("10.0.0.0/24\n10.0.1.0/24\n")
	tmp.Close()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	p := ParsedCLI{FilePath: tmp.Name()}
	runNetblock(false, p)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	out := strings.TrimSpace(buf.String())
	if out != "512" {
		t.Errorf("runNetblock with file input = %q, want %q", out, "512")
	}
}

func TestRunNetblockDashRange(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	p := ParsedCLI{PositionalArgs: []string{"10.0.0.1", "-", "10.0.0.10"}}
	runNetblock(false, p)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	out := strings.TrimSpace(buf.String())
	if out != "10" {
		t.Errorf("runNetblock dash-range count = %q, want %q", out, "10")
	}
}

func captureRun(t *testing.T, args []string, stdin string) (stdout, stderr string, code int) {
	t.Helper()

	oldStdout, oldStderr, oldStdin := os.Stdout, os.Stderr, os.Stdin
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout, os.Stderr = outW, errW

	if stdin != "" {
		inR, inW, _ := os.Pipe()
		os.Stdin = inR
		go func() {
			inW.WriteString(stdin)
			inW.Close()
		}()
	}

	code = run(args)

	outW.Close()
	errW.Close()
	var outBuf, errBuf bytes.Buffer
	io.Copy(&outBuf, outR)
	io.Copy(&errBuf, errR)
	os.Stdout, os.Stderr, os.Stdin = oldStdout, oldStderr, oldStdin

	return outBuf.String(), errBuf.String(), code
}

func TestRunNoArgs(t *testing.T) {
	_, stderr, code := captureRun(t, []string{}, "")
	if code != 1 {
		t.Errorf("expected exit code 1 for no args, got %d", code)
	}
	if !strings.Contains(stderr, "nlgrep") {
		t.Errorf("expected help output on stderr, got %q", stderr)
	}
}

func TestRunHelpFlag(t *testing.T) {
	_, stderr, code := captureRun(t, []string{"--help"}, "")
	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	if !strings.Contains(stderr, "Usage") {
		t.Errorf("expected usage text, got %q", stderr)
	}
}

func TestRunListSubcommand(t *testing.T) {
	_, stderr, code := captureRun(t, []string{"list"}, "")
	if code != 0 {
		t.Errorf("expected exit code 0 for list, got %d", code)
	}
	if !strings.Contains(stderr, "Available Data Types") {
		t.Errorf("expected category listing, got %q", stderr)
	}
}

func TestRunParseError(t *testing.T) {
	_, stderr, code := captureRun(t, []string{"-z"}, "")
	if code != 1 {
		t.Errorf("expected exit code 1 for bad flag, got %d", code)
	}
	if !strings.Contains(stderr, "Error") {
		t.Errorf("expected error message, got %q", stderr)
	}
}

func TestRunExtractFromStdin(t *testing.T) {
	stdout, _, code := captureRun(t, []string{"emails"}, "a@b.com\nno match\n")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout, "a@b.com") {
		t.Errorf("expected extracted email in stdout, got %q", stdout)
	}
}

func TestRunExtractCountOnly(t *testing.T) {
	stdout, _, code := captureRun(t, []string{"count", "emails"}, "a@b.com\nb@c.com\n")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if strings.TrimSpace(stdout) != "2" {
		t.Errorf("expected count output '2', got %q", stdout)
	}
}

func TestRunUnrecognizedQuery(t *testing.T) {
	_, stderr, code := captureRun(t, []string{"zzqxw plonkfrobnicate"}, "x\n")
	if code != 2 {
		t.Errorf("expected exit code 2 for unrecognized query, got %d", code)
	}
	if !strings.Contains(stderr, "unrecognized") {
		t.Errorf("expected unrecognized-query error, got %q", stderr)
	}
}

func TestRunNetblockMergeSubcommand(t *testing.T) {
	stdout, _, code := captureRun(t, []string{"merge", "ips"}, "10.0.0.0/24\n10.0.1.0/24\n")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if strings.TrimSpace(stdout) != "10.0.0.0/23" {
		t.Errorf("expected merged CIDR, got %q", stdout)
	}
}

func TestRunNetblockCountPositional(t *testing.T) {
	stdout, _, code := captureRun(t, []string{"10.0.0.0/24"}, "")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if strings.TrimSpace(stdout) != "256" {
		t.Errorf("expected count 256, got %q", stdout)
	}
}

func TestRunExtractFileNotFound(t *testing.T) {
	_, stderr, code := captureRun(t, []string{"emails", "/no/such/file/exists.txt"}, "")
	if code != 3 {
		t.Errorf("expected exit code 3 for missing file, got %d", code)
	}
	if !strings.Contains(stderr, "Error opening") {
		t.Errorf("expected file-open error, got %q", stderr)
	}
}

func TestRunHumanFlagNoArgsShowsHelp(t *testing.T) {
	_, stderr, code := captureRun(t, []string{"-h"}, "")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stderr, "Usage") {
		t.Errorf("expected help output, got %q", stderr)
	}
}

func TestRunNetblockDetails(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	p := ParsedCLI{PositionalArgs: []string{"10.0.0.0/24"}, ShowDetails: true, HumanFormat: true}
	runNetblock(false, p)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	out := buf.String()
	if !strings.Contains(out, "Total Unique Addresses") {
		t.Errorf("expected details output, got %q", out)
	}
}
