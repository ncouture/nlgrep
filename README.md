`nlgrep` is a standalone, high-performance command-line utility built in Go that functions like `grep`, but is specialized for **structured data types and entity extraction**. It combines regular expressions, algorithmic checksum validators (Luhn, Mod-97, Mod-11), and a natural language query router.

Unlike standard `grep`, which prints entire lines by default and requires arcane regular expressions, `nlgrep` defaults to extracting **only the matched pattern** (like `grep -o`), supports natural language subcommands (`nlgrep "find all emails"`), and applies mathematical validation to the types that carry check digits.

---


# Table of Contents

1.  [Key Features](#org64733e9)
2.  [Building & Installation](#org824928a)
3.  [Command-Line Reference](#org717985e)
4.  [Exit Codes](#org7dd8fa8)
5.  [Context Windows (-A and -B)](#orgd5a6eee)
6.  [Natural Language Query Router](#orgeb259e9)
7.  [Supported Data Types & Categories](#org08cb76a)
8.  [Algorithmic Verification & Checksums](#orgd615705)
9.  [Practical Usage Examples](#orge8d1816)
10. [Known Limitations & Behavioral Notes](#org3b6e371)
11. [Architecture & Performance](#orgb30b26f)

---


# Key Features

-   **Natural Language Intent Recognition**: Run `./nlgrep urls`, `./nlgrep "find emails"`, or `./nlgrep "show me credit cards"` without remembering strict syntax.
-   **Algorithmic Checksum Verification**: Mathematically verifies Credit Cards (Luhn), Bank Accounts (IBAN Mod-97), Book IDs (ISBN-10/13), Vehicle Identifiers (VIN Mod-11), and US SSNs. IP addresses are additionally parsed with `net.ParseIP` rather than matched by shape alone.
-   **Grep-Compatible Context Controls**:
    -   Default: Extracts **only the pattern** (e.g. `user@example.com`).
    -   `--line`, `-L`, `-whole-line`: Prints the **entire line** containing the pattern.
    -   `-A <N>`: Prints `<N>` lines **after and including** the matching line.
    -   `-B <M>`: Prints `<M>` lines **before and including** the matching line.
-   **UNIX Pipeline Streaming**: Reads from files or standard input (`cat log | nlgrep -u ips`) with bounded memory usage using a sliding-window ring buffer.
-   **ReDoS Immune**: Implemented with Go's RE2 engine, guaranteeing $O(n)$ worst-case execution time on untrusted data.
-   **100% Statically Linked**: Compiles into a single binary with zero external package dependencies (`not a dynamic executable`).

---


# Building & Installation

`nlgrep` is written in standard Go with zero third-party dependencies. There is no `go.mod` — the single source file is compiled directly.


## Build as a Static ELF Binary

    # Build standalone binary stripped of debug symbols
    CGO_ENABLED=0 go build -ldflags="-s -w" -o nlgrep nlgrep.go
    
    # Verify it has zero dynamic dependencies
    file nlgrep
    # Output: nlgrep: ELF 64-bit LSB executable, ..., statically linked, stripped
    
    # Move to a system or user PATH directory
    chmod +x nlgrep
    mv nlgrep /usr/local/bin/   # or ~/bin/


## Run Directly Without Compiling

    go run nlgrep.go urls access.log

Note that `go run` does **not** propagate the program's exit status — it reports `1` for any nonzero exit. Build the binary if you need to test the exit codes below.


## Static Analysis

There is no test suite. The available checks are:

    go vet nlgrep.go
    gofmt -l nlgrep.go

---


# Command-Line Reference

    Usage:
      nlgrep [options] <data-type | "natural language query"> [file ...]
      cat input.txt | nlgrep [options] <data-type | "query">


## Flags and Options

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Flag</th>
<th scope="col" class="org-left">Type</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left"><code>--line</code>, <code>-L</code>, <code>-whole-line</code></td>
<td class="org-left">bool</td>
<td class="org-left">Print the <b>entire line</b> containing the match (default prints only the pattern).</td>
</tr>


<tr>
<td class="org-left"><code>-A &lt;N&gt;</code></td>
<td class="org-left">int</td>
<td class="org-left">Print <code>&lt;N&gt;</code> lines <b>after and including</b> the line containing the pattern.</td>
</tr>


<tr>
<td class="org-left"><code>-B &lt;M&gt;</code></td>
<td class="org-left">int</td>
<td class="org-left">Print <code>&lt;M&gt;</code> lines <b>before and including</b> the line containing the pattern.</td>
</tr>


<tr>
<td class="org-left"><code>-n</code></td>
<td class="org-left">bool</td>
<td class="org-left">Prefix each output line with its 1-based line number (<code>line:match</code> or <code>line-context</code>).</td>
</tr>


<tr>
<td class="org-left"><code>-u</code></td>
<td class="org-left">bool</td>
<td class="org-left">Deduplicate matching values so each distinct item is printed only once.</td>
</tr>


<tr>
<td class="org-left"><code>-c</code></td>
<td class="org-left">bool</td>
<td class="org-left">Suppress normal output and print only the total count of matched items.</td>
</tr>


<tr>
<td class="org-left"><code>--color &lt;when&gt;</code></td>
<td class="org-left">string</td>
<td class="org-left">Colorize matches: <code>auto</code> (default for TTY), <code>always</code>, or <code>never</code>.</td>
</tr>


<tr>
<td class="org-left"><code>list</code>, <code>help</code>, <code>--help</code>, <code>-h</code></td>
<td class="org-left">command</td>
<td class="org-left">Display available data types, aliases, and examples.</td>
</tr>
</tbody>
</table>

Notes on flag behavior:

-   Passing `-A` or `-B` greater than zero **implies** `--line`; context output is always whole lines.
-   `--color` only affects whole-line and context output. In the default pattern-only mode the match **is** the whole output, so no highlight is applied.
-   `-u` dedupes across **all** input files, not per file.
-   `-c` reports the total number of matches, and is **not** reduced by `-u`. `nlgrep -c -u emails f` prints the raw match count, not the number of distinct addresses. To count distinct values, use `nlgrep -u emails f | wc -l`.
-   Multiple files produce no filename prefixes, and `-n` line numbers restart at 1 for each file.
-   `list` / `help` / `--help` / `-h` write **everything to STDERR**. Redirect when piping or grepping the type registry:

    nlgrep list 2>&1 | grep coordinates

---


# Exit Codes

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-right" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-right">Code</th>
<th scope="col" class="org-left">Meaning</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-right">0</td>
<td class="org-left">Success — including the case where <b>no matches</b> were found</td>
</tr>


<tr>
<td class="org-right">1</td>
<td class="org-left">No arguments supplied (usage printed to STDERR)</td>
</tr>


<tr>
<td class="org-right">2</td>
<td class="org-left">Unrecognized data type or query</td>
</tr>


<tr>
<td class="org-right">3</td>
<td class="org-left">Failed to open an input file</td>
</tr>
</tbody>
</table>

**This differs from `grep`**, which exits `1` when nothing matches. A shell test like `nlgrep ssns data.csv && alert` will fire unconditionally. Test for output instead:

    [ -n "$(nlgrep ssns data.csv)" ] && alert

---


# Context Windows (-A and -B)

`nlgrep` implements precise context controls where the count **includes** the matching line:

-   **`-A <N>` (Lines After and Including Match)**:
    -   `-A 1`: Prints the matching line itself.
    -   `-A 2`: Prints the matching line plus **1 line after** (2 lines total).
    -   `-A 5`: Prints the matching line plus **4 lines after** (5 lines total).
-   **`-B <M>` (Lines Before and Including Match)**:
    -   `-B 1`: Prints the matching line itself.
    -   `-B 2`: Prints **1 line before** plus the matching line (2 lines total).
    -   `-B 3`: Prints **2 lines before** plus the matching line (3 lines total).
-   **Combined `-B <M> -A <N>`**:
    -   Merges leading and trailing context. `-B 2 -A 3` prints 1 line before, the matching line, and 2 lines after (4 lines total).
    -   Overlapping match blocks are merged without repeating lines; a `--` separator is emitted only where a gap occurs.

With `-n`, the matching line is marked with `:` and context lines with `-`, mirroring `grep`:

    $ nlgrep -n -B 2 -A 3 emails ctx.txt
    3-line 3
    4:line 4 hit@a.com
    5-line 5
    6-line 6
    --
    8-line 8
    9:line 9 hit@b.com
    10-line 10
    11-line 11

---


# Natural Language Query Router

You don't need to memorize exact command strings. The built-in router resolves a query in three escalating passes:

1.  **Filler stripping**: leading conversational prefixes (`find`, `extract`, `show me all`, `get`, `list all`, `where are the`, &#x2026;) and trailing `please` / `?` / `!` are removed.
2.  **Exact match** against extractor IDs and their alias lists.
3.  **Token-overlap scoring** across aliases: `+3` per exactly equal token, `+1` per substring overlap, `+4` when the query contains an alias or vice versa. A winner is returned only at a score of `3` or higher, so a single weak substring hit deliberately falls through.
4.  **Levenshtein fuzzy match** (edit distance ≤ 2) for typo tolerance.


## Query Examples

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">User Query</th>
<th scope="col" class="org-left">Resolved Extractor</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left"><code>nlgrep urls</code></td>
<td class="org-left"><code>urls</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "extract all web links"</code></td>
<td class="org-left"><code>urls</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "find email addresses"</code></td>
<td class="org-left"><code>emails</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "show me credit cards"</code></td>
<td class="org-left"><code>credit_cards</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "get ip addresses"</code></td>
<td class="org-left"><code>ips</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "look for phone numbers"</code></td>
<td class="org-left"><code>phone_numbers</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "where are the mac addresses"</code></td>
<td class="org-left"><code>mac_addresses</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "list all bank accounts"</code></td>
<td class="org-left"><code>ibans</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "cve security bugs"</code></td>
<td class="org-left"><code>cves</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep "find bitcoin or ethereum wallets"</code></td>
<td class="org-left"><code>crypto</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep emaisl</code> (typo)</td>
<td class="org-left"><code>emails</code></td>
</tr>


<tr>
<td class="org-left"><code>nlgrep phne</code> (typo)</td>
<td class="org-left"><code>phone_numbers</code></td>
</tr>
</tbody>
</table>

---


# Supported Data Types & Categories

29 extractors across 16 categories. Run `nlgrep list 2>&1` to view them from the binary itself — the `Registry` in `nlgrep.go` is the authoritative source.

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Category</th>
<th scope="col" class="org-left">Extractor ID</th>
<th scope="col" class="org-left">Standard / Grammar</th>
<th scope="col" class="org-left">Verification Method</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left"><b>Automotive</b></td>
<td class="org-left"><code>vins</code></td>
<td class="org-left">ISO 3779 Vehicle Identification</td>
<td class="org-left"><b>Weighted Modulo-11 Check Digit Algorithm</b></td>
</tr>


<tr>
<td class="org-left"><b>Aviation &amp; Weather</b></td>
<td class="org-left"><code>metar</code></td>
<td class="org-left">ICAO METAR aerodrome reports</td>
<td class="org-left">Station + DDHHMMZ + wind + visibility sequence</td>
</tr>


<tr>
<td class="org-left"><b>Blockchain</b></td>
<td class="org-left"><code>crypto</code></td>
<td class="org-left">Bitcoin, Ethereum</td>
<td class="org-left">Legacy/Bech32 BTC shape, <code>0x</code> + 40 hex ETH</td>
</tr>


<tr>
<td class="org-left"><b>Communications</b></td>
<td class="org-left"><code>emails</code></td>
<td class="org-left">RFC 5322 Standard Email</td>
<td class="org-left">Structure + domain/TLD syntax</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>phone_numbers</code></td>
<td class="org-left">E.164 &amp; regionally formatted numbers</td>
<td class="org-left">Digit-group shape and delimiter check</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>subjects</code></td>
<td class="org-left">RFC 822 Email / Ticket Headers</td>
<td class="org-left">Line-anchored <code>Subject:~/~Re:~/~Fwd:~/~Fw:</code> capture</td>
</tr>


<tr>
<td class="org-left"><b>Cybersecurity</b></td>
<td class="org-left"><code>cves</code></td>
<td class="org-left">MITRE CVE Vulnerability IDs</td>
<td class="org-left"><code>CVE-\d{4}-\d{4,7}</code> format rules</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>hashes</code></td>
<td class="org-left">MD5 (32-hex), SHA-1 (40), SHA-256 (64)</td>
<td class="org-left">Fixed-width hexadecimal digest bounds</td>
</tr>


<tr>
<td class="org-left"><b>Data Formats</b></td>
<td class="org-left"><code>jsonpath</code></td>
<td class="org-left">RFC 9535 JSONPath Expressions</td>
<td class="org-left">Root <code>$</code> anchor with dot/bracket selectors</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>xpath</code></td>
<td class="org-left">W3C XPath Navigation Expressions</td>
<td class="org-left"><code>/</code>, <code>//</code>, <code>@attribute</code>, and predicate syntax</td>
</tr>


<tr>
<td class="org-left"><b>Financial</b></td>
<td class="org-left"><code>credit_cards</code></td>
<td class="org-left">Visa, MC, Amex, Discover PAN</td>
<td class="org-left"><b>Luhn Modulo-10 Checksum Algorithm</b></td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>ibans</code></td>
<td class="org-left">ISO 13616 International Bank Accounts</td>
<td class="org-left"><b>Modulo-97-10 Checksum Algorithm</b> (<code>big.Int</code>)</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>currencies</code></td>
<td class="org-left">ISO 4217 Currency Codes</td>
<td class="org-left">Fixed list of 20 major codes (see note below)</td>
</tr>


<tr>
<td class="org-left"><b>Gaming &amp; Notation</b></td>
<td class="org-left"><code>chess_fen</code></td>
<td class="org-left">Forsyth–Edwards Notation (FEN)</td>
<td class="org-left">8-rank structure + full field sequence</td>
</tr>


<tr>
<td class="org-left"><b>Geospatial</b></td>
<td class="org-left"><code>coordinates</code></td>
<td class="org-left">Decimal Degree coordinate pairs</td>
<td class="org-left">Lat \([-90, +90]\) / Lon \([-180, +180]\) bounds in regex</td>
</tr>


<tr>
<td class="org-left"><b>Government &amp; Identity</b></td>
<td class="org-left"><code>ssns</code></td>
<td class="org-left">US Social Security Numbers</td>
<td class="org-left">Area (<code>!= 000, 666, &gt;=900</code>) &amp; group rules</td>
</tr>


<tr>
<td class="org-left"><b>Identity</b></td>
<td class="org-left"><code>names</code></td>
<td class="org-left">Personal Names (Honorific Anchored)</td>
<td class="org-left">Anchored on <code>Mr.</code>, <code>Mrs.</code>, <code>Dr.</code>, <code>Prof.</code>, etc.</td>
</tr>


<tr>
<td class="org-left"><b>Networking</b></td>
<td class="org-left"><code>ips</code></td>
<td class="org-left">IPv4 and IPv6</td>
<td class="org-left">Parsed with Go's <code>net.ParseIP</code></td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>mac_addresses</code></td>
<td class="org-left">EUI-48 Hexadecimal</td>
<td class="org-left">Colon or hyphen delimited 6-octet form</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>asns</code></td>
<td class="org-left">Autonomous System Numbers</td>
<td class="org-left">BGP <code>AS&lt;number&gt;</code> format bounds</td>
</tr>


<tr>
<td class="org-left"><b>Publishing &amp; Academic</b></td>
<td class="org-left"><code>dois</code></td>
<td class="org-left">ISO 26324 Digital Object Identifiers</td>
<td class="org-left">Standard <code>10.\d{4,9}/...</code> registry syntax</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>isbns</code></td>
<td class="org-left">ISBN-10 &amp; ISBN-13 Books</td>
<td class="org-left"><b>Modulo-11 &amp; Modulo-10 Check Digit Math</b></td>
</tr>


<tr>
<td class="org-left"><b>Software &amp; Systems</b></td>
<td class="org-left"><code>uuids</code></td>
<td class="org-left">RFC 4122 128-bit UUID/GUID</td>
<td class="org-left">8-4-4-4-12 layout with version and variant bits</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>semver</code></td>
<td class="org-left">SemVer 2.0.0 Version Strings</td>
<td class="org-left"><code>MAJOR.MINOR.PATCH</code> with prerelease/build tags</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>cron</code></td>
<td class="org-left">UNIX 5-field Cron Syntax</td>
<td class="org-left">Minute, hour, DOM, month, DOW range parser</td>
</tr>


<tr>
<td class="org-left"><b>Temporal</b></td>
<td class="org-left"><code>dates</code></td>
<td class="org-left">ISO 8601 <code>YYYY-MM-DD</code> and <code>MM/DD/YYYY</code></td>
<td class="org-left">Month \([01,12]\) and day \([01,31]\) range bounds</td>
</tr>


<tr>
<td class="org-left"><b>Web &amp; Internet</b></td>
<td class="org-left"><code>urls</code></td>
<td class="org-left">RFC 3986 URI Specification</td>
<td class="org-left">Scheme anchor (<code>http</code>, <code>https</code>, <code>ftp</code>, <code>www.</code>)</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>domains</code></td>
<td class="org-left">FQDN (Fully Qualified Domain Names)</td>
<td class="org-left">Fixed list of ~24 common TLDs (see note below)</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left"><code>user_agents</code></td>
<td class="org-left">HTTP User-Agent tokens</td>
<td class="org-left"><code>Mozilla/5.0</code> prefixed signatures only</td>
</tr>
</tbody>
</table>

Two entries carry aliases broader than their implementation:

-   `currencies` matches a hard-coded set of 20 codes (USD, EUR, GBP, JPY, AUD, CAD, CHF, CNY, INR, BRL, RUB, KRW, SEK, NOK, MXN, NZD, SGD, HKD, ZAR, TRY). It is not a full ISO 4217 table — `PLN` and `THB` are not matched.
-   `domains` matches a hard-coded TLD list (`com org net edu gov mil io ai dev app co uk de fr jp cn nl eu info biz me tv`). `example.xyz` and `test.museum` are not matched.

---


# Algorithmic Verification & Checksums

For the types that carry a check digit, `nlgrep` does not simply match digit lengths — it verifies the arithmetic. This is the "broad regex, then validate" pattern, and it is what keeps false positives low on the financial and identity types.


## 1. Luhn Modulo-10 Algorithm (`credit_cards`)

Validates payment card numbers by doubling every second digit from the right, summing the digits, and verifying that the total is divisible by 10. Filters out random 16-digit sequences and database primary keys.


## 2. ISO 13616 Modulo-97 Algorithm (`ibans`)

Converts the IBAN country code and characters to numbers, moves the first 4 characters to the end, and calculates modulo 97 on the resulting integer using arbitrary-precision arithmetic (`big.Int`). Returns valid only if `integer mod 97 == 1`.


## 3. ISO 3779 Modulo-11 Algorithm (`vins`)

Applies official letter-to-number transliteration and position-specific weights to all 17 characters, computing a modulo 11 check digit that must exactly match position 9 of the VIN.


## 4. ISBN Check Digits (`isbns`)

-   **ISBN-10**: Weighted modulo 11 check digit where $\sum_{i=1}^{10} (11 - i) \cdot d_i \equiv 0 \pmod{11}$.
-   **ISBN-13**: Alternating weights of 1 and 3 where $(10 - (\sum \text{weighted} \pmod{10})) \pmod{10} = d_{13}$.


## 5. Structural Validation (`ips`, `ssns`)

-   `ips` passes every regex candidate through Go's `net.ParseIP`, so `999.1.1.1` is rejected.
-   `ssns` applies the SSA allocation rules: area is not `000`, `666`, or `>= 900`, and the group and serial segments are nonzero.

Every other extractor is regex-shape only. Where bounds matter, they are encoded directly in the pattern (`coordinates`, `dates`) rather than in a separate validator.

---


# Practical Usage Examples


## 1. Extracting Only Patterns (Default Mode)

    # Extract all clean URLs from an Nginx access log:
    nlgrep urls /var/log/nginx/access.log
    
    # Extract all unique email addresses from a mail dump:
    nlgrep -u emails /var/spool/mail/dump.txt
    
    # Extract all IPv4 and IPv6 addresses with line numbers:
    nlgrep -n ips /var/log/syslog


## 2. Printing Full Matching Lines (`--line`)

    # Print every line in an SQL dump that contains a Luhn-valid credit card:
    nlgrep --line "find credit cards" backup.sql
    
    # Print lines mentioning CVE vulnerabilities:
    nlgrep --line cves security_report.txt


## 3. Extracting Context Around Matches (`-A` and `-B`)

    # Print 1 line before and 2 lines after any line containing a URL:
    nlgrep -B 2 -A 3 urls /var/log/app.log
    
    # Inspect the 2 lines preceding an alert containing an IP address:
    nlgrep -B 3 ips alert.log


## 4. Pipeline Streaming and Filtering

    # Stream journalctl directly through nlgrep:
    journalctl -u my-service -f | nlgrep "find urls"
    
    # Count *distinct* cryptocurrency addresses in a transaction dump
    # (use -u | wc -l, not -c -u, which counts every match):
    cat mempool.json | nlgrep -u crypto | wc -l
    
    # Count every SSN occurrence in a file:
    nlgrep -c ssns sensitive_data.csv

---


# Known Limitations & Behavioral Notes

Checksum-backed types are precise. The regex-only types are deliberately broad, and a few extractors under-deliver on their own descriptions. Known cases:


## Extractors that match less than their name suggests

-   **`crypto` does not extract Solana addresses**, despite the `solana` alias resolving and the description mentioning it. A `reSolana` pattern is compiled in `nlgrep.go` but is not wired into the `crypto` extractor. Wiring it in needs a false-positive story first: it is length-bounded Base58 with no checksum, so it would match a great many non-addresses.
-   **`isbns` rejects lowercase prefixes.** The regex is case-insensitive but the validator strips the literal `"ISBN"` case-sensitively, so `ISBN 978-3-16-148410-0` and bare `9783161484100` match while `isbn 978-3-16-148410-0` does not.
-   **`chess_fen` does not sum ranks.** It requires 8 slash-separated ranks and the full trailing field sequence, but does not verify that each rank describes 8 squares — `pppp/8/8/8/8/8/8/8 w KQkq - 0 1` is accepted.
-   **`metar` and `user_agents` capture a prefix, not the whole record.** `metar` stops after the visibility group; `user_agents` matches only `Mozilla/5.0`-prefixed strings and stops at the first unsupported character.
-   **`subjects` returns at most one match per line** and is anchored to the start of the line. `Subject:` appearing mid-line is not matched.
-   **`names` requires an honorific plus two or more capitalized tokens**: `Mr. John Smith` matches, `Mr. Smith` does not.


## Expected false positives

These types match by shape alone and will pick up unrelated digits and paths in mixed data:

-   `phone_numbers` matches digit runs inside credit card numbers, IBANs, and UUIDs.
-   `semver` matches the `10.0.0` inside an IP address such as `10.0.0.5`.
-   `xpath` matches ordinary Unix paths — `/usr/local/bin/thing` is reported as an XPath expression.
-   `hashes` cannot distinguish a SHA-1 digest from any other 40-character hex string.

Pipe through `--line` to inspect surrounding context when precision matters, or pick the checksum-backed type where one exists.

---


# Architecture & Performance

-   **Single File, Zero Dependencies**: All logic lives in `nlgrep.go` — validators, precompiled regexes, the `Registry`, the intent router, and the stream processor. Adding a data type means adding a regex (plus a validator if it has a checksum) and appending one `Extractor` entry; flag parsing, help text, and the router all iterate the registry generically.
-   **Zero Memory Bloat**: Stream processing reads inputs line-by-line via `bufio.Scanner` with a buffer expandable up to 10MB per line for minified JSON/HTML files. Without `-A~/`-B~/~&#x2013;line~, output streams in O(1) memory.
-   **Bounded Context Buffering**: The `-B` flag uses a sliding slice buffer sized strictly to the requested line count, ensuring constant memory overhead regardless of whether the file is 10 KB or 100 GB.
-   **RE2 Safety**: Go's native regular expression library prevents catastrophic backtracking (ReDoS attacks) that affect utilities built on PCRE. All patterns are precompiled once at package init and use RE2 syntax only — no backreferences or lookahead.

