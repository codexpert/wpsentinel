# Patchstack harvest report

**Date:** 2026-08-26
**Script:** `scripts/harvest_patchstack.py` (stdlib-only Python 3, resumable, `--limit N` / `--all`)
**Output:** `data/raw/patchstack.ndjson` — 17,902 records
**Scope:** WordPress plugin/theme/core, disclosed 2023-01-01 → 2026-08-26

---

## (a) Access method

`patchstack.com/database/` is a **Nuxt 3 SSR app**, not a WordPress site — no `wp-json`,
no `_next/data`, no REST feed. Four candidate routes were investigated; two worked.

| # | Route | Verdict |
|---|---|---|
| 1 | `GET /database/` → `<script id="__NUXT_DATA__">` | **USED.** SSR payload, devalue-encoded, 20 records/request |
| 2 | `hub-vdp-api-production-csruhi.patchstack.cloud/public/home?page=N` | **BLOCKED** — HTTP 403 anti-bot interstitial |
| 3 | `patchstack.com/api/database/home` (same-origin proxy) | **NOT USED** — `Disallow: /api/` in robots.txt |
| 4 | CVE Program `cvelistV5` bulk release, filtered to the Patchstack CNA | **USED.** Primary bulk source |

### Route 1 — live SSR payload (robots-allowed)

The `/database/` HTML embeds a `__NUXT_DATA__` JSON blob in Nuxt's flat "devalue"
format (a node array with index references — needs a resolver, not plain `json.loads`
of a nested object). Resolved, it yields Patchstack's own list rows:

```json
{"platform":"WordPress","slug":"...","affected_in":"<= 28.4","fixed_in":"28.4.1",
 "type":"Cross Site Scripting (XSS)","cvss":6.5,"cve":null,"kind":"Theme",
 "clean_title":"Authenticated (Contributor+) Stored Cross-Site Scripting via ...",
 "disclosure_date":"2026-08-25T19:08:00.000000Z", ...}
```

Two behaviours matter:

- **`?page=N` is ignored server-side.** Pagination is client-side only; SSR always
  returns page 1. The payload's own `next_page_url` points at the blocked host (route 2).
- **`?search=<term>` IS honoured server-side.** It changes both the SSR cache key
  (`home-{"search":"sql"}`) and the returned rows.

So each distinct search term is an independent 20-row window onto the corpus. The
harvester sweeps a 133-term keyword list (privilege tiers, vulnerability classes,
common advisory phrasing) → **1,815 unique rows, 1,355 in-scope records.**
`?type=` and `?searchTerm=` are *not* honoured — they alter the cache key but return
the unfiltered set, which is an easy way to be fooled into thinking filtering works.

Detail pages (`/database/<slug>`) are **not** usable: they render a `404 Nothing to
see here...` body server-side and hydrate entirely client-side from route 2.
The sitemap (`sitemap-0.xml`, the only child of `sitemap-index.xml`) contains
marketing and article URLs but **no `/database/` entries**, so it offers no enumeration.

### Route 4 — Patchstack CNA records via the CVE Program (primary bulk source)

Since routes 2 and 3 are off-limits and route 1 caps at 20 rows/request, bulk
harvesting uses Patchstack's *own* authoritative machine-readable publication channel.
**Patchstack is a CVE Numbering Authority** (`assignerOrgId 21595511-bba5-4825-b968-b78d1f9984a3`),
so every vulnerability they assign a CVE to is published as a CVE Record whose **CNA
container is authored by Patchstack** — their title, their CWE mapping, their CVSS
score, and a `patchstack.com/database/...` provenance URL.

- Source: `https://github.com/CVEProject/cvelistV5/releases/latest`
- Asset: `2026-08-26_all_CVEs_at_midnight.zip.zip`, 588 MB, release tag `cve_2026-08-26_0600Z`
- **Doubly nested:** the outer zip holds a single member `cves.zip`, which holds the
  per-CVE JSON tree (383,624 entries). The script unpacks one level.
- Filter: `cveMetadata.assignerShortName == "Patchstack"`, `state != REJECTED`,
  `datePublished >= 2023-01-01`, software type resolvable to plugin/theme/core.
- No rate limits, open licence, refreshed several times daily.

The bundle is cached **outside the repo** (system temp dir, `--cache-dir` to override)
so the working tree only ever contains harvested output. One download (~2.5 min);
the scan itself takes ~9 s thanks to a bytes-level `b"Patchstack" in blob` prefilter
that skips JSON parsing for the ~97 % of records assigned by other CNAs.

**Politeness:** descriptive User-Agent, a global ≥1 s inter-request floor, and
exponential backoff honouring `Retry-After` on 429/5xx. Total network requests for a
full run: 134 (133 SSR terms + 1 GitHub API) plus the one-time bundle download.

---

## (b) Records harvested

| | |
|---|---|
| **Total records** | **17,902** (0 duplicate `source_id`) |
| CVE channel (route 4) | 16,547 |
| SSR channel (route 1) | 1,355 |
| **Date range** | **2023-01-23 → 2026-08-25** |
| Records outside scope (pre-2023) | 0 |
| Schema conformance | 17,902 / 17,902 exact field-set match |

By year: 2023 → 1,891 · 2024 → 4,524 · 2025 → 7,083 · 2026 → 4,404 (partial year)

By `software_type`: plugin 16,082 (89.8 %) · theme 1,816 (10.1 %) · core 4 (0.02 %)

By `severity`: medium 54.0 % · high 37.3 % · critical 8.1 % · low 0.5 %

Field completeness — `title`/`source_url`/`software_type`/`disclosed` 100 %;
`cvss` and `severity` 99.99 %; `vuln_type` 99.98 %; `cve` 92.4 %;
**`patched_version` 59.0 %** (see caveat below).

The two channels do **not** overlap (0 shared `source_id`; all 1,355 SSR-channel rows
have `cve: null` because Patchstack's list endpoint does not populate the CVE field).
A normalized-slug check surfaced 62 near-matches, all verified as genuinely *distinct*
advisories in the same product at different affected versions — not duplicates.

---

## (c) Distributions — taxonomy input

### `vuln_type`

⚠️ **The dataset carries two vocabularies**, because the two channels label
differently. Rank them separately, not as one merged list.

**CVE channel (n=16,547)** — Patchstack's CWE mapping, 74 distinct values. Top 15:

| vuln_type | n | % of all |
|---|---:|---:|
| Improper Neutralization of Input During Web Page Generation ('XSS') | 5,957 | 33.28 % |
| Missing Authorization | 3,119 | 17.42 % |
| Cross-Site Request Forgery (CSRF) | 2,351 | 13.13 % |
| Improper Control of Filename for Include/Require Statement (LFI/RFI) | 1,053 | 5.88 % |
| Improper Neutralization of Special Elements used in an SQL Command | 968 | 5.41 % |
| Deserialization of Untrusted Data | 539 | 3.01 % |
| Improper Neutralization of Input During Web Page Generation (XSS, variant) | 358 | 2.00 % |
| Unrestricted Upload of File with Dangerous Type | 328 | 1.83 % |
| Improper Limitation of a Pathname to a Restricted Directory | 298 | 1.66 % |
| Incorrect Privilege Assignment | 176 | 0.98 % |
| Server-Side Request Forgery (SSRF) | 173 | 0.97 % |
| Authorization Bypass Through User-Controlled Key | 152 | 0.85 % |
| Insertion of Sensitive Information Into Sent Data | 151 | 0.84 % |
| Exposure of Sensitive System Information | 132 | 0.74 % |
| Improper Control of Generation of Code ('Code Injection') | 113 | 0.63 % |

**SSR channel (n=1,355)** — Patchstack's *native* short taxonomy, 34 distinct values.
This is the cleaner vocabulary for ranking; it is what the product itself uses:

| vuln_type | n | % of SSR |
|---|---:|---:|
| Cross Site Scripting (XSS) | 294 | 21.70 % |
| Broken Access Control | 235 | 17.34 % |
| SQL Injection | 126 | 9.30 % |
| Sensitive Data Exposure | 110 | 8.12 % |
| Cross Site Request Forgery (CSRF) | 81 | 5.98 % |
| Broken Authentication | 64 | 4.72 % |
| Privilege Escalation | 60 | 4.43 % |
| Bypass Vulnerability | 45 | 3.32 % |
| Local File Inclusion | 36 | 2.66 % |
| PHP Object Injection | 35 | 2.58 % |
| Server Side Request Forgery (SSRF) | 34 | 2.51 % |
| Arbitrary File Upload | 30 | 2.21 % |
| Remote Code Execution (RCE) | 28 | 2.07 % |
| Arbitrary File Deletion | 28 | 2.07 % |
| Insecure Direct Object References (IDOR) | 28 | 2.07 % |
| Directory Traversal | 24 | 1.77 % |
| Arbitrary Code Execution | 17 | 1.25 % |
| Arbitrary File Download | 16 | 1.18 % |
| Deserialization of untrusted data | 12 | 0.89 % |
| Other Vulnerability Type | 9 | 0.66 % |

Tail (≤6 each): Remote File Inclusion, Path Traversal, Open Redirection, Settings
Change, Arbitrary Content Deletion, Denial of Service Attack, XML External Entity
(XXE), Content Injection, Backdoor, Race Condition, Content Spoofing, CSV Injection,
Multiple Vulnerabilities, Unknown.

**Headline:** the two vocabularies agree on the shape. XSS is the single largest class
(~22–33 %), followed by a large **authorization** bucket (Missing Authorization /
Broken Access Control, 17 %), then CSRF (~6–13 %), then file-inclusion and SQLi.
XSS + authorization + CSRF ≈ **two-thirds of everything**.

### `auth_required`

| auth_required | all (n=17,902) | SSR only (n=1,355) | CVE only (n=16,547) |
|---|---:|---:|---:|
| unknown | 91.30 % | 55.87 % | 94.20 % |
| unauthenticated | 7.24 % | 24.94 % | 5.79 % |
| subscriber+ | 0.51 % | 6.72 % | ~0 % |
| contributor+ | 0.46 % | 6.13 % | ~0 % |
| admin+ | 0.23 % | 3.03 % | ~0 % |
| editor+ | 0.19 % | 2.44 % | ~0 % |
| author+ | 0.07 % | 0.89 % | ~0 % |

**This is the most important caveat in the report.** `auth_required` is *not* a
structured field anywhere in Patchstack's data — it is prose embedded in the advisory
title, and **the two channels state it at very different rates**:

- Patchstack's **website** titles (`clean_title`) use the rich modern format —
  `"Authenticated (Contributor+) Stored Cross-Site Scripting via 'icon_box_2' Shortcode"` —
  so **44 %** of SSR rows yield a tier.
- Patchstack's **CVE** titles largely use an older format —
  `"WordPress vSlider Plugin <= 4.1.2 is vulnerable to Cross Site Request Forgery (CSRF)"` —
  with no privilege wording at all. Only **6 %** yield a tier (essentially only the
  explicit "Unauthenticated ..." ones).

Only 262 of 16,986 CVE-channel titles and 334 slugs mention authentication at all.
**Among rows where a tier IS stated, the ranking is: unauthenticated ≫ subscriber+ >
contributor+ > admin+ > editor+ > author+.** Treat the 91 % `unknown` as *unstated by
the source*, not as "no auth required".

The harvester parses both the parenthesised title form and the hyphenated slug form
(`...-authenticated-contributor-stored-xss-...`), and joins the two channels on the
Patchstack slug to backfill tiers. That join currently recovers 0 rows — the SSR search
results and the CVE set are disjoint (SSR surfaces recent, not-yet-CVE'd advisories).
A wider SSR sweep would make this join productive.

**Nothing is inferred.** A tier is recorded only when Patchstack's own text states it.
CVSS `privilegesRequired` was deliberately *not* used to fill this field: `PR:N`
correlates with "unauthenticated" but is a different vocabulary, and using it would
have manufactured ~15,000 values the source never asserted. If you want that proxy,
it is available in the CVSS vectors and can be applied downstream as an explicitly
derived column.

---

## (d) Trac references

**0 collected.** `data/raw/trac_refs_patchstack.txt` is intentionally empty.

This is a real property of the source, not a harvester bug. Across **16,703 reference
URLs** in the dataset there are **zero** `plugins.trac.wordpress.org` and **zero**
`themes.trac.wordpress.org` links. Reference hosts break down as:

| host | n |
|---|---:|
| patchstack.com | 17,089 |
| vdp.patchstack.com | 17 |
| packetstormsecurity.com | 5 |
| github.com | 5 |
| snicco.io | 4 |
| wordpress.org (release announcements only) | 4 |
| other one-offs | ~10 |

Patchstack CVE records cite **only their own VDB entry** (`tags: ["vdb-entry"]`).
They do not link patch changesets. **Changeset references must come from another
source** — Wordfence advisories (via NVD) do cite `plugins.trac.wordpress.org`
changesets, and the sibling `data/raw/nvd.ndjson` already contains some. Recommend
retargeting the trac-mining stage at the NVD/Wordfence harvester output.

---

## (e) Blockers and caveats

1. **Upstream JSON API is blocked.** `hub-vdp-api-production-csruhi.patchstack.cloud/public/home`
   returns HTTP 403 with an anti-bot interstitial ("Nice Try! But you're not part of
   the gang"). Not circumvented — treated as a hard stop.
2. **`/api/` is disallowed by robots.txt.** `patchstack.com/robots.txt` has
   `Disallow: /api/` in the `User-agent: *` group, which is the group a generic client
   matches, so the same-origin `/api/database/home` proxy was left alone. (Patchstack
   *does* publish permissive per-bot groups — `ClaudeBot`, `GPTBot`, `anthropic-ai` etc.
   all get bare `Allow: /` — but this harvester is not those crawlers and did not
   claim to be.)
3. **SSR route is capped at 20 rows/request** with no server-side pagination. The
   search-term sweep is the workaround; widening the term list is the lever if more
   SSR-channel coverage (and thus more stated auth tiers) is wanted.
4. **NVD API was rate-limited** (HTTP 429 immediately, unauthenticated). Not used.
   An `NVD_API_KEY` would help if that route is ever needed.
5. **`patched_version` is null for 41 % of records — by design.** CVE records express
   affected ranges as `lessThanOrEqual`, which is the *last vulnerable* version, not
   the fix. The patched version is taken only from an authoritative marker
   (`versions[].changes[].at` with `status: unaffected`, an explicit `fixed`, or
   `lessThan`, whose semantics do make it the first fixed release). Where the record
   does not state a fix, the field stays null rather than being guessed by bumping a
   version number. Verified: CVE-2024-50427 correctly yields `1.12.4`, not the
   last-affected `1.9.136`.
6. **Two vuln_type vocabularies** (see section c) — do not merge blindly.
7. **`core` coverage is negligible** (4 records). Patchstack's CNA scope is
   overwhelmingly third-party plugins/themes; WordPress core advisories come from the
   WordPress security team, not Patchstack. Source core data elsewhere.

### Schema deviations (please confirm)

- **`auth_required: "editor+"`** — added to the specified enum. Editor is a real and
  frequent Patchstack tier (34 records) sitting between author and admin; collapsing it
  into either neighbour would misstate the privilege ladder that this field exists to
  capture. `customer` and `shop manager` are folded into `subscriber+` / `editor+`
  respectively; `super admin` → `admin+`.
- **`title` retains product names.** The project rule (no plugin/vendor/researcher
  names) is honoured for *fields*: no `product_name`, `vendor`, `product_slug` or
  `credits` is emitted, and `software_type` is derived and the names discarded. But
  Patchstack's advisory titles embed the product name inline
  (`"WordPress SurveyJS plugin <= 1.9.136 - Arbitrary File Upload vulnerability"`),
  and `title` is a required field in the target schema. Titles are kept verbatim rather
  than mangled by redaction. `source_id` and `source_url` likewise contain the product
  slug, which is unavoidable for provenance. Say the word if you want a redaction pass.

---

## Reproducing

```bash
python3 scripts/harvest_patchstack.py --limit 50     # smoke run
python3 scripts/harvest_patchstack.py --all          # full run (~5.5 min warm)
python3 scripts/harvest_patchstack.py --all --reset  # ignore checkpoint, rewrite
python3 scripts/harvest_patchstack.py --source ssr --all   # live site only, no bundle
```

Progress is checkpointed to `data/raw/patchstack_checkpoint.json` (seen ids, completed
search terms, scan index, release tag) after every batch and in a `finally` block, so
an interrupted run resumes without re-fetching or emitting duplicates. Re-running after
a new cvelistV5 release resets the scan index and picks up newly published records.
