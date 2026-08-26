# Attribution and Data Licensing

wpsentinel derives its knowledge base from public vulnerability databases. Those sources
grant redistribution rights **conditionally**, and this project must honour those
conditions. This file records them so the obligations survive contributor turnover.

> Verified 2026-08-26 against the Wordfence Intelligence V3 API documentation, the
> Wordfence Intelligence Community Edition Terms, and the CVE Program Terms of Use.

## Wordfence Intelligence (Defiant Inc.)

The Wordfence Intelligence Vulnerability Data Feed is free for personal and commercial
use. Each record carries this license:

> Copyright 2012–2026 Defiant Inc.
>
> Defiant hereby grants you a perpetual, worldwide, non-exclusive, no-charge,
> royalty-free, irrevocable copyright license to reproduce, prepare derivative works of,
> publicly display, publicly perform, sublicense, and distribute this software
> vulnerability information. Any copy of the software vulnerability information you make
> for such purposes is authorized provided that you include a hyperlink to this
> vulnerability record, and reproduce Defiant's copyright designation and this license
> in any such copy.

License terms: <https://www.wordfence.com/wti-community-edition-terms-and-conditions/>

**What this obliges us to do:**

1. **Keep the hyperlink.** Every derived record must retain a link back to its source
   vulnerability record. This is why `source_url` is a required, non-droppable field in
   `kb/SCHEMA.md` — it is a license condition, not merely good provenance hygiene.
2. **Reproduce the copyright and license.** This file satisfies that for the repository;
   it must ship with any redistribution.

## MITRE / CVE Program

CVE records carry:

> Copyright 1999–2026 The MITRE Corporation
>
> CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge,
> royalty-free, irrevocable copyright license to reproduce, prepare derivative works of,
> publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities
> and Exposures (CVE®). Any copy you make for such purposes is authorized provided that
> you reproduce MITRE's copyright designation and this license in any such copy.

Terms: <https://www.cve.org/Legal/TermsOfUse>

## NVD (NIST)

NVD data is US Government work in the public domain. NIST requests attribution and
does not endorse derived products. wpsentinel is not affiliated with or endorsed by NIST.

## Patchstack

Patchstack database entries are referenced by URL for provenance. Where entry content is
summarized, it is reduced to the abstract vulnerability pattern rather than reproduced
verbatim.

## WordPress.org

Code excerpts from `plugins.trac.wordpress.org` are quoted minimally — only the few lines
needed to explain a root cause — under fair use for security education. Plugin code is
GPL-licensed. Excerpts are always accompanied by their Trac URL.

## Our own scope choice

wpsentinel deliberately records **no plugin names, vendor names, or researcher credits.**
This is a project scope decision: the goal is to teach the vulnerability *pattern*, not to
index victims. It has a side benefit — it keeps the knowledge base from functioning as a
targeting list for still-unpatched installations.

Researchers who discovered these issues deserve credit, and it is preserved in full at the
`source_url` for every record. Follow the link.
