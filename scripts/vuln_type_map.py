#!/usr/bin/env python3
"""Map a free-text vulnerability-type string to a CWE id.

Patchstack records carry a `vuln_type` string instead of a CWE field. Those strings
are almost always CWE *titles* ("Deserialization of Untrusted Data"), sometimes
abbreviated ("SQL Injection"), and occasionally a house term ("Broken Access
Control"). Mapping them back to CWE ids lets the whole corpus be attributed through
the single CWE->class map in kb/taxonomy.json, instead of maintaining two schemes.

Matching is keyword-based and ORDER SENSITIVE: the most specific patterns must come
first, because several titles legitimately contain each other's keywords (a "Path
Traversal" title also contains "Traversal"; an SSRF title contains "Request
Forgery", which would otherwise match CSRF).

Python 3.8+. Standard library only.
"""

import re

# (compiled pattern, CWE id). First match wins, so order is significant.
_RULES = [
    # --- must precede the broader patterns they overlap with
    (r"server-?side request forgery|\bssrf\b",                     "CWE-918"),
    (r"cross-?site request forgery|\bcsrf\b",                      "CWE-352"),
    (r"authorization bypass through user-?controlled key",         "CWE-639"),
    (r"php remote file inclusion|filename for include/require",    "CWE-98"),
    (r"local file inclusion|remote file inclusion|file inclusion",  "CWE-98"),
    (r"path traversal|limitation of a pathname|directory traversal", "CWE-22"),

    # --- short house-style names Patchstack also uses; these must sit near the top
    #     of their family so the longer CWE titles above still win where both apply.
    (r"arbitrary file upload",                                     "CWE-434"),
    (r"arbitrary file download|arbitrary file read",               "CWE-22"),
    (r"insecure direct object reference|\bidor\b",                 "CWE-639"),
    (r"remote code execution|arbitrary code execution|\brce\b",    "CWE-94"),
    (r"improper authentication",                                   "CWE-287"),
    (r"improper validation of specified quantity",                 "CWE-20"),
    (r"arbitrary file deletion",                                   "CWE-73"),
    (r"full path disclosure",                                      "CWE-200"),

    # --- injection family
    (r"sql injection|sql command",                                 "CWE-89"),
    (r"script-?related html tags",                                 "CWE-80"),
    (r"cross-?site scripting|\bxss\b",                             "CWE-79"),
    (r"code injection|control of generation of code",              "CWE-94"),
    (r"command injection|os command",                              "CWE-78"),
    (r"expression language|template injection",                    "CWE-1336"),
    (r"formula|csv injection",                                     "CWE-1236"),
    (r"xml external entity|\bxxe\b",                               "CWE-611"),
    (r"deserialization|object injection",                          "CWE-502"),

    # --- access control / auth
    (r"missing authorization",                                     "CWE-862"),
    (r"incorrect authorization|improper authorization",            "CWE-863"),
    (r"broken access control|improper access control",             "CWE-284"),
    (r"missing authentication",                                    "CWE-306"),
    (r"authentication bypass|broken authentication|bypass vulner", "CWE-288"),
    (r"incorrect privilege assignment|improper privilege|privilege escalation", "CWE-269"),
    (r"unverified password change",                                "CWE-620"),
    (r"weak password recovery|forgot.*password",                   "CWE-640"),
    (r"session fixation",                                          "CWE-384"),

    # --- files
    (r"unrestricted upload|dangerous type",                        "CWE-434"),
    (r"file deletion|deletion of file",                            "CWE-73"),

    # --- disclosure
    (r"sensitive system information",                              "CWE-497"),
    (r"insertion of sensitive information",                        "CWE-201"),
    (r"log file",                                                  "CWE-532"),
    (r"sensitive data exposure|exposure of sensitive information|information disclosure", "CWE-200"),
    (r"files or directories accessible",                           "CWE-552"),

    # --- misc
    (r"open redirect|url redirection",                             "CWE-601"),
    (r"hard-?coded credential",                                    "CWE-798"),
    (r"insufficiently random|weak.*random|predictable",            "CWE-330"),
    (r"server-?side template",                                     "CWE-1336"),
    (r"denial of service",                                         "CWE-400"),
    (r"race condition",                                            "CWE-362"),
    (r"improper certificate|certificate validation",               "CWE-295"),
    (r"insufficient verification of data authenticity",            "CWE-345"),
    (r"improper input validation",                                 "CWE-20"),
]

_COMPILED = [(re.compile(p, re.I), c) for p, c in _RULES]


def vuln_type_to_cwe(text):
    """Return a CWE id for a free-text vulnerability type, or None if unrecognised."""
    if not text:
        return None
    for pattern, cwe in _COMPILED:
        if pattern.search(text):
            return cwe
    return None


if __name__ == "__main__":
    # Self-test against the real Patchstack vocabulary, including the ordering traps.
    CASES = [
        ("Server-Side Request Forgery (SSRF)", "CWE-918"),
        ("Cross-Site Request Forgery (CSRF)", "CWE-352"),
        ("Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "CWE-79"),
        ("Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "CWE-80"),
        ("Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "CWE-89"),
        ("Deserialization of Untrusted Data", "CWE-502"),
        ("Missing Authorization", "CWE-862"),
        ("Broken Access Control", "CWE-284"),
        ("Unrestricted Upload of File with Dangerous Type", "CWE-434"),
        ("Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "CWE-22"),
        ("Improper Control of Filename for Include/Require Statement in PHP Program "
         "('PHP Remote File Inclusion')", "CWE-98"),
        ("Authorization Bypass Through User-Controlled Key", "CWE-639"),
        ("URL Redirection to Untrusted Site ('Open Redirect')", "CWE-601"),
        ("Incorrect Privilege Assignment", "CWE-269"),
        ("Exposure of Sensitive System Information to an Unauthorized Control Sphere", "CWE-497"),
        ("Local File Inclusion", "CWE-98"),
        ("Authentication Bypass Using an Alternate Path or Channel", "CWE-288"),
    ]
    bad = 0
    for text, want in CASES:
        got = vuln_type_to_cwe(text)
        if got != want:
            bad += 1
            print("FAIL want=%-10s got=%-10s %s" % (want, got, text[:60]))
    print("%d/%d ordering + mapping cases pass" % (len(CASES) - bad, len(CASES)))
    raise SystemExit(1 if bad else 0)
