"""
Rule metadata. Detection logic lives in python_rules.py / js_ts_rules.py —
this file is just the human-readable side, kept separate so adding/tuning
a rule's wording doesn't require touching the AST-walking code.

Phase 4 additions to every rule (existing and new):
  - `owasp`: OWASP Top 10 (2021) category — gives a second, widely
    recognized classification alongside CWE, useful for teams that
    triage/report by OWASP category rather than (or in addition to) CWE.
  - `remediation`: a short, general fix suggestion available even from
    the rule-only `/analyze` endpoint, before any AI validation has run.
    This is deliberately generic ("use parameterized queries") rather
    than code-specific — Module 4's `patch_suggestion` is what gives a
    concrete, this-exact-line fix; this field exists so a candidate
    finding is still actionable on its own, without an API key.

Six new rules this phase (see README "Phase 4" section for the full
writeup): path-traversal-open / path-traversal-fs, insecure-random-token
(Python and JS/TS each), flask-cookie-missing-secure-flag,
cookie-missing-secure-flag (JS/TS equivalent).
"""

RULES = {
    "sql-injection-string-build": {
        "title": "SQL query built with string formatting",
        "severity": "high",
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "description": (
            "A SQL query passed to execute()/executemany() is built with "
            "string concatenation, %-formatting, .format(), or an f-string "
            "instead of parameterized placeholders. If any part of the "
            "query includes user input, this allows SQL injection."
        ),
        "remediation": (
            "Use parameterized queries / placeholders (e.g. "
            "cursor.execute(\"...WHERE id = ?\", (id,))) instead of building "
            "the query string with concatenation or formatting."
        ),
    },
    "command-injection-shell-true": {
        "title": "subprocess call with shell=True",
        "severity": "high",
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
        "description": (
            "subprocess.run/Popen/call/check_call/check_output is invoked "
            "with shell=True. If any part of the command includes "
            "unsanitized input, this allows arbitrary command execution."
        ),
        "remediation": (
            "Avoid shell=True. Pass the command as a list of arguments "
            "(e.g. subprocess.run([\"ls\", \"-la\", path])) so arguments are "
            "never interpreted by a shell."
        ),
    },
    "command-injection-os-system": {
        "title": "os.system/os.popen with dynamic argument",
        "severity": "high",
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
        "description": (
            "os.system() or os.popen() is called with an argument that "
            "isn't a plain string literal, suggesting it may include "
            "unsanitized input — a classic command injection vector."
        ),
        "remediation": (
            "Replace os.system()/os.popen() with subprocess.run() using an "
            "argument list (no shell=True), which avoids shell "
            "interpretation of the input entirely."
        ),
    },
    "hardcoded-secret": {
        "title": "Hardcoded credential or secret",
        "severity": "medium",
        "cwe": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": (
            "A variable name suggesting a password, API key, token, or "
            "secret is assigned a string literal directly in source code, "
            "rather than being loaded from environment/config/secret store."
        ),
        "remediation": (
            "Load the value from an environment variable, secret manager, "
            "or config file excluded from version control, instead of a "
            "literal in source. Rotate the credential if it was ever "
            "committed."
        ),
    },
    "insecure-deserialization-pickle": {
        "title": "Unsafe deserialization with pickle",
        "severity": "high",
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "description": (
            "pickle.load()/loads() deserializes data without restriction. "
            "If the source of that data isn't fully trusted, this allows "
            "arbitrary code execution during deserialization."
        ),
        "remediation": (
            "Avoid pickle for untrusted data. Use a safe serialization "
            "format (JSON, or a schema-validated format) instead, or "
            "restrict pickle loading to data your own process wrote."
        ),
    },
    "insecure-deserialization-yaml": {
        "title": "yaml.load() without a safe loader",
        "severity": "high",
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "description": (
            "yaml.load() is called without Loader=yaml.SafeLoader (or is "
            "using yaml.Loader/UnsafeLoader explicitly). Untrusted YAML "
            "input can lead to arbitrary code execution."
        ),
        "remediation": (
            "Use yaml.safe_load(data), or yaml.load(data, "
            "Loader=yaml.SafeLoader) explicitly."
        ),
    },
    "dangerous-eval-exec": {
        "title": "eval()/exec() with a non-literal argument",
        "severity": "high",
        "cwe": "CWE-95",
        "owasp": "A03:2021-Injection",
        "description": (
            "eval() or exec() is called with an argument that isn't a "
            "fixed string literal, meaning its behavior depends on "
            "runtime data — a common code-injection vector."
        ),
        "remediation": (
            "Avoid eval()/exec() on any value influenced by external "
            "input. If dynamic evaluation is genuinely required, use a "
            "restricted parser/evaluator scoped to exactly what's needed "
            "(e.g. ast.literal_eval() for literal data)."
        ),
    },
    "weak-crypto-hash": {
        "title": "Weak hash algorithm (MD5/SHA1)",
        "severity": "low",
        "cwe": "CWE-327",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": (
            "hashlib.md5() or hashlib.sha1() is used. Both are considered "
            "cryptographically broken for security-sensitive purposes "
            "(e.g. password hashing, signatures) — prefer SHA-256+ or a "
            "dedicated password-hashing function like bcrypt/argon2."
        ),
        "remediation": (
            "For password hashing, use bcrypt/argon2/scrypt via a "
            "dedicated library. For general integrity hashing (not "
            "passwords), use SHA-256 or stronger."
        ),
    },
    "debug-mode-enabled": {
        "title": "Debug mode enabled",
        "severity": "medium",
        "cwe": "CWE-489",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": (
            "A .run(debug=True) call was found. Running with debug mode "
            "on in production can expose a werkzeug interactive debugger "
            "that allows arbitrary code execution to anyone who can reach "
            "an error page."
        ),
        "remediation": (
            "Set debug=False (or omit it) in production, and drive it "
            "from an environment variable so it can be safely True only "
            "in local development."
        ),
    },
    "tls-verification-disabled": {
        "title": "TLS certificate verification disabled",
        "severity": "high",
        "cwe": "CWE-295",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": (
            "An HTTP request is made with verify=False, disabling TLS "
            "certificate validation and exposing the request to "
            "man-in-the-middle attacks."
        ),
        "remediation": (
            "Remove verify=False. If a custom/internal CA is the actual "
            "issue, pass verify=\"/path/to/ca-bundle.pem\" instead of "
            "disabling verification entirely."
        ),
    },
    "command-injection-js-exec": {
        "title": "child_process.exec() with dynamic command string",
        "severity": "high",
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
        "description": (
            "exec()/execSync() is called with a template literal or "
            "string concatenation instead of a fixed command. If any "
            "part of the string includes unsanitized input, this allows "
            "arbitrary command execution. Prefer execFile()/spawn() with "
            "an argument array instead of a shell string."
        ),
        "remediation": (
            "Use execFile()/spawn() with an argument array instead of "
            "exec() with a shell string — arguments are never interpreted "
            "by a shell."
        ),
    },
    "xss-innerhtml-assignment": {
        "title": "Unsanitized assignment to innerHTML",
        "severity": "medium",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": (
            "A value built from a variable or template literal is "
            "assigned directly to .innerHTML. If that value includes "
            "unsanitized user input, this allows stored/reflected XSS. "
            "Prefer .textContent for plain text, or a sanitizer (e.g. "
            "DOMPurify) if HTML is genuinely required."
        ),
        "remediation": (
            "Use .textContent for plain text. If HTML is genuinely "
            "required, sanitize with a library like DOMPurify before "
            "assigning to innerHTML."
        ),
    },
    "insecure-cors-wildcard": {
        "title": "CORS allows any origin (wildcard)",
        "severity": "medium",
        "cwe": "CWE-942",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": (
            "CORS is configured to allow requests from any origin "
            "('*'). Combined with credentialed requests, this can let "
            "any website read authenticated responses from this API."
        ),
        "remediation": (
            "Set an explicit allowlist of trusted origins instead of "
            "'*', especially for any endpoint that returns authenticated "
            "or sensitive data."
        ),
    },
    "jwt-none-algorithm": {
        "title": "JWT accepts the 'none' algorithm or is unverified",
        "severity": "high",
        "cwe": "CWE-347",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": (
            "JWT verification explicitly allows the 'none' algorithm, "
            "or a token is decoded without verifying its signature. "
            "Either lets an attacker forge tokens that the application "
            "will accept as valid."
        ),
        "remediation": (
            "Explicitly restrict `algorithms` to the specific algorithm(s) "
            "your app actually issues tokens with (e.g. ['HS256']), and "
            "never include 'none'."
        ),
    },
    "path-traversal-open": {
        "title": "File path built dynamically and passed to open()",
        "severity": "medium",
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "description": (
            "open() is called with a file path built from string "
            "concatenation, formatting, or an f-string, rather than a "
            "fixed literal. If any part of the path includes unsanitized "
            "user input, this allows path traversal (e.g. '../../etc/passwd') "
            "to read or write files outside the intended directory."
        ),
        "remediation": (
            "Validate and normalize the path (e.g. os.path.realpath) and "
            "confirm it stays within an expected base directory before "
            "opening it, rather than trusting the input directly."
        ),
    },
    "insecure-random-token": {
        "title": "Weak randomness used for a security-sensitive value",
        "severity": "medium",
        "cwe": "CWE-330",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": (
            "A variable name suggesting a token, password, secret, or key "
            "is assigned a value from the standard `random` module (or "
            "Math.random() in JS), which is not cryptographically secure "
            "and can be predictable — unsuitable for anything "
            "security-sensitive."
        ),
        "remediation": (
            "Use a cryptographically secure source: Python's `secrets` "
            "module (e.g. secrets.token_urlsafe()), or "
            "crypto.randomBytes()/crypto.randomUUID() in Node.js."
        ),
    },
    "flask-cookie-missing-secure-flag": {
        "title": "Cookie set without Secure/HttpOnly flags",
        "severity": "low",
        "cwe": "CWE-614",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": (
            "response.set_cookie() is called without both secure=True and "
            "httponly=True. Without `secure`, the cookie can be sent over "
            "plain HTTP; without `httponly`, it's readable by JavaScript, "
            "increasing exposure if an XSS vulnerability exists elsewhere."
        ),
        "remediation": (
            "Pass secure=True and httponly=True to set_cookie() for any "
            "cookie holding a session identifier or other sensitive value."
        ),
    },
    "path-traversal-fs": {
        "title": "File path built dynamically and passed to an fs call",
        "severity": "medium",
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "description": (
            "A Node fs function (readFile/readFileSync/writeFile/"
            "writeFileSync/unlink/unlinkSync) is called with a path built "
            "from template-literal interpolation or string concatenation, "
            "rather than a fixed literal. If any part of the path includes "
            "unsanitized user input, this allows path traversal."
        ),
        "remediation": (
            "Resolve the path with path.resolve()/path.normalize() and "
            "verify it stays within an expected base directory before "
            "using it, rather than trusting the input directly."
        ),
    },
    "cookie-missing-secure-flag": {
        "title": "Cookie set without secure/httpOnly flags",
        "severity": "low",
        "cwe": "CWE-614",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": (
            "res.cookie() is called without both secure: true and "
            "httpOnly: true in its options object. Without `secure`, the "
            "cookie can be sent over plain HTTP; without `httpOnly`, it's "
            "readable by JavaScript, increasing exposure if an XSS "
            "vulnerability exists elsewhere."
        ),
        "remediation": (
            "Pass { secure: true, httpOnly: true } (and typically "
            "sameSite: 'strict' or 'lax') to res.cookie() for any cookie "
            "holding a session identifier or other sensitive value."
        ),
    },
}
