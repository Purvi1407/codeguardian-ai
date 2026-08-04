"""
Rule metadata. Detection logic lives in python_rules.py — this file is just
the human-readable side, kept separate so adding/tuning a rule's wording
doesn't require touching the AST-walking code.
"""

RULES = {
    "sql-injection-string-build": {
        "title": "SQL query built with string formatting",
        "severity": "high",
        "cwe": "CWE-89",
        "description": (
            "A SQL query passed to execute()/executemany() is built with "
            "string concatenation, %-formatting, .format(), or an f-string "
            "instead of parameterized placeholders. If any part of the "
            "query includes user input, this allows SQL injection."
        ),
    },
    "command-injection-shell-true": {
        "title": "subprocess call with shell=True",
        "severity": "high",
        "cwe": "CWE-78",
        "description": (
            "subprocess.run/Popen/call/check_call/check_output is invoked "
            "with shell=True. If any part of the command includes "
            "unsanitized input, this allows arbitrary command execution."
        ),
    },
    "command-injection-os-system": {
        "title": "os.system/os.popen with dynamic argument",
        "severity": "high",
        "cwe": "CWE-78",
        "description": (
            "os.system() or os.popen() is called with an argument that "
            "isn't a plain string literal, suggesting it may include "
            "unsanitized input — a classic command injection vector."
        ),
    },
    "hardcoded-secret": {
        "title": "Hardcoded credential or secret",
        "severity": "medium",
        "cwe": "CWE-798",
        "description": (
            "A variable name suggesting a password, API key, token, or "
            "secret is assigned a string literal directly in source code, "
            "rather than being loaded from environment/config/secret store."
        ),
    },
    "insecure-deserialization-pickle": {
        "title": "Unsafe deserialization with pickle",
        "severity": "high",
        "cwe": "CWE-502",
        "description": (
            "pickle.load()/loads() deserializes data without restriction. "
            "If the source of that data isn't fully trusted, this allows "
            "arbitrary code execution during deserialization."
        ),
    },
    "insecure-deserialization-yaml": {
        "title": "yaml.load() without a safe loader",
        "severity": "high",
        "cwe": "CWE-502",
        "description": (
            "yaml.load() is called without Loader=yaml.SafeLoader (or is "
            "using yaml.Loader/UnsafeLoader explicitly). Untrusted YAML "
            "input can lead to arbitrary code execution."
        ),
    },
    "dangerous-eval-exec": {
        "title": "eval()/exec() with a non-literal argument",
        "severity": "high",
        "cwe": "CWE-95",
        "description": (
            "eval() or exec() is called with an argument that isn't a "
            "fixed string literal, meaning its behavior depends on "
            "runtime data — a common code-injection vector."
        ),
    },
    "weak-crypto-hash": {
        "title": "Weak hash algorithm (MD5/SHA1)",
        "severity": "low",
        "cwe": "CWE-327",
        "description": (
            "hashlib.md5() or hashlib.sha1() is used. Both are considered "
            "cryptographically broken for security-sensitive purposes "
            "(e.g. password hashing, signatures) — prefer SHA-256+ or a "
            "dedicated password-hashing function like bcrypt/argon2."
        ),
    },
    "debug-mode-enabled": {
        "title": "Debug mode enabled",
        "severity": "medium",
        "cwe": "CWE-489",
        "description": (
            "A .run(debug=True) call was found. Running with debug mode "
            "on in production can expose a werkzeug interactive debugger "
            "that allows arbitrary code execution to anyone who can reach "
            "an error page."
        ),
    },
    "tls-verification-disabled": {
        "title": "TLS certificate verification disabled",
        "severity": "high",
        "cwe": "CWE-295",
        "description": (
            "An HTTP request is made with verify=False, disabling TLS "
            "certificate validation and exposing the request to "
            "man-in-the-middle attacks."
        ),
    },
    "command-injection-js-exec": {
        "title": "child_process.exec() with dynamic command string",
        "severity": "high",
        "cwe": "CWE-78",
        "description": (
            "exec()/execSync() is called with a template literal or "
            "string concatenation instead of a fixed command. If any "
            "part of the string includes unsanitized input, this allows "
            "arbitrary command execution. Prefer execFile()/spawn() with "
            "an argument array instead of a shell string."
        ),
    },
    "xss-innerhtml-assignment": {
        "title": "Unsanitized assignment to innerHTML",
        "severity": "medium",
        "cwe": "CWE-79",
        "description": (
            "A value built from a variable or template literal is "
            "assigned directly to .innerHTML. If that value includes "
            "unsanitized user input, this allows stored/reflected XSS. "
            "Prefer .textContent for plain text, or a sanitizer (e.g. "
            "DOMPurify) if HTML is genuinely required."
        ),
    },
    "insecure-cors-wildcard": {
        "title": "CORS allows any origin (wildcard)",
        "severity": "medium",
        "cwe": "CWE-942",
        "description": (
            "CORS is configured to allow requests from any origin "
            "('*'). Combined with credentialed requests, this can let "
            "any website read authenticated responses from this API."
        ),
    },
    "jwt-none-algorithm": {
        "title": "JWT accepts the 'none' algorithm or is unverified",
        "severity": "high",
        "cwe": "CWE-347",
        "description": (
            "JWT verification explicitly allows the 'none' algorithm, "
            "or a token is decoded without verifying its signature. "
            "Either lets an attacker forge tokens that the application "
            "will accept as valid."
        ),
    },
}
