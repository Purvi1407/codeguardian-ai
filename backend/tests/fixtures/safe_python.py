"""
Benign functions that look similar to the vulnerable patterns in
vulnerable_python.py but are NOT vulnerable, or that use APIs the rules
must not confuse with the dangerous ones.

These are the "false positive" regression fixtures — every function here
must produce ZERO findings. If one starts firing after a rule change,
that's a real regression, not a stricter rule working as intended.

DO NOT import or execute this file — it's static analysis input only.
"""
import os
import subprocess
import hashlib
import hmac
import json
import yaml
import requests
import random


# ---- sql-injection-string-build: parameterized queries are safe ----

def safe_sql_parameterized_qmark(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def safe_sql_parameterized_named(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})


def safe_sql_static_string_only(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")


# ---- command-injection-shell-true: shell=False (or omitted) is safe ----

def safe_subprocess_no_shell(user_input):
    subprocess.run(["echo", user_input])


def safe_subprocess_shell_explicit_false(user_input):
    subprocess.run(["echo", user_input], shell=False)


# ---- command-injection-os-system: literal command string is safe ----

def safe_os_system_literal():
    os.system("echo hello")


# ---- hardcoded-secret: loaded from env/config, not a literal ----

def safe_secret_from_env():
    password = os.environ["DB_PASSWORD"]
    return password


def safe_secret_from_getenv():
    api_key = os.getenv("API_KEY")
    return api_key


def safe_secret_empty_placeholder():
    # Trivial placeholder (len <= 3) — not worth flagging
    token = ""
    return token


# ---- insecure-deserialization: json instead of pickle/unsafe yaml ----

def safe_deserialization_json(data):
    return json.loads(data)


def safe_deserialization_yaml_safe_loader(data):
    return yaml.load(data, Loader=yaml.SafeLoader)


def safe_deserialization_yaml_safe_load(data):
    return yaml.safe_load(data)


# ---- dangerous-eval-exec: literal argument, or not a bare eval/exec ----

def safe_eval_literal_argument():
    return eval("2 + 2")


class SandboxedEvaluator:
    """Mimics a scoped math evaluator (e.g. the mathjs.eval() pattern) —
    this is a *method* call (obj.eval(...)), not the builtin eval(), and
    the rule must not confuse the two."""

    def eval(self, expr):
        return expr


def safe_eval_is_actually_a_method(expr):
    evaluator = SandboxedEvaluator()
    return evaluator.eval(expr)  # NOT the builtin eval — must not fire


# ---- weak-crypto-hash: HMAC signing and modern hashes are safe ----

def safe_crypto_sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_crypto_hmac_with_sha1_for_signing(key, message):
    # HMAC-SHA1 for signing/verification is a different threat model than
    # using bare SHA1 for password hashing — hashlib.sha1() itself isn't
    # even called here, hmac.new() is, so the rule correctly won't fire.
    return hmac.new(key, message, digestmod="sha1").hexdigest()


# ---- debug-mode-enabled: debug=False, or no debug kwarg at all ----

def safe_debug_false(app):
    app.run(debug=False)


def safe_debug_not_specified(app):
    app.run(host="0.0.0.0", port=8000)


# ---- tls-verification-disabled: verify=True or omitted (defaults True) ----

def safe_tls_verify_true(url):
    return requests.get(url, verify=True)


def safe_tls_verify_omitted(url):
    return requests.get(url)


# ---- call targets that are neither a plain name nor a dotted attribute ----

def safe_call_target_not_name_or_attribute(get_handler):
    # get_handler() returns a callable, so the outer call's .func is a
    # Call node itself — neither ast.Name nor ast.Attribute. Exercises
    # the fallback branch in SecurityRuleVisitor._call_name/_call_root.
    return get_handler()()


# ---- path-traversal-open: fixed literal path is safe ----

def safe_open_literal_path():
    return open("/etc/app/config.json")


# ---- insecure-random-token: secrets module is the safe choice ----

def safe_random_token_uses_secrets_module():
    import secrets
    token = secrets.token_urlsafe(32)
    return token


def safe_random_non_secret_variable():
    # "random" module use is fine when the variable isn't security-named
    dice_roll = random.randint(1, 6)
    return dice_roll


# ---- flask-cookie-missing-secure-flag: both flags present is safe ----

def safe_cookie_with_both_flags(response, session_id):
    response.set_cookie("session_id", session_id, secure=True, httponly=True)
    return response

