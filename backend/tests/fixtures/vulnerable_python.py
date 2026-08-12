"""
One deliberately vulnerable function per rule in analyzer/rules.py.

Each function name is prefixed with the rule_id it's meant to trigger, so
tests can assert "this function fires this rule" without depending on
line numbers, which would make the test suite brittle to edits.

DO NOT import or execute this file — it's static analysis input only.
"""
import os
import pickle
import subprocess
import hashlib
import yaml
import requests
import sqlite3
import random


# ---- sql-injection-string-build ----

def sql_injection_string_build__fstring(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def sql_injection_string_build__concat(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")


def sql_injection_string_build__format_call(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(username))


def sql_injection_string_build__via_variable(conn, user_id):
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)


# ---- command-injection-shell-true ----

def command_injection_shell_true__run(user_input):
    subprocess.run(f"echo {user_input}", shell=True)


def command_injection_shell_true__popen(user_input):
    subprocess.Popen(f"cat {user_input}", shell=True)


# ---- command-injection-os-system ----

def command_injection_os_system__dynamic_arg(filename):
    os.system("cat " + filename)


def command_injection_os_system__variable(cmd):
    os.system(cmd)


# ---- hardcoded-secret ----

def hardcoded_secret__password():
    password = "SuperSecret123!"
    return password


def hardcoded_secret__api_key():
    api_key = "sk-abcdef1234567890"
    return api_key


# ---- insecure-deserialization-pickle ----

def insecure_deserialization_pickle__load(f):
    return pickle.load(f)


def insecure_deserialization_pickle__loads(data):
    return pickle.loads(data)


# ---- insecure-deserialization-yaml ----

def insecure_deserialization_yaml__no_loader(data):
    return yaml.load(data)


def insecure_deserialization_yaml__unsafe_loader(data):
    return yaml.load(data, Loader=yaml.Loader)


# ---- dangerous-eval-exec ----

def dangerous_eval_exec__eval_variable(user_expr):
    return eval(user_expr)


def dangerous_eval_exec__exec_variable(user_code):
    exec(user_code)


# ---- weak-crypto-hash ----

def weak_crypto_hash__md5(data):
    return hashlib.md5(data).hexdigest()


def weak_crypto_hash__sha1(data):
    return hashlib.sha1(data).hexdigest()


# ---- debug-mode-enabled ----

def debug_mode_enabled__flask_app(app):
    app.run(debug=True)


# ---- tls-verification-disabled ----

def tls_verification_disabled__get(url):
    return requests.get(url, verify=False)


def tls_verification_disabled__post(url, payload):
    return requests.post(url, json=payload, verify=False)


# ---- path-traversal-open ----

def path_traversal_open__fstring(filename):
    return open(f"/uploads/{filename}")


def path_traversal_open__via_variable(filename):
    path = f"/uploads/{filename}"
    return open(path)


# ---- insecure-random-token ----

def insecure_random_token__qualified(length):
    token = random.randint(100000, 999999)
    return token


def insecure_random_token__bare_import(length):
    from random import choice
    import string
    password = choice(string.ascii_letters)
    return password


# ---- flask-cookie-missing-secure-flag ----

def flask_cookie_missing_secure_flag__no_flags(response, session_id):
    response.set_cookie("session_id", session_id)
    return response


def flask_cookie_missing_secure_flag__only_httponly(response, session_id):
    response.set_cookie("session_id", session_id, httponly=True)
    return response
