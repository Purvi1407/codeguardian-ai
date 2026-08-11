/**
 * Benign functions that look similar to the vulnerable patterns in
 * vulnerable_js.js but must NOT fire any rule. Every function here is a
 * false-positive regression check.
 *
 * DO NOT import or execute this file — it's static analysis input only.
 */

// ---- sql-injection-string-build: parameterized/static queries are safe ----

function safe_sql_parameterized(id) {
  db.query("SELECT * FROM users WHERE id = ?", [id]);
}

function safe_sql_static_string_only() {
  db.query("SELECT COUNT(*) FROM users");
}

// ---- command-injection-js-exec: RegExp.exec() must not be confused with child_process.exec() ----

function safe_regex_exec_literal_pattern(str) {
  const re = /foo/;
  return re.exec(str);
}

function safe_regex_exec_named_variable(str) {
  return someRegex.exec(str);
}

// ---- dangerous-eval-exec: literal argument, or a method named eval that isn't the builtin ----

function safe_eval_literal_argument() {
  return eval("2 + 2");
}

function safe_eval_is_actually_a_method(expr) {
  // Mirrors the mathjs.eval() case from manual DVNA testing: a method
  // call named "eval" on an object, not the global eval() builtin —
  // the AST distinguishes a bare identifier call from a member-expression
  // call, so this correctly does not fire.
  const evaluator = { eval: (x) => x };
  return evaluator.eval(expr);
}

// ---- xss-innerhtml-assignment: literal string is safe ----

function safe_innerhtml_literal() {
  el.innerHTML = "<b>static content</b>";
}

// ---- weak-crypto-hash: modern hash algorithms are safe ----

function safe_crypto_sha256() {
  return crypto.createHash('sha256');
}

// ---- insecure-cors-wildcard: specific origin, not a wildcard ----

function safe_cors_specific_origin(res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://example.com');
}

function safe_cors_origin_config_specific() {
  app.use(cors({ origin: 'https://example.com' }));
}

// ---- jwt-none-algorithm: a real algorithm, not "none" ----

function safe_jwt_proper_algorithm(token, secret) {
  jwt.verify(token, secret, { algorithms: ['HS256'] });
}

// ---- hardcoded-secret: loaded from environment, not a literal ----

function safe_secret_from_env() {
  const password = process.env.DB_PASSWORD;
  return password;
}

function safe_secret_empty_placeholder() {
  const token = "";
  return token;
}

// ---- arrow functions and class methods must be scanned too, not just function declarations ----

const safe_arrow_function_no_issue = (id) => {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
};

class SafeService {
  lookup(id) {
    return db.query("SELECT * FROM users WHERE id = ?", [id]);
  }
}

// ---- taint tracking must clear on reassignment, not stick forever ----

function safe_taint_cleared_on_reassignment(id) {
  let q = `SELECT * FROM users WHERE id = ${id}`;
  q = "SELECT COUNT(*) FROM users"; // reassigned to a safe literal
  db.query(q); // must NOT fire — q is no longer tainted at this point
}

// ---- destructuring declarators must not crash the analyzer ----

function safe_destructured_declaration() {
  const { query } = require("./db");
  return query;
}

// ---- known limitation, documented rather than silently missed:
// require('child_process').exec(cmd) is NOT detected, because the
// object side of the member expression is a call_expression
// (require(...)), not a plain identifier — _member_root_identifier
// deliberately returns None rather than guessing. The direct
// `child_process.exec(cmd)` / `cp.exec(cmd)` forms ARE detected (see
// vulnerable_js.js). This matches the old regex version's behavior for
// the same construct — not a Phase 2 regression, a pre-existing,
// now-documented gap. ----

function known_gap_require_child_process_exec_not_detected(cmd) {
  require("child_process").exec(cmd);
}
