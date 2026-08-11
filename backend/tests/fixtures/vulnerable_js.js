/**
 * One deliberately vulnerable function per rule in analyzer/js_ts_rules.py.
 * Function names are prefixed with the rule_id they must trigger, so
 * tests assert "this function fires this rule" without depending on
 * line numbers (see tests/fixtures/vulnerable_python.py for the same
 * convention on the Python side).
 *
 * DO NOT import or execute this file — it's static analysis input only.
 */

// ---- sql-injection-string-build ----

function sql_injection_string_build__template(id) {
  db.query(`SELECT * FROM users WHERE id = ${id}`);
}

function sql_injection_string_build__concat(name) {
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

function sql_injection_string_build__via_variable(id) {
  const q = `SELECT * FROM users WHERE id = ${id}`;
  db.query(q);
}

// ---- command-injection-js-exec ----

function command_injection_js_exec__child_process(cmd) {
  child_process.exec(`rm ${cmd}`);
}

function command_injection_js_exec__bare_via_variable(cmd) {
  const c = `cat ${cmd}`;
  exec(c);
}

// ---- dangerous-eval-exec ----

function dangerous_eval_exec__eval_variable(userInput) {
  eval(userInput);
}

function dangerous_eval_exec__new_function(body) {
  return new Function(body);
}

// ---- xss-innerhtml-assignment ----

function xss_innerhtml_assignment__parameter(data) {
  el.innerHTML = data;
}

function xss_innerhtml_assignment__template(name) {
  el.innerHTML = `Hello ${name}`;
}

// ---- weak-crypto-hash ----

function weak_crypto_hash__md5() {
  return crypto.createHash('md5');
}

function weak_crypto_hash__sha1() {
  return crypto.createHash('sha1');
}

// ---- insecure-cors-wildcard ----

function insecure_cors_wildcard__set_header(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
}

function insecure_cors_wildcard__origin_config() {
  app.use(cors({ origin: '*' }));
}

// ---- jwt-none-algorithm ----

function jwt_none_algorithm__algorithms_array(token, secret) {
  jwt.verify(token, secret, { algorithms: ['none'] });
}

// ---- hardcoded-secret ----

function hardcoded_secret__password() {
  const password = "hunter2222";
  return password;
}

function hardcoded_secret__api_key() {
  const apiKey = "sk-abcdef1234567890";
  return apiKey;
}

// ---- scope coverage: arrow functions and class methods, not just
// `function` declarations, must be scanned and attributed correctly ----

const sql_injection_string_build__arrow_function = (id) => {
  db.query(`SELECT * FROM users WHERE id = ${id}`);
};

class VulnerableService {
  sql_injection_string_build__class_method(id) {
    db.query(`SELECT * FROM users WHERE id = ${id}`);
  }

  sql_injection_string_build__chained_member(id) {
    // Multi-hop member access (this.db.query) — exercises the
    // "walk up through multiple member_expression hops" branch in
    // _member_root_identifier, not just a single a.b access.
    this.db.query(`SELECT * FROM users WHERE id = ${id}`);
  }
}

function jwt_none_algorithm__singular_key(token, secret) {
  jwt.verify(token, secret, { algorithm: 'none' });
}

