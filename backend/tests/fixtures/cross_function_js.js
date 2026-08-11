/**
 * Fixtures specifically for Phase 3's bounded, one-hop cross-function
 * parameter taint tracking in analyzer/js_ts_rules.py. Mirrors
 * cross_function_python.py in structure and intent.
 *
 * DO NOT import or execute this file — it's static analysis input only.
 */

// ---- one-hop cross-function: sink lives in a helper, taint originates
// in the caller and is passed in as an argument ----

function runQueryOneHop(query) {
  db.query(query);
}

function callerPassesDynamicViaVariable(userId) {
  const q = `SELECT * FROM users WHERE id = ${userId}`;
  runQueryOneHop(q);
}

function callerPassesDynamicInline(userId) {
  runQueryOneHop(`SELECT * FROM users WHERE id = ${userId}`);
}

// ---- a helper called ONLY with safe, static arguments must never fire ----

function runQueryOnlyCalledSafely(query) {
  db.query(query);
}

function callerAlwaysPassesStaticString() {
  runQueryOnlyCalledSafely("SELECT COUNT(*) FROM users");
}

// ---- alias propagation: renaming a tainted variable within the same
// function must not break tracking ----

function aliasChainStillDetected(userId) {
  const q1 = `SELECT * FROM users WHERE id = ${userId}`;
  const q2 = q1;
  db.query(q2);
}

function aliasClearedBySafeReassignment(userId) {
  let q = `SELECT * FROM users WHERE id = ${userId}`;
  q = "SELECT COUNT(*) FROM users";
  db.query(q); // must NOT fire — q is no longer tainted here
}

// ---- an untainted parameter passed through does NOT seed the callee
// (we don't treat every bare parameter as a taint source, only ones with
// a demonstrated dynamic value at some call site in this file) ----

function runCommandNotSeeded(cmd) {
  child_process.exec(cmd);
}

function callerPassesUnprovenParameter(userInput) {
  // userInput is itself just a bare parameter here, with no local
  // taint of its own — this must NOT cause runCommandNotSeeded to fire.
  runCommandNotSeeded(userInput);
}

// ---- two-hop chain: intentionally NOT detected — documents the
// one-hop scope limit rather than leaving it a silent gap ----

function hopA(x) {
  hopB(x);
}

function hopB(y) {
  db.query(y);
}

function entryPointTwoHopsAway(userId) {
  const q = `SELECT * FROM users WHERE id = ${userId}`;
  hopA(q);
}
