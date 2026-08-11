"""
Fixtures specifically for Phase 3's bounded, one-hop cross-function
parameter taint tracking in analyzer/python_rules.py.

DO NOT import or execute this file — it's static analysis input only.
"""


# ---- one-hop cross-function: sink lives in a helper, taint originates
# in the caller and is passed in as an argument ----

def run_query_one_hop(query):
    """The sink itself has no locally-built dynamic string — whether
    this fires depends entirely on whether any caller elsewhere in this
    file passes it something dynamic."""
    cursor.execute(query)


def caller_passes_dynamic_via_variable(user_id):
    q = f"SELECT * FROM users WHERE id = {user_id}"
    run_query_one_hop(q)


def caller_passes_dynamic_inline(user_id):
    run_query_one_hop(f"SELECT * FROM users WHERE id = {user_id}")


# ---- alias propagation: renaming a tainted variable must not break
# tracking within the same function ----

def alias_chain_still_detected(user_id):
    q1 = f"SELECT * FROM users WHERE id = {user_id}"
    q2 = q1  # simple rename/alias — q2 must inherit q1's taint
    cursor.execute(q2)


def alias_cleared_by_safe_reassignment(user_id):
    q = f"SELECT * FROM users WHERE id = {user_id}"
    q = "SELECT COUNT(*) FROM users"  # reassigned to a safe literal
    cursor.execute(q)  # must NOT fire — q is no longer tainted here


# ---- a helper called ONLY with safe, static arguments must never fire ----

def run_query_only_called_safely(query):
    cursor.execute(query)


def caller_always_passes_static_string():
    run_query_only_called_safely("SELECT COUNT(*) FROM users")


# ---- two-hop chain: intentionally NOT detected — documents the
# one-hop scope limit rather than leaving it a silent gap ----

def hop_a(x):
    hop_b(x)


def hop_b(y):
    cursor.execute(y)


def entry_point_two_hops_away(user_id):
    q = f"SELECT * FROM users WHERE id = {user_id}"
    hop_a(q)


# ---- alias of a cross-function-seeded parameter, not just a locally-
# built dynamic string — the "via parameter" note must still apply ----

def run_query_alias_of_seeded_param(query):
    q = query  # aliasing a parameter that a caller seeds with taint
    cursor.execute(q)


def caller_for_alias_of_seeded_param(user_id):
    q = f"SELECT * FROM users WHERE id = {user_id}"
    run_query_alias_of_seeded_param(q)


# ---- calling something that ISN'T a locally-defined function (e.g. a
# builtin) with a dynamic argument must not error or do anything odd ----

def call_to_external_function_with_dynamic_arg(user_id):
    print(f"debug: {user_id}")
