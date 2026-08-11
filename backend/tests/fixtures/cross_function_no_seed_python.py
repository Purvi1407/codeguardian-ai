"""
Isolated edge case: call_taint has an entry, but it never resolves to
an actual seeded parameter (arity mismatch — calling a zero-param local
function with an argument it has no parameter to receive). Kept in its
own file so seed_params ends up completely empty for this file, since
cross_function_python.py has other functions that DO seed successfully
and would mask this branch.
"""


def zero_param_function():
    cursor.execute("SELECT 1")


def caller_passes_arg_to_zero_param_function(user_id):
    # Syntactically valid — arity mismatches only fail at runtime, not
    # at parse time — so this exercises the "no local function param
    # actually matches this call-taint entry" path in analyze_python_file.
    zero_param_function(f"unused {user_id}")
