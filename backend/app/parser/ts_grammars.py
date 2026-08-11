"""
Loads the tree-sitter grammars for JavaScript, TypeScript, and TSX, and
picks the right one by file extension. Centralized here so both the
parser (Module 2) and the analyzer (Module 3) share one source of truth
for "how do I get a parse tree for this file" instead of duplicating
grammar setup in two places.
"""
import tree_sitter
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

JS_LANGUAGE = tree_sitter.Language(tsjs.language())
TS_LANGUAGE = tree_sitter.Language(tsts.language_typescript())
TSX_LANGUAGE = tree_sitter.Language(tsts.language_tsx())

# Parsers are stateless-enough to reuse across files of the same
# extension — created once per language, not once per file.
_PARSERS = {
    "js": tree_sitter.Parser(JS_LANGUAGE),
    "jsx": tree_sitter.Parser(JS_LANGUAGE),
    "mjs": tree_sitter.Parser(JS_LANGUAGE),
    "cjs": tree_sitter.Parser(JS_LANGUAGE),
    "ts": tree_sitter.Parser(TS_LANGUAGE),
    "tsx": tree_sitter.Parser(TSX_LANGUAGE),
}


def parser_for_suffix(suffix: str) -> tree_sitter.Parser:
    """`suffix` is a file extension without the dot, e.g. 'ts', 'jsx'.
    Falls back to the plain JS grammar for anything unrecognized rather
    than raising — an unusual extension shouldn't crash the whole scan."""
    return _PARSERS.get(suffix.lower(), _PARSERS["js"])


def parse_source(source: bytes, suffix: str) -> tree_sitter.Tree:
    return parser_for_suffix(suffix).parse(source)
