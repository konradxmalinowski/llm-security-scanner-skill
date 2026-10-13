"""Static checks that encode CodeQL rules locally, so pytest catches them first.

CodeQL only runs after a push, and a maintainability alert then sits open until
someone notices. Reimplementing the rule here is cheap and makes the failure
immediate and self-explaining at the point the code is written.
"""

from __future__ import annotations

import ast
import pathlib

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"


def _line_starts(src: str) -> list[int]:
    offsets, pos = [0], 0
    for line in src.splitlines(keepends=True):
        pos += len(line)
        offsets.append(pos)
    return offsets


def _is_parenthesized(src: str, starts: list[int], node: ast.Constant) -> bool:
    """Mirror CodeQL's ``StringLiteral.isParenthesized()``.

    The ast node for a parenthesized literal begins at the first string, not at the
    ``(``, so the paren is found by scanning backwards past whitespace.
    """
    i = starts[node.lineno - 1] + node.col_offset - 1
    while i >= 0 and src[i] in " \t\r\n":
        i -= 1
    return i >= 0 and src[i] == "("


def test_no_unintentional_implicit_string_concatenation_in_a_list() -> None:
    """Reimplements CodeQL `py/implicit-string-concatenation-in-list`.

    Adjacent string literals are concatenated by the interpreter, so inside a list a
    missing comma silently merges two elements into one. The query fires on a
    multi-part literal that sits in a list alongside at least one other string and is
    not wrapped in parentheses; wrapping it is what makes the intent explicit.

    Conditions copied from the query:
      - the literal is an element of a `List`
      - that list holds at least one OTHER string element
      - the literal has an implicitly concatenated part
      - the literal is not parenthesized
    """
    findings: list[str] = []

    for path in sorted(SRC.rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        starts = _line_starts(src)
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.List):
                continue
            strings = [
                e for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
            ]
            if len(strings) < 2:
                continue
            for elt in strings:
                if elt.lineno == elt.end_lineno:
                    continue  # a single-line literal cannot be a wrapped concatenation
                segment = ast.get_source_segment(src, elt) or ""
                if segment.lstrip().startswith(('"""', "'''")):
                    continue  # a triple-quoted string legitimately spans lines
                if not _is_parenthesized(src, starts, elt):
                    findings.append(f"{path.name}:{elt.lineno}")

    assert not findings, (
        "Implicit string concatenation in a list. Wrap each wrapped literal in "
        "parentheses to make the intent explicit, or add the missing comma:\n  "
        + "\n  ".join(findings)
    )
