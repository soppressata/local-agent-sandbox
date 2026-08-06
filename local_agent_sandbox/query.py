"""
Receipt query filtering.

``sandboxctl query '<expr>'`` filters the JSONL receipt store with a small
boolean expression language:

    expr     := or_expr
    or_expr  := and_expr ( "or" and_expr )*
    and_expr := not_expr ( "and" not_expr )*
    not_expr := "not" not_expr | "(" or_expr ")" | predicate
    predicate:= field op value
    op       := "=" | "!=" | ">" | ">=" | "<" | "<=" | "contains"

Fields resolve against a receipt document, including nested paths such as
``node.hostname`` and enforcement checks such as ``checks.resources.ok``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Union

from .receipt import SignedReceipt

_QUERY_RE = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<op><=|>=|!=|=|<|>)
  | (?P<qstr>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<word>[A-Za-z_][A-Za-z0-9_.-]*)
  | (?P<num>[0-9]+(?:\.[0-9]+)?)
  | (?P<bad>.)
    """,
    re.VERBOSE,
)

_OPERATORS = {"=", "!=", ">", ">=", "<", "<=", "contains"}


class QuerySyntaxError(ValueError):
    """Raised when a query expression cannot be parsed."""


@dataclass(frozen=True)
class _Token:
    """A single lexical token of a query expression."""

    kind: str
    value: Any


def _tokenize(text: str) -> List[_Token]:
    """Tokenize a query expression into a flat token list."""
    tokens: List[_Token] = []
    position = 0
    for match in _QUERY_RE.finditer(text):
        if match.start() != position:
            raise QuerySyntaxError(
                f"unexpected characters at offset {position}: {text[position:match.start()]!r}"
            )
        position = match.end()
        kind = match.lastgroup
        value = match.group()
        if kind == "space":
            continue
        if kind == "bad":
            raise QuerySyntaxError(f"unexpected character {value!r}")
        if kind == "qstr":
            tokens.append(_Token("str", _unescape(value[1:-1])))
        elif kind == "word":
            lower = value.lower()
            if lower in ("and", "or", "not", "contains"):
                tokens.append(_Token("kw", lower))
            else:
                tokens.append(_Token("word", value))
        else:
            tokens.append(_Token(kind, value))
    if position != len(text):
        raise QuerySyntaxError(
            f"unexpected characters at offset {position}: {text[position:]!r}"
        )
    return tokens


def _unescape(value: str) -> str:
    """Unescape quote characters inside a quoted string value."""
    return value.replace(r"\'", "'").replace(r"\"", '"')


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


class Expr:
    """Base class for a parsed query expression."""

    def evaluate(self, data: Dict[str, Any]) -> bool:
        """Evaluate the expression against a receipt document dict."""
        raise NotImplementedError


@dataclass
class Predicate(Expr):
    """``field op value`` leaf expression."""

    field: str
    op: str
    value: Any

    def evaluate(self, data: Dict[str, Any]) -> bool:
        return _compare(resolve_field(data, self.field), self.op, self.value)


@dataclass
class NotExpr(Expr):
    """Logical negation of a child expression."""

    child: Expr

    def evaluate(self, data: Dict[str, Any]) -> bool:
        return not self.child.evaluate(data)


@dataclass
class BinExpr(Expr):
    """Binary ``and`` / ``or`` combination of two expressions."""

    op: str
    left: Expr
    right: Expr

    def evaluate(self, data: Dict[str, Any]) -> bool:
        left = self.left.evaluate(data)
        right = self.right.evaluate(data)
        return left and right if self.op == "and" else left or right


# ---------------------------------------------------------------------------
# Field resolution + comparison
# ---------------------------------------------------------------------------


def resolve_field(data: Dict[str, Any], field: str) -> Any:
    """Resolve a (possibly dotted) field path against a receipt dict.

    ``fully_enforced`` maps to the enforcement summary and ``checks.<name>``
    maps to the named policy check's ``ok`` / ``applied`` attributes.
    """
    parts = field.split(".")
    if parts[0] == "fully_enforced":
        return data.get("enforcement", {}).get("fully_enforced")
    if parts[0] == "checks":
        if len(parts) < 2:
            return None
        for check in data.get("enforcement", {}).get("checks", []):
            if check.get("name") == parts[1]:
                if len(parts) == 2:
                    return check
                return check.get(parts[2])
        return None
    node: Any = data
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return None
    return node


def _coerce_number(value: Any) -> Optional[float]:
    """Coerce a value to a float for numeric comparison, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _compare(actual: Any, op: str, expected: Any) -> bool:
    """Apply an operator between a resolved field value and a literal."""
    if op == "contains":
        return isinstance(actual, str) and isinstance(expected, str) and expected in actual
    if op in ("=", "!="):
        equal = actual == expected
        if not equal and isinstance(actual, str) and isinstance(expected, str):
            equal = actual.lower() == expected.lower()
        return equal if op == "=" else not equal
    left = _coerce_number(actual)
    right = _coerce_number(expected)
    if left is None or right is None:
        return False
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    return False


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class _Parser:
    """Recursive-descent parser for the query expression grammar."""

    def __init__(self, tokens: List[_Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    def peek(self) -> Optional[_Token]:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def next(self) -> Optional[_Token]:
        token = self.peek()
        if token is not None:
            self._pos += 1
        return token

    def parse(self) -> Expr:
        expr = self.parse_or()
        if self.peek() is not None:
            raise QuerySyntaxError(f"unexpected token {self.peek().value!r}")
        return expr

    def parse_or(self) -> Expr:
        left = self.parse_and()
        while self.peek() is not None and (
            self.peek().kind == "kw" and self.peek().value == "or"
        ):
            self.next()
            left = BinExpr("or", left, self.parse_and())
        return left

    def parse_and(self) -> Expr:
        left = self.parse_not()
        while self.peek() is not None and (
            self.peek().kind == "kw" and self.peek().value == "and"
        ):
            self.next()
            left = BinExpr("and", left, self.parse_not())
        return left

    def parse_not(self) -> Expr:
        if self.peek() is not None and (
            self.peek().kind == "kw" and self.peek().value == "not"
        ):
            self.next()
            return NotExpr(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Expr:
        token = self.next()
        if token is None:
            raise QuerySyntaxError("unexpected end of expression")
        if token.kind == "lparen":
            expr = self.parse_or()
            closing = self.next()
            if closing is None or closing.kind != "rparen":
                raise QuerySyntaxError("missing closing parenthesis")
            return expr
        if token.kind != "word":
            raise QuerySyntaxError(f"expected a field name, got {token.value!r}")

        field = token.value
        op_token = self.next()
        if op_token is None:
            raise QuerySyntaxError(f"missing operator after {field!r}")
        if op_token.kind == "kw" and op_token.value == "contains":
            op = "contains"
        elif op_token.kind == "op" and op_token.value in _OPERATORS:
            op = op_token.value
        else:
            raise QuerySyntaxError(
                f"expected an operator after {field!r}, got {op_token.value!r}"
            )

        value_token = self.next()
        if value_token is None:
            raise QuerySyntaxError(f"missing value after operator {op!r}")
        return Predicate(field, op, self._coerce_value(value_token))

    def _coerce_value(self, token: _Token) -> Any:
        if token.kind == "num":
            return int(token.value) if token.value.isdigit() else float(token.value)
        if token.kind == "str":
            return token.value
        if token.kind == "word":
            lower = token.value.lower()
            if lower == "true":
                return True
            if lower == "false":
                return False
            if lower == "null":
                return None
            return token.value
        raise QuerySyntaxError(f"invalid literal value {token.value!r}")


def parse_query(text: str) -> Expr:
    """Parse a query expression into an :class:`Expr` tree.

    Raises :class:`QuerySyntaxError` for malformed expressions.
    """
    if not isinstance(text, str) or not text.strip():
        raise QuerySyntaxError("empty query expression")
    return _Parser(_tokenize(text)).parse()


def filter_receipts(
    receipts: Iterable[SignedReceipt], expr: Expr
) -> List[SignedReceipt]:
    """Return the signed receipts that satisfy ``expr``."""
    return [
        receipt
        for receipt in receipts
        if expr.evaluate(receipt.receipt.model_dump(mode="json"))
    ]
