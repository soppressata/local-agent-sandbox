"""
Tests for the sandboxctl query expression language: tokenizing, parsing,
field resolution, and filtering of the signed receipt store.
"""

import pytest

from local_agent_sandbox.query import (
    BinExpr,
    NotExpr,
    Predicate,
    QuerySyntaxError,
    filter_receipts,
    parse_query,
    resolve_field,
)
from local_agent_sandbox.receipt import (
    EnforcementSummary,
    NodeInfo,
    PolicyCheck,
    Receipt,
    SignedReceipt,
    generate_keypair,
    sign_receipt,
)


def _make_signed(receipt_id, image="echo hi", exit_code=0, hostname="node-a", **overrides):
    kwargs = dict(
        id=receipt_id,
        trustfile="digest",
        trustfile_name="profile",
        image=image,
        command=image,
        node=NodeInfo(
            id="local-" + hostname,
            hostname=hostname,
            platform="Linux",
            backend="local-agent-sandbox",
            cpu_cores=4,
            mem_mb=8000,
        ),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        duration_ms=100.0,
        exit_code=exit_code,
        blocked=False,
        enforcement=EnforcementSummary(
            checks=[
                PolicyCheck(name="resources", applied=True, ok=True, detail="ok"),
                PolicyCheck(name="network", applied=True, ok=True, detail="ok"),
            ],
            fully_enforced=True,
        ),
        stdout="",
        stderr="",
    )
    kwargs.update(overrides)
    receipt = Receipt(**kwargs)
    private_key, _ = generate_keypair()
    return sign_receipt(receipt, private_key)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parse_simple_equality():
    expr = parse_query("exit_code=0")
    assert expr == Predicate(field="exit_code", op="=", value=0)


def test_parse_quoted_string():
    expr = parse_query('image="echo hi"')
    assert expr == Predicate(field="image", op="=", value="echo hi")


def test_parse_boolean_literal():
    expr = parse_query("blocked=true")
    assert expr == Predicate(field="blocked", op="=", value=True)


def test_parse_comparison_operators():
    for op in (">", ">=", "<", "<=", "!="):
        expr = parse_query(f"duration_ms{op}100")
        assert expr == Predicate(field="duration_ms", op=op, value=100)


def test_parse_contains_operator():
    expr = parse_query('image contains "build"')
    assert expr == Predicate(field="image", op="contains", value="build")


def test_parse_and_or_precedence():
    expr = parse_query("exit_code=0 and blocked=false or image=x")
    assert isinstance(expr, BinExpr)
    assert expr.op == "or"
    assert isinstance(expr.left, BinExpr)
    assert expr.left.op == "and"


def test_parse_not_and_parentheses():
    expr = parse_query("not (exit_code=0 and fully_enforced=true)")
    assert isinstance(expr, NotExpr)
    assert isinstance(expr.child, BinExpr)


def test_parse_nested_field_path():
    expr = parse_query("node.hostname=node-a")
    assert expr.field == "node.hostname"


def test_parse_dotted_check_field():
    expr = parse_query("checks.resources.ok=true")
    assert expr.field == "checks.resources.ok"


# ---------------------------------------------------------------------------
# Syntax errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expr",
    [
        "",
        "   ",
        "exit_code",                      # missing operator
        "exit_code =",                    # missing value
        "= 5",                            # missing field
        "exit_code ~ 5",                  # unknown character
        "exit_code=0 and",                # trailing operator
        "(exit_code=0",                   # missing closing paren
        "exit_code=0 extra",              # trailing tokens
        "exit_code=>5",                   # value cannot be operator
    ],
)
def test_parse_rejects_malformed_expressions(expr):
    with pytest.raises(QuerySyntaxError):
        parse_query(expr)


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------


def test_resolve_field_top_level():
    data = {"exit_code": 0, "image": "echo"}
    assert resolve_field(data, "exit_code") == 0
    assert resolve_field(data, "image") == "echo"


def test_resolve_field_nested():
    data = {"node": {"hostname": "node-a"}}
    assert resolve_field(data, "node.hostname") == "node-a"
    assert resolve_field(data, "node.missing") is None


def test_resolve_field_fully_enforced():
    data = {"enforcement": {"fully_enforced": True}}
    assert resolve_field(data, "fully_enforced") is True


def test_resolve_field_check_attr():
    data = {
        "enforcement": {
            "checks": [{"name": "network", "applied": False, "ok": False}]
        }
    }
    assert resolve_field(data, "checks.network.ok") is False
    assert resolve_field(data, "checks.network.applied") is False
    assert resolve_field(data, "checks.missing.ok") is None


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_filter_by_exit_code():
    receipts = [
        _make_signed("ok", exit_code=0),
        _make_signed("bad", exit_code=1),
    ]
    matches = filter_receipts(receipts, parse_query("exit_code=0"))
    assert [r.receipt.id for r in matches] == ["ok"]


def test_filter_composes_boolean_expression():
    receipts = [
        _make_signed("a", exit_code=0, duration_ms=50),
        _make_signed("b", exit_code=0, duration_ms=500),
        _make_signed("c", exit_code=1, duration_ms=50),
    ]
    expr = parse_query("exit_code=0 and duration_ms>100")
    assert [r.receipt.id for r in filter_receipts(receipts, expr)] == ["b"]


def test_filter_nested_field_and_enforcement():
    receipts = [
        _make_signed("a", hostname="node-a"),
        _make_signed("b", hostname="node-b"),
    ]
    expr = parse_query("node.hostname=node-b and fully_enforced=true")
    assert [r.receipt.id for r in filter_receipts(receipts, expr)] == ["b"]


def test_filter_check_field():
    receipts = [
        _make_signed("a"),
        _make_signed("b", enforcement=EnforcementSummary(checks=[], fully_enforced=False)),
    ]
    expr = parse_query("checks.network.ok=true")
    assert [r.receipt.id for r in filter_receipts(receipts, expr)] == ["a"]


def test_filter_not_expression():
    receipts = [
        _make_signed("blocked", blocked=True),
        _make_signed("clean", blocked=False),
    ]
    expr = parse_query("not blocked=true")
    assert [r.receipt.id for r in filter_receipts(receipts, expr)] == ["clean"]
