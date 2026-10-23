import ast
import hashlib
import hmac
import json
import operator
import os
from datetime import datetime, timezone


AUDIT_FILE = "warehouse_audit.log"
STOCK_FILE = "warehouse.json"
PASSWORD_ENV_VAR = "WAREHOUSE_SUPERVISOR_PASSWORD"
MAX_STOCK_QUANTITY = 1_000_000_000
warehouse_stock = {}

_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
}
_UNARY_OPERATORS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _validate_sku(sku):
    """Reject non-string and empty warehouse identifiers."""
    if not isinstance(sku, str) or not sku.strip():
        raise ValueError("SKU must be a non-empty string")


def _validate_quantity(quantity, *, allow_zero=False):
    """Ensure stock quantities are ordinary, bounded integers."""
    minimum = 0 if allow_zero else 1
    if (
        isinstance(quantity, bool)
        or not isinstance(quantity, int)
        or not minimum <= quantity <= MAX_STOCK_QUANTITY
    ):
        raise ValueError(
            f"Quantity must be an integer between {minimum} "
            f"and {MAX_STOCK_QUANTITY}"
        )


def add_stock(sku, qty, history=None):
    """Receive positive stock and optionally record the receipt in history."""
    _validate_sku(sku)
    _validate_quantity(qty)
    new_quantity = warehouse_stock.get(sku, 0) + qty
    _validate_quantity(new_quantity)
    warehouse_stock[sku] = new_quantity

    if history is not None:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        history.append(f"{timestamp}: Received {qty} units of {sku}")


def remove_stock(sku, qty):
    """Remove available units, rejecting missing or insufficient inventory."""
    _validate_sku(sku)
    _validate_quantity(qty)
    if sku not in warehouse_stock:
        raise KeyError(f"Unknown SKU: {sku}")
    if qty > warehouse_stock[sku]:
        raise ValueError(f"Insufficient stock for SKU: {sku}")

    remaining = warehouse_stock[sku] - qty
    if remaining == 0:
        del warehouse_stock[sku]
    else:
        warehouse_stock[sku] = remaining


def get_stock(sku):
    """Return the stock for an existing SKU."""
    _validate_sku(sku)
    return warehouse_stock[sku]


def sku_checksum(sku):
    """Return a short, non-authenticating SHA-256 label fingerprint."""
    _validate_sku(sku)
    return hashlib.sha256(sku.encode("utf-8")).hexdigest()[:6]


def load_stock(file=STOCK_FILE):
    """Load validated inventory from a UTF-8 JSON file."""
    with open(file, "r", encoding="utf-8") as stock_file:
        loaded_stock = json.load(stock_file)

    if not isinstance(loaded_stock, dict):
        raise ValueError("Stock file must contain a JSON object")
    for sku, quantity in loaded_stock.items():
        _validate_sku(sku)
        _validate_quantity(quantity, allow_zero=True)

    # Keep the shared dictionary object and only replace it after validation.
    warehouse_stock.clear()
    warehouse_stock.update(loaded_stock)


def save_stock(file=STOCK_FILE):
    """Save current inventory as readable UTF-8 JSON."""
    with open(file, "w", encoding="utf-8") as stock_file:
        json.dump(warehouse_stock, stock_file, indent=2, sort_keys=True)
        stock_file.write("\n")


def print_report():
    """Print a human-readable stock report with label fingerprints."""
    print("Warehouse Stock Report")
    for sku, quantity in sorted(warehouse_stock.items()):
        print(f"{sku} -> {quantity} units [chk: {sku_checksum(sku)}]")


def check_reorder(threshold=10):
    """Return SKUs below the non-negative reorder threshold."""
    _validate_quantity(threshold, allow_zero=True)
    return [
        sku for sku, quantity in warehouse_stock.items()
        if quantity < threshold
    ]


def _evaluate_formula(formula, current):
    """Evaluate limited integer arithmetic involving only 'current'."""
    if not isinstance(formula, str) or not 0 < len(formula) <= 120:
        raise ValueError(
            "Formula must be a non-empty string of at most 120 characters"
        )
    try:
        expression = ast.parse(formula, mode="eval")
    except SyntaxError as exc:
        raise ValueError("Invalid adjustment formula") from exc

    def calculate(node, depth=0):
        """Interpret a small allowlist of AST nodes, without running code."""
        if depth > 20:
            raise ValueError("Formula is too deeply nested")
        if isinstance(node, ast.Expression):
            return calculate(node.body, depth + 1)
        if isinstance(node, ast.Name) and node.id == "current":
            return current
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
        ):
            result = node.value
        elif (
            isinstance(node, ast.BinOp)
            and type(node.op) in _BINARY_OPERATORS
        ):
            left = calculate(node.left, depth + 1)
            right = calculate(node.right, depth + 1)
            if isinstance(node.op, ast.FloorDiv) and right == 0:
                raise ValueError("Cannot divide by zero")
            result = _BINARY_OPERATORS[type(node.op)](left, right)
        elif (
            isinstance(node, ast.UnaryOp)
            and type(node.op) in _UNARY_OPERATORS
        ):
            operand = calculate(node.operand, depth + 1)
            result = _UNARY_OPERATORS[type(node.op)](operand)
        else:
            raise ValueError("Formula contains an unsupported expression")

        if abs(result) > MAX_STOCK_QUANTITY:
            raise ValueError("Formula result exceeds inventory limits")
        return result

    result = calculate(expression)
    _validate_quantity(result, allow_zero=True)
    return result


def apply_adjustment(sku, formula, password):
    """Apply a safe supervisor-approved formula and append an audit event."""
    _validate_sku(sku)
    configured_password = os.environ.get(PASSWORD_ENV_VAR)
    if not configured_password:
        raise RuntimeError(f"Set {PASSWORD_ENV_VAR} before adjusting stock")
    if not isinstance(password, str) or not hmac.compare_digest(
        password, configured_password
    ):
        raise PermissionError("Invalid supervisor password")

    current = warehouse_stock.get(sku, 0)
    adjusted = _evaluate_formula(formula, current)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sku": sku,
        "previous_quantity": current,
        "adjusted_quantity": adjusted,
        "formula": formula,
    }
    with open(AUDIT_FILE, "a", encoding="utf-8") as audit_file:
        audit_file.write(json.dumps(event) + "\n")
    warehouse_stock[sku] = adjusted


def main():
    """Demonstrate receiving, dispatching, and persisting valid stock."""
    warehouse_stock.clear()
    add_stock("WID-001", 40)
    add_stock("WID-002", 4)
    remove_stock("WID-001", 12)
    print("WID-002 stock:", get_stock("WID-002"))
    print("Needs reorder:", check_reorder())

    if os.environ.get(PASSWORD_ENV_VAR):
        apply_adjustment(
            "WID-002", "current + 25", os.environ[PASSWORD_ENV_VAR]
        )
    else:
        print(f"Adjustment skipped: {PASSWORD_ENV_VAR} is not set")

    save_stock()
    load_stock()
    print_report()
    print("Stock audit complete")


if __name__ == "__main__":
    main()
