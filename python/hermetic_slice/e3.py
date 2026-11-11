"""E3 corpus and accuracy harness for hermetic sealcheck."""

from __future__ import annotations

import argparse
import difflib
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import py_compile
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any
import zipfile

from hermetic_slice.dockerutil import run_docker
from hermetic_slice.gitutil import run_git

TOOL_VERSION = "0.1.0"
# Detectors scored per case. D0 is excluded: it reads the task's problem statement, not the
# case root, so it would score every case of a task the same way. It's reported per task.
SCORED_DETECTORS = ("D2", "D3b")
Z_95 = 1.959963984540054  # 95% Wilson score z-value


def wilson_interval(k: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Calculate the Wilson 95% score interval for a binomial proportion.

    Args:
        k: Number of successes.
        n: Total number of trials.
        z: Z-score (defaults to 1.95996... for 95% confidence).

    Returns:
        (lower_bound, upper_bound) clamped to [0.0, 1.0].
    """
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1.0 + (z**2) / n
    center = (p + (z**2) / (2.0 * n)) / denom
    variance_term = (p * (1.0 - p)) / n + (z**2) / (4.0 * (n**2))
    margin = (z * math.sqrt(max(0.0, variance_term))) / denom
    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return (lower, upper)


def parse_patch_touched_files(patch_text: str) -> list[str]:
    """Parse unified / git diff and return list of touched repository relative paths."""
    files: set[str] = set()
    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                a_path = parts[2]
                b_path = parts[3]
                if a_path.startswith("a/"):
                    a_path = a_path[2:]
                if b_path.startswith("b/"):
                    b_path = b_path[2:]
                if a_path and a_path != "/dev/null":
                    files.add(a_path)
                if b_path and b_path != "/dev/null":
                    files.add(b_path)
        elif line.startswith("--- "):
            path = line[4:].strip()
            if path.startswith("a/"):
                path = path[2:]
            if path and path != "/dev/null":
                files.add(path)
        elif line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path and path != "/dev/null":
                files.add(path)
    return sorted(files)


def parse_patch_hunks(patch_text: str) -> dict[str, list[tuple[int, int, int, int]]]:
    """Parse diff and return mapping from file path to list of hunks (old_start, old_count, new_start, new_count)."""
    hunks_by_file: dict[str, list[tuple[int, int, int, int]]] = {}
    current_file: str | None = None
    hunk_re = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                b_path = parts[3]
                if b_path.startswith("b/"):
                    b_path = b_path[2:]
                current_file = b_path
        elif line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path and path != "/dev/null":
                current_file = path
        elif line.startswith("@@ ") and current_file:
            m = hunk_re.match(line)
            if m:
                old_start = int(m.group(1))
                old_count = int(m.group(2)) if m.group(2) is not None else 1
                new_start = int(m.group(3))
                new_count = int(m.group(4)) if m.group(4) is not None else 1
                hunks_by_file.setdefault(current_file, []).append((old_start, old_count, new_start, new_count))

    return hunks_by_file


def apply_patch_in_temp_dir(base_tree_dir: Path, patch_text: str, touched_files: list[str]) -> dict[str, str]:
    """Apply patch to copies of only the touched base files in a non-repo temp dir.

    Returns dict mapping rel_path -> post_fix_file_text.
    """
    with tempfile.TemporaryDirectory() as td:
        temp_path = Path(td)
        for rel in touched_files:
            src = base_tree_dir / rel
            if src.exists():
                dst = temp_path / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

        # Apply patch with git apply
        patch_file = temp_path / "patch.diff"
        patch_file.write_text(patch_text, encoding="utf-8", newline="")
        run_git(["apply", str(patch_file)], cwd=temp_path)

        post_fix_contents: dict[str, str] = {}
        for rel in touched_files:
            dst = temp_path / rel
            if dst.exists():
                post_fix_contents[rel] = dst.read_text(encoding="utf-8", errors="replace")

        return post_fix_contents


def compute_dir_files_sha256(root_dir: Path) -> str:
    """Compute sha256 digest of sorted relative file contents under root_dir."""
    files: list[str] = []
    for p in root_dir.rglob("*"):
        if p.is_file():
            files.append(p.relative_to(root_dir).as_posix())
    files.sort()

    h = hashlib.sha256()
    for rel in files:
        h.update(rel.encode("utf-8") + b"\n")
        h.update((root_dir / rel).read_bytes())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Synthetic Task Generator
# ---------------------------------------------------------------------------

SYNTHETIC_MODULE_LINES = [
    '"""Core billing and usage calculation service module."""',
    "",
    "from __future__ import annotations",
    "",
    "from dataclasses import dataclass, field",
    "from datetime import datetime, timezone",
    "from enum import Enum",
    "import logging",
    "import math",
    "import re",
    "from typing import Any, Callable, Sequence",
    "",
    'logger = logging.getLogger("billing_service")',
    "",
    "",
    "class CustomerTier(Enum):",
    '    FREE = "free"',
    '    STARTER = "starter"',
    '    PRO = "pro"',
    '    ENTERPRISE = "enterprise"',
    "",
    "",
    "class InvoiceStatus(Enum):",
    '    DRAFT = "draft"',
    '    PENDING = "pending"',
    '    PAID = "paid"',
    '    VOID = "void"',
    "",
    "",
    "@dataclass",
    "class TierRate:",
    "    tier: CustomerTier",
    "    base_rate: float",
    "    included_credits: int",
    "    overage_rate: float",
    "    discount_threshold: int = 1000",
    "    discount_rate: float = 0.05",
    "    max_retries: int = 3",
    "    timeout_seconds: int = 30",
    "",
    "",
    "@dataclass",
    "class UsageRecord:",
    "    customer_id: str",
    "    tier: CustomerTier",
    "    compute_hours: float",
    "    storage_gb_hours: float",
    "    network_egress_gb: float",
    "    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))",
    "",
    "",
    "@dataclass",
    "class InvoiceItem:",
    "    description: str",
    "    quantity: float",
    "    unit_price: float",
    "    total_price: float",
    "",
    "",
    "@dataclass",
    "class Invoice:",
    "    invoice_id: str",
    "    customer_id: str",
    "    items: list[InvoiceItem] = field(default_factory=list)",
    "    status: InvoiceStatus = InvoiceStatus.DRAFT",
    "    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))",
    "",
    "    @property",
    "    def subtotal(self) -> float:",
    "        return sum(item.total_price for item in self.items)",
    "",
    "    @property",
    "    def total(self) -> float:",
    "        return round(self.subtotal, 2)",
    "",
    "",
    "TIER_CATALOG: dict[CustomerTier, TierRate] = {",
    "    CustomerTier.FREE: TierRate(CustomerTier.FREE, 0.0, 100, 0.10),",
    "    CustomerTier.STARTER: TierRate(CustomerTier.STARTER, 29.0, 500, 0.08),",
    "    CustomerTier.PRO: TierRate(CustomerTier.PRO, 99.0, 2000, 0.05),",
    "    CustomerTier.ENTERPRISE: TierRate(CustomerTier.ENTERPRISE, 499.0, 10000, 0.03),",
    "}",
    "",
    "",
    "def validate_customer_id(customer_id: str) -> bool:",
    '    """Validate customer identifier string."""',
    '    pattern = r"^[a-zA-Z0-9_-]{3,32}$"',
    "    return bool(re.match(pattern, customer_id))",
    "",
    "",
    "def calculate_compute_charge(hours: float, tier_rate: TierRate) -> float:",
    '    """Calculate charge for compute hours with threshold discounting."""',
    "    if hours <= 0.0:",
    "        return 0.0",
    "    effective_hours = max(0.0, hours - tier_rate.included_credits)",
    "    raw_charge = effective_hours * tier_rate.overage_rate",
    "    if effective_hours >= tier_rate.discount_threshold:",
    "        discount = raw_charge * tier_rate.discount_rate",
    "        raw_charge -= discount",
    "    return max(0.0, round(raw_charge, 4))",
    "",
    "",
    "def calculate_storage_charge(gb_hours: float, tier_rate: TierRate) -> float:",
    '    """Calculate monthly storage cost from GB-hours."""',
    "    if gb_hours <= 0.0:",
    "        return 0.0",
    "    gb_months = gb_hours / 720.0",
    "    rate_per_gb_month = tier_rate.overage_rate * 0.5",
    "    return round(gb_months * rate_per_gb_month, 4)",
    "",
    "",
    "def calculate_network_charge(egress_gb: float, tier: CustomerTier) -> float:",
    '    """Calculate egress network charges based on bandwidth tiers."""',
    "    if egress_gb <= 0.0:",
    "        return 0.0",
    "    if tier in (CustomerTier.PRO, CustomerTier.ENTERPRISE):",
    "        price_per_gb = 0.04",
    "    else:",
    "        price_per_gb = 0.08",
    "    return round(egress_gb * price_per_gb, 4)",
    "",
    "",
    "def generate_invoice(customer_id: str, records: Sequence[UsageRecord]) -> Invoice:",
    '    """Generate customer invoice aggregating usage records."""',
    "    if not validate_customer_id(customer_id):",
    '        raise ValueError(f"Invalid customer ID format: {customer_id}")',
    "",
    "    cust_records = [r for r in records if r.customer_id == customer_id]",
    "    if not cust_records:",
    "        tier = CustomerTier.FREE",
    "    else:",
    "        tier = cust_records[0].tier",
    "    rate = TIER_CATALOG[tier]",
    "",
    '    invoice = Invoice(invoice_id=f"inv_{customer_id}_{int(time.time())}", customer_id=customer_id)',
    "    if rate.base_rate > 0:",
    '        invoice.items.append(InvoiceItem("Base Subscription Fee", 1, rate.base_rate, rate.base_rate))',
    "",
    "    total_compute = sum(r.compute_hours for r in cust_records)",
    "    compute_cost = calculate_compute_charge(total_compute, rate)",
    "    if compute_cost > 0:",
    "        invoice.items.append(",
    '            InvoiceItem("Compute Resources Usage", total_compute, rate.overage_rate, compute_cost)',
    "        )",
    "",
    "    total_storage = sum(r.storage_gb_hours for r in cust_records)",
    "    storage_cost = calculate_storage_charge(total_storage, rate)",
    "    if storage_cost > 0:",
    "        invoice.items.append(",
    '            InvoiceItem("Persistent Storage Usage", total_storage, rate.overage_rate * 0.5, storage_cost)',
    "        )",
    "",
    "    total_egress = sum(r.network_egress_gb for r in cust_records)",
    "    network_cost = calculate_network_charge(total_egress, tier)",
    "    if network_cost > 0:",
    '        unit_rate = 0.04 if tier in (CustomerTier.PRO, CustomerTier.ENTERPRISE) else 0.08',
    '        invoice.items.append(InvoiceItem("Network Egress Traffic", total_egress, unit_rate, network_cost))',
    "",
    "    return invoice",
    "",
    "",
    "def summarize_tier_metrics(invoices: Sequence[Invoice]) -> dict[str, float]:",
    '    """Calculate summary metrics across a collection of customer invoices."""',
    '    summary: dict[str, float] = {"count": float(len(invoices)), "gross_revenue": 0.0, "average_invoice": 0.0}',
    "    if not invoices:",
    "        return summary",
    "    gross = sum(inv.total for inv in invoices)",
    '    summary["gross_revenue"] = round(gross, 2)',
    '    summary["average_invoice"] = round(gross / len(invoices), 2)',
    "    return summary",
    "",
    "",
    "def apply_promotional_credit(invoice: Invoice, credit_amount: float) -> None:",
    '    """Apply promotional credit discount line item to pending invoice."""',
    "    if credit_amount <= 0.0:",
    "        return",
    "    actual_credit = min(invoice.subtotal, credit_amount)",
    "    invoice.items.append(",
    '        InvoiceItem("Promotional Service Credit", 1, -actual_credit, -actual_credit)',
    "    )",
    "",
    "",
    "def format_invoice_ascii_report(invoice: Invoice) -> str:",
    '    """Format invoice into printable plain-text ASCII report."""',
    '    lines = ["=" * 60, f"INVOICE REPORT: {invoice.invoice_id}", f"Customer ID:    {invoice.customer_id}"]',
    '    lines.append(f"Status:         {invoice.status.value.upper()}")',
    '    lines.append("-" * 60)',
    '    lines.append(f"{\'Description\':<32} {\'Qty\':>8} {\'Rate\':>8} {\'Total\':>8}")',
    '    lines.append("-" * 60)',
    "    for itm in invoice.items:",
    '        lines.append(f"{itm.description[:32]:<32} {itm.quantity:>8.1f} {itm.unit_price:>8.2f} {itm.total_price:>8.2f}")',
    '    lines.append("=" * 60)',
    '    lines.append(f"{\'TOTAL DUE:\':<48} {invoice.total:>8.2f}")',
    '    lines.append("=" * 60)',
    '    return "\\n".join(lines)',
    "",
    "",
    "def estimate_future_growth(current_revenue: float, monthly_growth_rate: float, months: int) -> list[float]:",
    '    """Project future monthly revenue given current base and compound rate."""',
    "    projections: list[float] = []",
    "    current = current_revenue",
    "    for _ in range(months):",
    "        current *= 1.0 + monthly_growth_rate",
    "        projections.append(round(current, 2))",
    "    return projections",
    "",
    "",
    "def batch_process_records(records: Sequence[UsageRecord]) -> dict[str, list[UsageRecord]]:",
    '    """Group usage records by customer identifier."""',
    "    grouped: dict[str, list[UsageRecord]] = {}",
    "    for r in records:",
    "        grouped.setdefault(r.customer_id, []).append(r)",
    "    return grouped",
    "",
    "",
    "def calculate_median_usage(values: Sequence[float]) -> float:",
    '    """Compute median value for statistical analysis."""',
    "    if not values:",
    "        return 0.0",
    "    s = sorted(values)",
    "    n = len(s)",
    "    mid = n // 2",
    "    if n % 2 == 1:",
    "        return float(s[mid])",
    "    return (s[mid - 1] + s[mid]) / 2.0",
    "",
    "",
    "def audit_ledger_consistency(invoices: Sequence[Invoice], expected_total: float) -> bool:",
    '    """Verify ledger sum matches expected control total."""',
    "    computed_sum = sum(inv.total for inv in invoices)",
    "    diff = abs(computed_sum - expected_total)",
    "    return diff < 0.01",
    "",
    "",
    "def reconcile_accounts(records: list[dict[str, Any]]) -> dict[str, Any]:",
    '    """Reconcile raw account balance ledger records."""',
    '    balance = 0.0',
    '    processed_count = 0',
    "    for rec in records:",
    '        amount = float(rec.get("amount", 0.0))',
    "        balance += amount",
    "        processed_count += 1",
    '    return {"reconciled_balance": round(balance, 2), "records_processed": processed_count}',
    "",
    "",
    "def compute_percentiles(data: list[float], percentiles: list[float]) -> dict[float, float]:",
    '    """Calculate custom percentiles over numeric distribution."""',
    "    if not data:",
    "        return {p: 0.0 for p in percentiles}",
    "    sorted_data = sorted(data)",
    "    results: dict[float, float] = {}",
    "    for p in percentiles:",
    "        k = (len(sorted_data) - 1) * (p / 100.0)",
    "        f_idx = math.floor(k)",
    "        c_idx = math.ceil(k)",
    "        if f_idx == c_idx:",
    "            results[p] = sorted_data[int(k)]",
    "        else:",
    "            d0 = sorted_data[int(f_idx)] * (c_idx - k)",
    "            d1 = sorted_data[int(c_idx)] * (k - f_idx)",
    "            results[p] = d0 + d1",
    "    return results",
    "",
    "",
    "def sanitize_tag_key(tag: str) -> str:",
    '    """Normalize user metadata tag keys."""',
    '    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "_", tag.strip())',
    "    return cleaned.lower()",
    "",
    "",
    "def serialize_invoice_payload(invoice: Invoice) -> dict[str, Any]:",
    '    """Serialize invoice dataclass into JSON-compatible payload."""',
    "    return {",
    '        "invoice_id": invoice.invoice_id,',
    '        "customer_id": invoice.customer_id,',
    '        "status": invoice.status.value,',
    '        "total": invoice.total,',
    '        "created_at": invoice.created_at.isoformat(),',
    '        "item_count": len(invoice.items),',
    "    }",
    "",
    "",
    "def verify_checksum(payload: bytes, expected_sha256: str) -> bool:",
    '    """Verify raw byte content against expected SHA256 checksum."""',
    "    digest = hashlib.sha256(payload).hexdigest()",
    "    return digest == expected_sha256.lower()",
    "",
    "",
    "def filter_outliers(samples: list[float], std_threshold: float = 3.0) -> list[float]:",
    '    """Filter statistical outliers exceeding standard deviation bound."""',
    "    if len(samples) < 2:",
    "        return list(samples)",
    "    mean_val = sum(samples) / len(samples)",
    "    var_val = sum((x - mean_val) ** 2 for x in samples) / (len(samples) - 1)",
    "    std_val = math.sqrt(var_val)",
    "    if std_val == 0.0:",
    "        return list(samples)",
    "    return [x for x in samples if abs(x - mean_val) <= std_threshold * std_val]",
    "",
    "",
    "def format_currency_usd(amount: float) -> str:",
    '    """Format numeric quantity into USD currency string."""',
    '    return f"${amount:,.2f}"',
    "",
    "",
    "def compute_exponential_backoff(attempt: int, base_delay: float = 1.0, max_delay: float = 60.0) -> float:",
    '    """Calculate exponential backoff sleep delay with cap."""',
    "    delay = base_delay * (2.0 ** attempt)",
    "    return min(delay, max_delay)",
    "",
    "",
    "def parse_iso_timestamp(ts_string: str) -> datetime:",
    '    """Parse ISO8601 formatted datetime string safely."""',
    "    return datetime.fromisoformat(ts_string.replace('Z', '+00:00'))",
    "",
    "",
    "def generate_batch_id(prefix: str = 'batch') -> str:",
    '    """Generate deterministic batch sequence identifier."""',
    '    return f"{prefix}_{int(time.time())}"',
    "",
    "",
    "def build_diagnostic_health_report() -> dict[str, Any]:",
    '    """Construct health check telemetry dictionary."""',
    "    return {",
    '        "status": "healthy",',
    '        "timestamp": datetime.now(timezone.utc).isoformat(),',
    '        "version": "1.0.0",',
    '        "tier_count": len(TIER_CATALOG),',
    "    }",
    "",
]


def _build_synthetic_patch(
    base_lines: list[str],
    line_index: int,
    kind: str,
    new_char: str = "",
) -> tuple[str, str]:
    """Generate patch and post-fix content.

    kind == "deletion": removes exactly base_lines[line_index].
    kind == "one_char": replaces 1 character in base_lines[line_index].
    Returns (patch_diff, post_fix_file_text).
    """
    post_lines = list(base_lines)
    old_line = base_lines[line_index]

    if kind == "deletion":
        del post_lines[line_index]
    elif kind == "one_char":
        # Modify exactly 1 character
        # We replace the targeted character
        old_char = old_line[new_char[0]] if isinstance(new_char, tuple) else None
        # target specified as (col_index, new_char)
        col_idx, replacement = new_char  # type: ignore[misc]
        modified_line = old_line[:col_idx] + replacement + old_line[col_idx + 1 :]
        post_lines[line_index] = modified_line

    base_text_lines = [l + "\n" for l in base_lines]
    post_text_lines = [l + "\n" for l in post_lines]

    diff_lines = list(
        difflib.unified_diff(
            base_text_lines,
            post_text_lines,
            fromfile="a/service.py",
            tofile="b/service.py",
            n=3,
        )
    )
    patch_text = f"diff --git a/service.py b/service.py\n{''.join(diff_lines)}"
    return patch_text, "".join(post_text_lines)


def generate_synthetic_tasks(synthetic_dir: Path) -> list[str]:
    """Generate 3 deletion-only and 3 one-character tasks under synthetic_dir.

    Returns list of generated task IDs.
    """
    synthetic_dir.mkdir(parents=True, exist_ok=True)
    base_lines = list(SYNTHETIC_MODULE_LINES)

    # Find line indices for synthetic tasks
    # Deletions:
    # 1. line: "    pattern = r"^[a-zA-Z0-9_-]{3,32}$"" -> redundant assignment
    del_idx_1 = base_lines.index('    pattern = r"^[a-zA-Z0-9_-]{3,32}$"')
    # 2. line: "        current *= 1.0 + monthly_growth_rate" or "    projections: list[float] = []"
    del_idx_2 = base_lines.index("    projections: list[float] = []")
    # 3. line: "    summary: dict[str, float] = {"count": float(len(invoices)), "gross_revenue": 0.0, "average_invoice": 0.0}"
    del_idx_3 = base_lines.index('    summary: dict[str, float] = {"count": float(len(invoices)), "gross_revenue": 0.0, "average_invoice": 0.0}')

    # One-character modifications:
    # 4. line: "    discount_rate: float = 0.05" -> change '5' to '6'
    char_idx_1 = base_lines.index("    discount_rate: float = 0.05")
    # col of '5' in "    discount_rate: float = 0.05"
    col_1 = base_lines[char_idx_1].rindex("5")

    # 5. line: "    max_retries: int = 3" -> change '3' to '5'
    char_idx_2 = base_lines.index("    max_retries: int = 3")
    col_2 = base_lines[char_idx_2].rindex("3")

    # 6. line: "    timeout_seconds: int = 30" -> change '3' to '6' (30 -> 60)
    char_idx_3 = base_lines.index("    timeout_seconds: int = 30")
    col_3 = base_lines[char_idx_3].rindex("30")

    task_specs = [
        ("synth_del_1", "deletion", del_idx_1, ""),
        ("synth_del_2", "deletion", del_idx_2, ""),
        ("synth_del_3", "deletion", del_idx_3, ""),
        ("synth_char_1", "one_char", char_idx_1, (col_1, "6")),
        ("synth_char_2", "one_char", char_idx_2, (col_2, "5")),
        ("synth_char_3", "one_char", char_idx_3, (col_3, "6")),
    ]

    created_ids: list[str] = []

    for task_id, kind, idx, param in task_specs:
        created_ids.append(task_id)
        task_dir = synthetic_dir / task_id
        base_tree_dir = task_dir / "base_tree"
        staging_dir = task_dir / "staging"
        agent_dir = task_dir / "agent"

        base_tree_dir.mkdir(parents=True, exist_ok=True)
        staging_dir.mkdir(parents=True, exist_ok=True)
        agent_dir.mkdir(parents=True, exist_ok=True)

        # Write base tree
        (base_tree_dir / "service.py").write_text("\n".join(base_lines) + "\n", encoding="utf-8", newline="")

        # Generate gold patch
        patch_diff, post_fix_text = _build_synthetic_patch(base_lines, idx, kind, param)
        (staging_dir / "gold.patch").write_text(patch_diff, encoding="utf-8", newline="")
        (staging_dir / "test.patch").write_text("", encoding="utf-8", newline="")
        (staging_dir / "hints.txt").write_text("", encoding="utf-8", newline="")

        # Agent problem statement
        (agent_dir / "problem_statement.md").write_text(
            f"Fix issue in billing service for synthetic task {task_id}.\n",
            encoding="utf-8",
        )

        task_json = {
            "instance_id": task_id,
            "base_commit": "synthetic_base",
            "repo": "hermetic/synthetic",
            "cutoffs": {
                "t_world": "2026-01-01T00:00:00Z",
                "t_clock": "2026-01-01T00:00:00Z",
                "discarded": [],
            },
            "kind": kind,
        }
        (task_dir / "task.json").write_text(json.dumps(task_json, indent=2) + "\n", encoding="utf-8")

    return created_ids


# ---------------------------------------------------------------------------
# Variant Builder Logic
# ---------------------------------------------------------------------------

FILLER_PROSE_1 = (
    "In this design note we analyze the core performance characteristics and memory overhead "
    "of the proposed changes. Prior architectural iterations revealed minor boundary conditions "
    "during high concurrency validation under simulated production workload conditions."
)

FILLER_PROSE_2 = (
    "Subsequent regression verification established that backward compatibility is preserved "
    "across all supported runtime environments. Additional telemetry monitors will be introduced "
    "in the forthcoming release to confirm steady-state memory utilization."
)


def _reformat_lines(lines: list[str]) -> list[str]:
    """Strip comments (#.*$), strip indentation, drop blank lines."""
    reformatted: list[str] = []
    for line in lines:
        cleaned = re.sub(r"#.*$", "", line).strip()
        if cleaned:
            reformatted.append(cleaned)
    return reformatted


def _build_variant_p02(
    gold_patch: str,
    post_fix_contents: dict[str, str],
) -> dict[str, str]:
    """Generate p02_reformatted file contents.

    Each changed hunk's region of the post-fix file, 10 lines either side,
    with comments removed, blank lines dropped and indentation stripped.
    """
    hunks_by_file = parse_patch_hunks(gold_patch)
    results: dict[str, str] = {}

    for rel_path, post_text in post_fix_contents.items():
        hunks = hunks_by_file.get(rel_path, [])
        post_lines = post_text.splitlines()
        reformatted_file_lines: list[str] = []

        if not hunks:
            # If no parsed hunk header, reformat whole file
            reformatted_file_lines = _reformat_lines(post_lines)
        else:
            for _, _, new_start, new_count in hunks:
                # Region: 10 lines either side
                start_line = max(1, new_start - 10)
                end_line = min(len(post_lines), new_start + max(1, new_count) - 1 + 10)
                hunk_region = post_lines[start_line - 1 : end_line]
                reformatted_file_lines.extend(_reformat_lines(hunk_region))

        results[rel_path] = "\n".join(reformatted_file_lines) + "\n"

    return results


def _build_variant_p04(
    base_tree_dir: Path,
    post_fix_contents: dict[str, str],
) -> str:
    """Generate p04_regenerated_diff: diff from difflib.unified_diff with n=1 and no index lines."""
    diff_output: list[str] = []
    for rel_path in sorted(post_fix_contents.keys()):
        base_file = base_tree_dir / rel_path
        if base_file.exists():
            base_lines = base_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        else:
            base_lines = []

        post_lines = post_fix_contents[rel_path].splitlines(keepends=True)
        udiff = list(
            difflib.unified_diff(
                base_lines,
                post_lines,
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                n=1,
            )
        )
        diff_output.extend(udiff)

    return "".join(diff_output)


def _build_variant_p05(gold_patch: str) -> str | None:
    """Generate p05_hunk_in_prose: added lines of first hunk pasted between filler prose.

    Returns None when the first hunk adds nothing (a deletion-only hunk).
    """
    added_lines: list[str] = []
    in_first_hunk = False

    for line in gold_patch.splitlines():
        if line.startswith("@@"):
            if in_first_hunk:
                break
            in_first_hunk = True
            continue
        if in_first_hunk:
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])

    if not added_lines:
        return None
    middle = "\n".join(added_lines)
    return f"{FILLER_PROSE_1}\n\n{middle}\n\n{FILLER_PROSE_2}\n"


def _build_variant_p10(test_patch: str) -> str:
    """Generate p10_hidden_tests: added lines of staging/test.patch as tests_leak.py."""
    added_lines: list[str] = []
    for line in test_patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])
    return "\n".join(added_lines) + "\n"


def _write_deterministic_zip(zip_path: Path, files_map: dict[str, bytes | str]) -> None:
    """Write zip file with deterministic entry timestamps."""
    fixed_time = (2026, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path in sorted(files_map.keys()):
            data = files_map[rel_path]
            data_bytes = data.encode("utf-8") if isinstance(data, str) else data
            zi = zipfile.ZipInfo(filename=rel_path, date_time=fixed_time)
            zf.writestr(zi, data_bytes)


def _write_deterministic_tar_gz(tar_path: Path, files_map: dict[str, bytes | str]) -> None:
    """Write tar.gz file with deterministic entry metadata and mtime=0."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(mode="w", fileobj=gz) as tf:
            for rel_path in sorted(files_map.keys()):
                data = files_map[rel_path]
                data_bytes = data.encode("utf-8") if isinstance(data, str) else data
                ti = tarfile.TarInfo(name=rel_path)
                ti.size = len(data_bytes)
                ti.mtime = 0
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                tf.addfile(ti, io.BytesIO(data_bytes))
    tar_path.write_bytes(buf.getvalue())


def _write_deterministic_sqlite(db_path: Path, files_map: dict[str, str]) -> None:
    """Write SQLite database with file contents in TEXT cells."""
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE leaks (path TEXT PRIMARY KEY, content TEXT)")
        for rel_path in sorted(files_map.keys()):
            conn.execute("INSERT INTO leaks (path, content) VALUES (?, ?)", (rel_path, files_map[rel_path]))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CLI Command: e3-basetrees
# ---------------------------------------------------------------------------

def extract_basetrees(tasks_dir: Path, out_dir: Path, only: list[str] | None = None) -> None:
    """Extract /testbed from hermetic/<id>:sealed into <out>/<id>/ without .git."""
    out_dir.mkdir(parents=True, exist_ok=True)
    task_dirs = sorted([d for d in tasks_dir.iterdir() if d.is_dir() and (d / "task.json").exists()])
    if only:
        task_dirs = [d for d in task_dirs if d.name in only]

    for tdir in task_dirs:
        task_id = tdir.name
        task_dest = out_dir / task_id
        meta_dest = out_dir / f"{task_id}.basetree.json"

        if task_dest.exists():
            continue

        image_tag = f"hermetic/{task_id}:sealed"
        cid = run_docker(["create", image_tag]).decode("utf-8").strip()
        try:
            with tempfile.TemporaryDirectory() as td:
                temp_extract = Path(td) / "testbed"
                run_docker(["cp", f"{cid}:/testbed", str(temp_extract)])
                git_dir = temp_extract / ".git"
                if git_dir.exists():
                    if git_dir.is_dir():
                        shutil.rmtree(git_dir, ignore_errors=True)
                    else:
                        git_dir.unlink()
                shutil.copytree(temp_extract, task_dest)
        finally:
            run_docker(["rm", "-f", cid], check=False)

        # Compute relative file list and sha256
        rel_files = []
        for p in task_dest.rglob("*"):
            if p.is_file():
                rel_files.append(p.relative_to(task_dest).as_posix())
        rel_files.sort()

        files_hash = hashlib.sha256("\n".join(rel_files).encode("utf-8")).hexdigest()
        meta_data = {
            "task_id": task_id,
            "file_count": len(rel_files),
            "sha256": files_hash,
            "files_sha256": files_hash,
        }
        meta_dest.write_text(json.dumps(meta_data, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI Command: e3-build
# ---------------------------------------------------------------------------

def build_corpus(
    tasks_dir: Path,
    base_trees_dir: Path,
    out_dir: Path,
    seed: int = 42,
) -> Path:
    """Build positive and negative leak variants for real and synthetic tasks."""
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = out_dir / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate synthetic tasks
    synthetic_dir = out_dir / "synthetic"
    synth_task_ids = generate_synthetic_tasks(synthetic_dir)

    # 2. Discover real tasks
    real_task_dirs: list[Path] = []
    if tasks_dir.exists():
        real_task_dirs = sorted([d for d in tasks_dir.iterdir() if d.is_dir() and (d / "task.json").exists()])

    # Combined task catalog
    # Map task_id -> (task_dir, base_tree_dir, is_synthetic)
    all_tasks: dict[str, tuple[Path, Path, bool]] = {}
    for td in real_task_dirs:
        bdir = base_trees_dir / td.name
        if bdir.exists():
            all_tasks[td.name] = (td, bdir, False)

    for stid in synth_task_ids:
        std = synthetic_dir / stid
        sbd = std / "base_tree"
        all_tasks[stid] = (std, sbd, True)

    sorted_task_ids = sorted(all_tasks.keys())

    # Pre-compute post-fix files and gold patches for all tasks (needed for p01, p03, and n03 cross-task)
    task_cache: dict[str, dict[str, Any]] = {}
    for task_id in sorted_task_ids:
        td, bd, is_synth = all_tasks[task_id]
        gold_patch = (td / "staging" / "gold.patch").read_text(encoding="utf-8", errors="replace")
        test_patch = ""
        test_patch_file = td / "staging" / "test.patch"
        if test_patch_file.exists():
            test_patch = test_patch_file.read_text(encoding="utf-8", errors="replace")

        touched = parse_patch_touched_files(gold_patch)
        postfix_contents = apply_patch_in_temp_dir(bd, gold_patch, touched)

        task_cache[task_id] = {
            "task_dir": td,
            "base_tree_dir": bd,
            "is_synth": is_synth,
            "gold_patch": gold_patch,
            "test_patch": test_patch,
            "touched": touched,
            "postfix_contents": postfix_contents,
        }

    case_records: list[dict[str, Any]] = []

    def _write_case(
        case_id: str,
        task_id: str,
        kind: str,
        variant: str,
        expected: str,
        notes: str,
        files_writer: Callable[[Path], None],
    ) -> None:
        case_dir = cases_dir / case_id
        root_dir = case_dir / "root"
        if case_dir.exists():
            shutil.rmtree(case_dir)
        root_dir.mkdir(parents=True, exist_ok=True)

        files_writer(root_dir)

        case_json_data = {
            "case_id": case_id,
            "task_id": task_id,
            "kind": kind,
            "variant": variant,
            "expected": expected,
            "notes": notes,
        }
        (case_dir / "case.json").write_text(json.dumps(case_json_data, indent=2) + "\n", encoding="utf-8")

        sha256_digest = compute_dir_files_sha256(root_dir)
        case_records.append({**case_json_data, "sha256": sha256_digest})

    # Generate variants for each task
    for idx, task_id in enumerate(sorted_task_ids):
        info = task_cache[task_id]
        td = info["task_dir"]
        bd = info["base_tree_dir"]
        is_synth = info["is_synth"]
        gold_patch = info["gold_patch"]
        test_patch = info["test_patch"]
        touched = info["touched"]
        postfix_contents = info["postfix_contents"]

        # ----------------- Positive variants -----------------

        # p01_postfix_file
        def write_p01(root: Path) -> None:
            for rel, content in postfix_contents.items():
                dst = root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(content, encoding="utf-8", newline="")

        _write_case(
            f"{task_id}__p01_postfix_file",
            task_id,
            "positive",
            "p01_postfix_file",
            "gate",
            "Post-fix touched files at repo-relative paths",
            write_p01,
        )

        # p03_patch_file
        def write_p03(root: Path) -> None:
            (root / "fix.patch").write_text(gold_patch, encoding="utf-8", newline="\n")

        _write_case(
            f"{task_id}__p03_patch_file",
            task_id,
            "positive",
            "p03_patch_file",
            "gate",
            "staging/gold.patch as fix.patch",
            write_p03,
        )

        # p04_regenerated_diff
        def write_p04(root: Path) -> None:
            diff_text = _build_variant_p04(bd, postfix_contents)
            (root / "fix.diff").write_text(diff_text, encoding="utf-8", newline="\n")

        _write_case(
            f"{task_id}__p04_regenerated_diff",
            task_id,
            "positive",
            "p04_regenerated_diff",
            "gate",
            "difflib unified diff with 1 context line and no index lines as fix.diff",
            write_p04,
        )

        # Real tasks get additional positive variants p02, p05-p11
        if not is_synth:
            # p02_reformatted
            def write_p02(root: Path) -> None:
                reformatted_map = _build_variant_p02(gold_patch, postfix_contents)
                for rel, content in reformatted_map.items():
                    dst = root / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_text(content, encoding="utf-8", newline="")

            _write_case(
                f"{task_id}__p02_reformatted",
                task_id,
                "positive",
                "p02_reformatted",
                "gate",
                "Changed hunks with comments removed, blank lines dropped and indentation stripped",
                write_p02,
            )

            # p05_hunk_in_prose, unless the first hunk only deletes
            notes_text = _build_variant_p05(gold_patch)

            def write_p05(root: Path) -> None:
                (root / "notes.txt").write_text(notes_text or "", encoding="utf-8", newline="")

            if notes_text is not None:
                _write_case(
                    f"{task_id}__p05_hunk_in_prose",
                    task_id,
                    "positive",
                    "p05_hunk_in_prose",
                    "gate",
                    "Added lines of first hunk in filler prose in notes.txt",
                    write_p05,
                )

            # p06_zip
            def write_p06(root: Path) -> None:
                _write_deterministic_zip(root / "leak.zip", postfix_contents)

            _write_case(
                f"{task_id}__p06_zip",
                task_id,
                "positive",
                "p06_zip",
                "gate",
                "p01 files in leak.zip",
                write_p06,
            )

            # p07_tar_gz
            def write_p07(root: Path) -> None:
                _write_deterministic_tar_gz(root / "leak.tar.gz", {"fix.patch": gold_patch})

            _write_case(
                f"{task_id}__p07_tar_gz",
                task_id,
                "positive",
                "p07_tar_gz",
                "gate",
                "fix.patch in leak.tar.gz",
                write_p07,
            )

            # p08_nested
            def write_p08(root: Path) -> None:
                zip_buf = io.BytesIO()
                fixed_time = (2026, 1, 1, 0, 0, 0)
                with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for rel in sorted(postfix_contents.keys()):
                        zi = zipfile.ZipInfo(filename=rel, date_time=fixed_time)
                        zf.writestr(zi, postfix_contents[rel].encode("utf-8"))
                _write_deterministic_tar_gz(root / "leak.tar.gz", {"leak.zip": zip_buf.getvalue()})

            _write_case(
                f"{task_id}__p08_nested",
                task_id,
                "positive",
                "p08_nested",
                "gate",
                "Zip holding p01 files inside leak.tar.gz",
                write_p08,
            )

            # p09_sqlite
            def write_p09(root: Path) -> None:
                _write_deterministic_sqlite(root / "leak.db", postfix_contents)

            _write_case(
                f"{task_id}__p09_sqlite",
                task_id,
                "positive",
                "p09_sqlite",
                "gate",
                "SQLite db with p01 text in TEXT cell",
                write_p09,
            )

            # p10_hidden_tests, unless the test patch adds nothing
            tests_leak_code = _build_variant_p10(test_patch)

            def write_p10(root: Path) -> None:
                (root / "tests_leak.py").write_text(tests_leak_code, encoding="utf-8", newline="")

            if tests_leak_code.strip():
                _write_case(
                    f"{task_id}__p10_hidden_tests",
                    task_id,
                    "positive",
                    "p10_hidden_tests",
                    "gate",
                    "Added lines of staging/test.patch as tests_leak.py",
                    write_p10,
                )

            # p11_pyc: only if any touched file is .py
            py_touched = [rel for rel in touched if rel.endswith(".py")]
            if py_touched:

                def write_p11(root: Path) -> None:
                    old_epoch = os.environ.get("SOURCE_DATE_EPOCH")
                    try:
                        os.environ["SOURCE_DATE_EPOCH"] = "0"
                        with tempfile.TemporaryDirectory() as td:
                            temp_dir = Path(td)
                            for rel in py_touched:
                                if rel in postfix_contents:
                                    src_f = temp_dir / rel
                                    src_f.parent.mkdir(parents=True, exist_ok=True)
                                    src_f.write_text(postfix_contents[rel], encoding="utf-8", newline="")
                                    # destination .pyc in root
                                    dst_pyc = root / (rel + "c" if not rel.endswith(".py") else rel[:-3] + ".pyc")
                                    dst_pyc.parent.mkdir(parents=True, exist_ok=True)
                                    py_compile.compile(str(src_f), cfile=str(dst_pyc), dfile=rel, doraise=True)
                    finally:
                        if old_epoch is not None:
                            os.environ["SOURCE_DATE_EPOCH"] = old_epoch
                        else:
                            os.environ.pop("SOURCE_DATE_EPOCH", None)

                _write_case(
                    f"{task_id}__p11_pyc",
                    task_id,
                    "positive",
                    "p11_pyc",
                    "gate",
                    "py_compile of touched .py files as .pyc only",
                    write_p11,
                )

        # ----------------- Negative variants -----------------

        # n01_prefix_files
        def write_n01(root: Path) -> None:
            for rel in touched:
                src = bd / rel
                if src.exists():
                    dst = root / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)

        _write_case(
            f"{task_id}__n01_prefix_files",
            task_id,
            "negative",
            "n01_prefix_files",
            "clean",
            "Touched files at base commit (before the fix)",
            write_n01,
        )

        # n02_base_sample: 200 base-tree files sampled with the seed
        all_base_files: list[str] = []
        for p in bd.rglob("*"):
            if p.is_file():
                all_base_files.append(p.relative_to(bd).as_posix())
        all_base_files.sort()

        if len(all_base_files) > 200:
            sample_files = sorted(rng.sample(all_base_files, 200))
        elif len(all_base_files) > 1:
            sample_files = sorted(rng.sample(all_base_files, len(all_base_files) - 1))
        else:
            sample_files = list(all_base_files)

        def write_n02(root: Path) -> None:
            for rel in sample_files:
                src = bd / rel
                dst = root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

        _write_case(
            f"{task_id}__n02_base_sample",
            task_id,
            "negative",
            "n02_base_sample",
            "clean",
            f"Base-tree files sampled with seed {seed}",
            write_n02,
        )

        # n03_cross_task: Another task's p01 and p03 content, paired with next task in sorted order
        if len(sorted_task_ids) > 1:
            next_task_id = sorted_task_ids[(idx + 1) % len(sorted_task_ids)]
            next_info = task_cache[next_task_id]

            def write_n03(root: Path) -> None:
                # Other task's p01 files
                for rel, content in next_info["postfix_contents"].items():
                    dst = root / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_text(content, encoding="utf-8", newline="")
                # Other task's fix.patch
                (root / "fix.patch").write_text(next_info["gold_patch"], encoding="utf-8", newline="\n")

            _write_case(
                f"{task_id}__n03_cross_task",
                task_id,
                "negative",
                "n03_cross_task",
                "clean",
                f"Cross-task leak with {next_task_id} scanned with {task_id} fingerprints",
                write_n03,
            )

    # Sort cases by case_id
    case_records.sort(key=lambda c: c["case_id"])

    corpus_data = {
        "seed": seed,
        "tool_version": TOOL_VERSION,
        "cases": case_records,
        "cases_by_id": {c["case_id"]: c for c in case_records},
    }
    (out_dir / "corpus.json").write_text(json.dumps(corpus_data, indent=2) + "\n", encoding="utf-8")
    return out_dir


# ---------------------------------------------------------------------------
# CLI Command: e3-run
# ---------------------------------------------------------------------------

def _compute_metrics_block(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute TP, FP, TN, FN, Precision, Recall and Wilson intervals for a result set."""
    tp = sum(1 for r in items if r["label"] == "gate" and r["call"] == "gate")
    tn = sum(1 for r in items if r["label"] == "clean" and r["call"] == "clean")

    # Error counted against recall for positives, against precision for negatives
    fn_clean = sum(1 for r in items if r["label"] == "gate" and r["call"] == "clean")
    fn_error = sum(1 for r in items if r["label"] == "gate" and r["call"] == "error")
    fn = fn_clean + fn_error

    fp_gate = sum(1 for r in items if r["label"] == "clean" and r["call"] == "gate")
    fp_error = sum(1 for r in items if r["label"] == "clean" and r["call"] == "error")
    fp = fp_gate + fp_error

    errors = sum(1 for r in items if r["call"] == "error")
    total = len(items)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    prec_ci = list(wilson_interval(tp, tp + fp)) if (tp + fp) > 0 else [0.0, 0.0]

    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    rec_ci = list(wilson_interval(tp, tp + fn)) if (tp + fn) > 0 else [0.0, 0.0]

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "raw_fp": fp_gate,
        "raw_fn": fn_clean,
        "errors": errors,
        "errors_positive": fn_error,
        "errors_negative": fp_error,
        "total": total,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "precision_ci": [round(prec_ci[0], 4), round(prec_ci[1], 4)],
        "recall_ci": [round(rec_ci[0], 4), round(rec_ci[1], 4)],
    }


def _render_metrics_markdown(metrics_data: dict[str, Any]) -> str:
    """Render comprehensive markdown report from metrics JSON."""
    lines: list[str] = [
        "# E3 Accuracy Harness Metrics Report",
        "",
        "## Overall Metrics",
        "",
        "| Metric | Value | 95% Confidence Interval |",
        "|---|---|---|",
    ]
    ov = metrics_data["overall"]
    lines.append(f"| True Positives (TP) | {ov['tp']} | - |")
    lines.append(f"| False Positives (FP) | {ov['fp']} (incl. {ov['errors_negative']} errors) | - |")
    lines.append(f"| True Negatives (TN) | {ov['tn']} | - |")
    lines.append(f"| False Negatives (FN) | {ov['fn']} (incl. {ov['errors_positive']} errors) | - |")
    lines.append(f"| Total Cases | {ov['total']} | - |")
    lines.append(f"| Total Errors | {ov['errors']} | - |")
    lines.append(
        f"| **Precision** | **{ov['precision'] * 100:.2f}%** | [{ov['precision_ci'][0] * 100:.2f}%, {ov['precision_ci'][1] * 100:.2f}%] |"
    )
    lines.append(
        f"| **Recall** | **{ov['recall'] * 100:.2f}%** | [{ov['recall_ci'][0] * 100:.2f}%, {ov['recall_ci'][1] * 100:.2f}%] |"
    )
    lines.append("")

    # Per Variant Table
    lines.append("## Per-Variant Metrics")
    lines.append("")
    lines.append("| Variant | Total | TP | FP | TN | FN | Errors | Precision | Recall |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for var_name, vm in sorted(metrics_data["per_variant"].items()):
        p_str = f"{vm['precision'] * 100:.1f}%" if (vm["tp"] + vm["fp"]) > 0 else "N/A"
        r_str = f"{vm['recall'] * 100:.1f}%" if (vm["tp"] + vm["fn"]) > 0 else "N/A"
        lines.append(
            f"| `{var_name}` | {vm['total']} | {vm['tp']} | {vm['fp']} | {vm['tn']} | {vm['fn']} | {vm['errors']} | {p_str} | {r_str} |"
        )
    lines.append("")

    # Synthetic Table
    lines.append("## Synthetic Tasks Metrics")
    lines.append("")
    lines.append("| Set | Total | TP | FP | TN | FN | Errors | Precision | Recall |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    syn = metrics_data["synthetic"]
    p_syn = f"{syn['precision'] * 100:.1f}%" if (syn["tp"] + syn["fp"]) > 0 else "N/A"
    r_syn = f"{syn['recall'] * 100:.1f}%" if (syn["tp"] + syn["fn"]) > 0 else "N/A"
    lines.append(
        f"| Synthetic | {syn['total']} | {syn['tp']} | {syn['fp']} | {syn['tn']} | {syn['fn']} | {syn['errors']} | {p_syn} | {r_syn} |"
    )
    lines.append("")

    # Per Task Table
    lines.append("## Per-Task Metrics")
    lines.append("")
    lines.append("| Task ID | Total | TP | FP | TN | FN | Errors | Precision | Recall |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for tid, tm in sorted(metrics_data["per_task"].items()):
        p_t = f"{tm['precision'] * 100:.1f}%" if (tm["tp"] + tm["fp"]) > 0 else "N/A"
        r_t = f"{tm['recall'] * 100:.1f}%" if (tm["tp"] + tm["fn"]) > 0 else "N/A"
        lines.append(
            f"| `{tid}` | {tm['total']} | {tm['tp']} | {tm['fp']} | {tm['tn']} | {tm['fn']} | {tm['errors']} | {p_t} | {r_t} |"
        )
    lines.append("")

    if "blind" in metrics_data:
        lines.append("## Blind Set Metrics")
        lines.append("")
        lines.append("| Set | Total | TP | FP | TN | FN | Errors | Precision | Recall |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        bl = metrics_data["blind"]
        p_bl = f"{bl['precision'] * 100:.1f}%" if (bl["tp"] + bl["fp"]) > 0 else "N/A"
        r_bl = f"{bl['recall'] * 100:.1f}%" if (bl["tp"] + bl["fn"]) > 0 else "N/A"
        lines.append(
            f"| Blind Set | {bl['total']} | {bl['tp']} | {bl['fp']} | {bl['tn']} | {bl['fn']} | {bl['errors']} | {p_bl} | {r_bl} |"
        )
        lines.append("")

    return "\n".join(lines)


def _scan_single_case(
    sealcheck_bin: str | Path,
    task_dir: Path,
    base_tree_dir: Path,
    case_root: Path,
    timeout: float = 300.0,
) -> tuple[str, int | None, list[str], float, bool]:
    """Execute sealcheck scan on a single case root.

    Returns (call, exit_code, scored_channels, wall_time, d0_gate).
    """
    cmd_str = str(sealcheck_bin)
    if cmd_str.endswith(".py"):
        cmd = [
            sys.executable,
            cmd_str,
            "scan",
            "--task",
            str(task_dir),
            "--base-tree",
            str(base_tree_dir),
            "--root",
            str(case_root),
            "--root-visibility",
            "agent_visible",
            "--format",
            "json",
        ]
    else:
        cmd = [
            cmd_str,
            "scan",
            "--task",
            str(task_dir),
            "--base-tree",
            str(base_tree_dir),
            "--root",
            str(case_root),
            "--root-visibility",
            "agent_visible",
            "--format",
            "json",
        ]

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
        )
        wall_time = time.perf_counter() - t0
        exit_code = proc.returncode

        if exit_code not in (0, 2):
            return ("error", exit_code, [], wall_time, False)

        try:
            output_json = json.loads(proc.stdout.decode("utf-8", errors="replace"))
            findings = output_json.get("findings", [])
            scored_findings = [
                f
                for f in findings
                if f.get("severity") == "gate"
                and f.get("visibility") == "agent_visible"
                and f.get("detector") in SCORED_DETECTORS
            ]
            d0_gate = any(f.get("detector") == "D0" and f.get("severity") == "gate" for f in findings)
            channels = sorted(list({f.get("channel", "") for f in scored_findings if f.get("channel")}))
            call = "gate" if len(scored_findings) > 0 else "clean"
            return (call, exit_code, channels, wall_time, d0_gate)
        except Exception:
            return ("error", exit_code, [], wall_time, False)

    except subprocess.TimeoutExpired:
        wall_time = time.perf_counter() - t0
        return ("error", -1, [], wall_time, False)
    except Exception:
        wall_time = time.perf_counter() - t0
        return ("error", -1, [], wall_time, False)


def run_e3(
    corpus_dir: Path,
    tasks_dir: Path,
    base_trees_dir: Path,
    sealcheck_bin: str | Path,
    out_dir: Path,
    blind_dir: Path | None = None,
) -> None:
    """Run sealcheck accuracy evaluation over corpus cases."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = corpus_dir / "cases"

    case_dirs = sorted([d for d in cases_dir.iterdir() if d.is_dir() and (d / "case.json").exists()])

    results: list[dict[str, Any]] = []

    for cdir in case_dirs:
        case_json = json.loads((cdir / "case.json").read_text(encoding="utf-8"))
        case_id = case_json["case_id"]
        task_id = case_json["task_id"]
        variant = case_json["variant"]
        expected = case_json["expected"]
        case_root = cdir / "root"

        # Resolve task dir and base tree
        synthetic_task_dir = corpus_dir / "synthetic" / task_id
        if synthetic_task_dir.exists():
            td = synthetic_task_dir
            bd = synthetic_task_dir / "base_tree"
            is_synth = True
        else:
            td = tasks_dir / task_id
            bd = base_trees_dir / task_id
            is_synth = False

        call, exit_code, channels, wall_time, d0_gate = _scan_single_case(
            sealcheck_bin,
            task_dir=td,
            base_tree_dir=bd,
            case_root=case_root,
        )

        res_item = {
            "case_id": case_id,
            "task_id": task_id,
            "variant": variant,
            "is_synth": is_synth,
            "label": expected,
            "call": call,
            "exit_code": exit_code,
            "channels": channels,
            "wall_time": round(wall_time, 4),
            "d0_gate": d0_gate,
        }
        results.append(res_item)

    # Handle blind evaluation if requested
    blind_results: list[dict[str, Any]] = []
    blind_unlabeled: list[str] = []
    if blind_dir is not None and blind_dir.exists():
        blind_cases_dir = blind_dir / "cases" if (blind_dir / "cases").exists() else blind_dir
        blind_case_dirs = sorted([d for d in blind_cases_dir.iterdir() if d.is_dir() and (d / "root").exists()])

        blind_scans: list[tuple[Path, str, int | None, list[str], float]] = []
        # Crucial: Scan all blind cases BEFORE reading blind_dir/labels.json!
        for b_cdir in blind_case_dirs:
            b_case_id = b_cdir.name
            b_root = b_cdir / "root"

            # Check if case has its own case.json for task_id or defaults
            b_task_id = b_case_id.split("__")[0]
            if (b_cdir / "case.json").exists():
                b_meta = json.loads((b_cdir / "case.json").read_text(encoding="utf-8"))
                b_task_id = b_meta.get("task_id", b_task_id)

            synthetic_task_dir = corpus_dir / "synthetic" / b_task_id
            if synthetic_task_dir.exists():
                td = synthetic_task_dir
                bd = synthetic_task_dir / "base_tree"
            else:
                td = tasks_dir / b_task_id
                bd = base_trees_dir / b_task_id

            call, exit_code, channels, wall_time, _ = _scan_single_case(
                sealcheck_bin,
                task_dir=td,
                base_tree_dir=bd,
                case_root=b_root,
            )
            blind_scans.append((b_cdir, call, exit_code, channels, wall_time))

        # ONLY NOW read blind_dir/labels.json!
        labels_file = blind_dir / "labels.json"
        blind_labels: dict[str, str] = {}
        if labels_file.exists():
            raw_labels = json.loads(labels_file.read_text(encoding="utf-8"))
            if isinstance(raw_labels, dict):
                for k, v in raw_labels.items():
                    if isinstance(v, str):
                        blind_labels[k] = v
                    elif isinstance(v, dict):
                        blind_labels[k] = v.get("expected", "clean")
            elif isinstance(raw_labels, list):
                for entry in raw_labels:
                    blind_labels[entry["case_id"]] = entry.get("expected", entry.get("label", "clean"))

        for b_cdir, call, exit_code, channels, wall_time in blind_scans:
            b_case_id = b_cdir.name
            expected_label = blind_labels.get(b_case_id)
            if expected_label not in ("gate", "clean"):
                blind_unlabeled.append(b_case_id)
                continue
            blind_results.append(
                {
                    "case_id": b_case_id,
                    "label": expected_label,
                    "call": call,
                    "exit_code": exit_code,
                    "channels": channels,
                    "wall_time": round(wall_time, 4),
                }
            )

    # Write results.jsonl
    results_jsonl = out_dir / "results.jsonl"
    with results_jsonl.open("w", encoding="utf-8") as f:
        for r in results:
            line_dict = {
                "case_id": r["case_id"],
                "task_id": r["task_id"],
                "variant": r["variant"],
                "label": r["label"],
                "call": r["call"],
                "exit_code": r["exit_code"],
                "channels": r["channels"],
                "wall_time": r["wall_time"],
                "d0_gate": r["d0_gate"],
            }
            f.write(json.dumps(line_dict) + "\n")

    # Compute metric breakdowns
    overall_metrics = _compute_metrics_block(results)

    # Per variant
    per_variant_metrics: dict[str, Any] = {}
    variant_groups: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        variant_groups.setdefault(r["variant"], []).append(r)
    for var_name, var_items in sorted(variant_groups.items()):
        per_variant_metrics[var_name] = _compute_metrics_block(var_items)

    # Synthetic set
    synth_items = [r for r in results if r.get("is_synth")]
    synthetic_metrics = _compute_metrics_block(synth_items)

    # Per task
    per_task_metrics: dict[str, Any] = {}
    task_groups: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        task_groups.setdefault(r["task_id"], []).append(r)
    for tid, t_items in sorted(task_groups.items()):
        per_task_metrics[tid] = _compute_metrics_block(t_items)

    metrics_output: dict[str, Any] = {
        "overall": overall_metrics,
        "per_variant": per_variant_metrics,
        "synthetic": synthetic_metrics,
        "per_task": per_task_metrics,
    }

    # D0 depends only on the task, so report it once per task.
    metrics_output["d0_gate_tasks"] = sorted({r["task_id"] for r in results if r["d0_gate"]})

    if blind_results:
        metrics_output["blind"] = _compute_metrics_block(blind_results)
    if blind_unlabeled:
        metrics_output["blind_unlabeled"] = sorted(blind_unlabeled)

    # Write metrics.json
    (out_dir / "metrics.json").write_text(json.dumps(metrics_output, indent=2) + "\n", encoding="utf-8")

    # Write metrics.md
    metrics_md_content = _render_metrics_markdown(metrics_output)
    (out_dir / "metrics.md").write_text(metrics_md_content + "\n", encoding="utf-8")
