"""Built-in fixture task worlds for Hermetic E3 blind leak seeding.

Provides 10-20 realistic fixture tasks, each with a one-sentence summary,
base files, problem statement, gold patch, and suggested leak/decoy strings.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES: int = 16 * 1024 * 1024
READ_CHUNK_BYTES: int = 64 * 1024


@dataclass(frozen=True, slots=True)
class FixtureTask:
    """Fixture task specification for blind leak seeding."""

    task_id: str
    summary: str
    base_files: dict[str, str]
    gold_patch: str
    problem_statement: str
    default_leak: str
    default_decoy: str


def _make_fixture_tasks() -> list[FixtureTask]:
    """Define the catalog of 16 fixture task worlds."""
    tasks: list[FixtureTask] = []

    # Task 1: Billing Tier Service
    t1_base = {
        "service.py": (
            "from enum import Enum\n\n"
            "class CustomerTier(Enum):\n"
            '    FREE = "free"\n'
            '    STARTER = "starter"\n'
            '    PRO = "pro"\n'
            '    ENTERPRISE = "enterprise"\n\n'
            "def get_tier_rate(tier: CustomerTier) -> float:\n"
            "    # Standard tier base rates\n"
            "    rates = {\n"
            "        CustomerTier.FREE: 0.0,\n"
            "        CustomerTier.STARTER: 29.0,\n"
            "        CustomerTier.PRO: 99.0,\n"
            "        CustomerTier.ENTERPRISE: 499.0,\n"
            "    }\n"
            "    return rates.get(tier, 0.0)\n"
        ),
        "README.md": (
            "# Billing Tier Service\n\n"
            "Manages customer subscription tiers and base monthly subscription rates.\n"
        ),
        "config.py": (
            "SERVICE_NAME = 'billing_tier'\n"
            "DEFAULT_CURRENCY = 'USD'\n"
            "TAX_RATE = 0.08\n"
        ),
        "tests/test_service.py": (
            "from service import CustomerTier, get_tier_rate\n\n"
            "def test_free_tier():\n"
            "    assert get_tier_rate(CustomerTier.FREE) == 0.0\n\n"
            "def test_starter_tier():\n"
            "    assert get_tier_rate(CustomerTier.STARTER) == 29.0\n"
        ),
    }
    t1_patch = (
        "diff --git a/service.py b/service.py\n"
        "--- a/service.py\n"
        "+++ b/service.py\n"
        "@@ -10,4 +10,5 @@\n"
        "         CustomerTier.STARTER: 29.0,\n"
        "         CustomerTier.PRO: 99.0,\n"
        "+        CustomerTier.PRO_PLUS: 199.0,\n"
        "         CustomerTier.ENTERPRISE: 499.0,\n"
    )
    tasks.append(
        FixtureTask(
            task_id="billing_tier_service",
            summary="Customer billing service: manages subscription tiers and base monthly rates.",
            base_files=t1_base,
            gold_patch=t1_patch,
            problem_statement="Support the new PRO_PLUS tier priced at 199.0 USD per month.",
            default_leak="CustomerTier.PRO_PLUS: 199.0,",
            default_decoy="# Maintenance note: verify annual billing discount rates quarterly.",
        )
    )

    # Task 2: Usage Calculator
    t2_base = {
        "calculator.py": (
            "def calculate_compute_units(cpu_hours: float, memory_gb_hours: float) -> float:\n"
            "    # Standard compute unit conversion\n"
            "    cpu_factor = 1.0\n"
            "    mem_factor = 0.25\n"
            "    return round(cpu_hours * cpu_factor + memory_gb_hours * mem_factor, 2)\n\n"
            "def is_over_quota(total_units: float, quota_limit: float) -> bool:\n"
            "    return total_units > quota_limit\n"
        ),
        "README.md": (
            "# Usage Calculator\n\n"
            "Calculates normalized compute units from raw CPU hours and memory usage.\n"
        ),
        "config.py": (
            "QUOTA_WARNING_THRESHOLD = 0.85\n"
            "MAX_MONTHLY_UNITS = 100000.0\n"
        ),
        "tests/test_calculator.py": (
            "from calculator import calculate_compute_units, is_over_quota\n\n"
            "def test_units():\n"
            "    assert calculate_compute_units(10.0, 40.0) == 20.0\n"
        ),
    }
    t2_patch = (
        "diff --git a/calculator.py b/calculator.py\n"
        "--- a/calculator.py\n"
        "+++ b/calculator.py\n"
        "@@ -3,3 +3,3 @@\n"
        "-    mem_factor = 0.25\n"
        "+    mem_factor = 0.20\n"
    )
    tasks.append(
        FixtureTask(
            task_id="usage_calculator",
            summary="Usage calculator: computes normalized resource units from CPU and memory metrics.",
            base_files=t2_base,
            gold_patch=t2_patch,
            problem_statement="Adjust memory weighting factor from 0.25 down to 0.20 per spec.",
            default_leak="mem_factor = 0.20",
            default_decoy="# Routine check: ensure memory allocation metric matches hypervisor logs.",
        )
    )

    # Task 3: Invoice Generator
    t3_base = {
        "invoice.py": (
            "def calculate_total(subtotal: float, discount: float, tax_rate: float) -> float:\n"
            "    discounted = max(0.0, subtotal - discount)\n"
            "    tax = discounted * tax_rate\n"
            "    return round(discounted + tax, 2)\n\n"
            "def format_currency(amount: float) -> str:\n"
            '    return f"${amount:,.2f}"\n'
        ),
        "README.md": (
            "# Invoice Generator\n\n"
            "Produces final billing invoices including discounts and sales tax.\n"
        ),
        "config.py": (
            "DEFAULT_TAX_RATE = 0.0825\n"
            "CURRENCY_SYMBOL = '$'\n"
        ),
        "tests/test_invoice.py": (
            "from invoice import calculate_total, format_currency\n\n"
            "def test_total():\n"
            "    assert calculate_total(100.0, 10.0, 0.10) == 99.0\n"
        ),
    }
    t3_patch = (
        "diff --git a/invoice.py b/invoice.py\n"
        "--- a/invoice.py\n"
        "+++ b/invoice.py\n"
        "@@ -3,3 +3,3 @@\n"
        "-    return round(discounted + tax, 2)\n"
        "+    return round(discounted + round(tax, 2), 2)\n"
    )
    tasks.append(
        FixtureTask(
            task_id="invoice_generator",
            summary="Invoice generator: calculates customer totals, line discounts, and sales tax.",
            base_files=t3_base,
            gold_patch=t3_patch,
            problem_statement="Round intermediate tax line before summing to match accounting rules.",
            default_leak="return round(discounted + round(tax, 2), 2)",
            default_decoy="# Accounting audit note: all invoices must preserve cents precision.",
        )
    )

    # Task 4: Discount Scheduler
    t4_base = {
        "discount.py": (
            "def apply_volume_discount(amount: float, annual_volume: int) -> float:\n"
            "    if annual_volume >= 10000:\n"
            "        rate = 0.15\n"
            "    elif annual_volume >= 5000:\n"
            "        rate = 0.10\n"
            "    else:\n"
            "        rate = 0.0\n"
            "    return round(amount * (1.0 - rate), 2)\n"
        ),
        "README.md": (
            "# Discount Scheduler\n\n"
            "Calculates volume discount tiers based on historical annual customer spend.\n"
        ),
        "config.py": (
            "MIN_QUALIFYING_VOLUME = 1000\n"
            "MAX_DISCOUNT_PERCENT = 20\n"
        ),
        "tests/test_discount.py": (
            "from discount import apply_volume_discount\n\n"
            "def test_high_volume():\n"
            "    assert apply_volume_discount(100.0, 12000) == 85.0\n"
        ),
    }
    t4_patch = (
        "diff --git a/discount.py b/discount.py\n"
        "--- a/discount.py\n"
        "+++ b/discount.py\n"
        "@@ -4,2 +4,4 @@\n"
        "+    elif annual_volume >= 2500:\n"
        "+        rate = 0.05\n"
    )
    tasks.append(
        FixtureTask(
            task_id="discount_scheduler",
            summary="Discount scheduler: determines tiered discounts from customer volume.",
            base_files=t4_base,
            gold_patch=t4_patch,
            problem_statement="Add an intermediate 5% discount tier for accounts with volume >= 2500.",
            default_leak="elif annual_volume >= 2500:\n        rate = 0.05",
            default_decoy="# Promotional rules: volume thresholds are reviewed every fiscal quarter.",
        )
    )

    # Task 5: Retry Policy Manager
    t5_base = {
        "retry.py": (
            "import time\n\n"
            "def compute_backoff(attempt: int, base_seconds: float = 1.0, max_seconds: float = 30.0) -> float:\n"
            "    delay = base_seconds * (2 ** attempt)\n"
            "    return min(delay, max_seconds)\n\n"
            "def should_retry(status_code: int) -> bool:\n"
            "    return status_code in (429, 502, 503, 504)\n"
        ),
        "README.md": (
            "# Retry Policy Manager\n\n"
            "Calculates exponential backoff and identifies transient HTTP status codes.\n"
        ),
        "config.py": (
            "MAX_RETRY_ATTEMPTS = 5\n"
            "BACKOFF_JITTER_ENABLED = False\n"
        ),
        "tests/test_retry.py": (
            "from retry import compute_backoff, should_retry\n\n"
            "def test_backoff():\n"
            "    assert compute_backoff(1, 1.0, 30.0) == 2.0\n"
        ),
    }
    t5_patch = (
        "diff --git a/retry.py b/retry.py\n"
        "--- a/retry.py\n"
        "+++ b/retry.py\n"
        "@@ -7,2 +7,2 @@\n"
        "-    return status_code in (429, 502, 503, 504)\n"
        "+    return status_code in (408, 429, 502, 503, 504)\n"
    )
    tasks.append(
        FixtureTask(
            task_id="retry_policy_manager",
            summary="Retry scheduler: computes exponential backoff for transient network errors.",
            base_files=t5_base,
            gold_patch=t5_patch,
            problem_statement="Include HTTP 408 Request Timeout in retryable status codes.",
            default_leak="return status_code in (408, 429, 502, 503, 504)",
            default_decoy="# Network resilience: backoff schedules prevent downstream thundering herds.",
        )
    )

    # Task 6: Payment Timeout Handler
    t6_base = {
        "timeout.py": (
            "def get_gateway_timeout(endpoint: str) -> int:\n"
            "    timeouts = {\n"
            '        "charge": 15,\n'
            '        "refund": 20,\n'
            '        "verify": 5,\n'
            "    }\n"
            '    return timeouts.get(endpoint, 10)\n'
        ),
        "README.md": (
            "# Payment Timeout Handler\n\n"
            "Defines socket connection and request timeouts for payment gateway endpoints.\n"
        ),
        "config.py": (
            "GATEWAY_HOST = 'api.payment-gateway.internal'\n"
            "CONNECT_TIMEOUT = 3\n"
        ),
        "tests/test_timeout.py": (
            "from timeout import get_gateway_timeout\n\n"
            "def test_charge_timeout():\n"
            '    assert get_gateway_timeout("charge") == 15\n'
        ),
    }
    t6_patch = (
        "diff --git a/timeout.py b/timeout.py\n"
        "--- a/timeout.py\n"
        "+++ b/timeout.py\n"
        "@@ -3,2 +3,3 @@\n"
        '         "charge": 15,\n'
        '+        "settle": 30,\n'
    )
    tasks.append(
        FixtureTask(
            task_id="payment_timeout_handler",
            summary="Connection timeout manager: enforces maximum wait times for external payment endpoints.",
            base_files=t6_base,
            gold_patch=t6_patch,
            problem_statement="Add a 30-second timeout for the new batch 'settle' payment endpoint.",
            default_leak='"settle": 30,',
            default_decoy="# Operational telemetry: timeout events trigger automated alerting rules.",
        )
    )

    # Task 7: Web Authentication Service
    t7_base = {
        "auth.py": (
            "import re\n\n"
            "def validate_bearer_token(header_val: str) -> str | None:\n"
            '    pattern = r"^Bearer\\s+([a-zA-Z0-9_.-]{16,128})$"\n'
            "    m = re.match(pattern, header_val)\n"
            "    if not m:\n"
            "        return None\n"
            "    return m.group(1)\n"
        ),
        "README.md": (
            "# Web Authentication Service\n\n"
            "Validates HTTP Bearer authorization headers and extracts session tokens.\n"
        ),
        "config.py": (
            "TOKEN_EXPIRY_HOURS = 24\n"
            "ALGORITHM = 'HS256'\n"
        ),
        "tests/test_auth.py": (
            "from auth import validate_bearer_token\n\n"
            "def test_valid_token():\n"
            '    assert validate_bearer_token("Bearer abc123def456ghi789") is not None\n'
        ),
    }
    t7_patch = (
        "diff --git a/auth.py b/auth.py\n"
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -3,2 +3,2 @@\n"
        '-    pattern = r"^Bearer\\s+([a-zA-Z0-9_.-]{16,128})$"\n'
        '+    pattern = r"^Bearer\\s+([a-zA-Z0-9_.~-]{16,128})$"\n'
    )
    tasks.append(
        FixtureTask(
            task_id="web_auth_service",
            summary="Web authentication service: validates bearer tokens and session headers.",
            base_files=t7_base,
            gold_patch=t7_patch,
            problem_statement="Allow tilde '~' characters in OAuth 2.0 unreserved token character set.",
            default_leak='pattern = r"^Bearer\\s+([a-zA-Z0-9_.~-]{16,128})$"',
            default_decoy="# Security notice: header parsing strictly follows RFC 6750 specifications.",
        )
    )

    # Task 8: CSV Data Pipeline
    t8_base = {
        "pipeline.py": (
            "def sanitize_record(row: dict[str, str]) -> dict[str, str]:\n"
            "    cleaned = {}\n"
            "    for k, v in row.items():\n"
            "        cleaned[k.strip().lower()] = v.strip()\n"
            "    return cleaned\n"
        ),
        "README.md": (
            "# CSV Data Pipeline\n\n"
            "Transforms and sanitizes incoming batch CSV rows for database staging.\n"
        ),
        "config.py": (
            "DELIMITER = ','\n"
            "MAX_LINE_LENGTH = 4096\n"
        ),
        "tests/test_pipeline.py": (
            "from pipeline import sanitize_record\n\n"
            "def test_sanitize():\n"
            '    assert sanitize_record({" Email ": " user@domain.com "}) == {"email": "user@domain.com"}\n'
        ),
    }
    t8_patch = (
        "diff --git a/pipeline.py b/pipeline.py\n"
        "--- a/pipeline.py\n"
        "+++ b/pipeline.py\n"
        "@@ -4,2 +4,4 @@\n"
        "     for k, v in row.items():\n"
        "+        if not k.strip():\n"
        "+            continue\n"
    )
    tasks.append(
        FixtureTask(
            task_id="csv_data_pipeline",
            summary="CSV data pipeline: cleans, normalizes, and filters imported dataset records.",
            base_files=t8_base,
            gold_patch=t8_patch,
            problem_statement="Skip blank or whitespace-only column headers when parsing CSV records.",
            default_leak="if not k.strip():\n            continue",
            default_decoy="# Data hygiene note: all columns are normalized to lowercase snake_case.",
        )
    )

    # Task 9: SQL Query Optimizer
    t9_base = {
        "optimizer.py": (
            "def should_use_index(estimated_rows: int, total_table_rows: int) -> bool:\n"
            "    if total_table_rows <= 100:\n"
            "        return False\n"
            "    selectivity = estimated_rows / total_table_rows\n"
            "    return selectivity <= 0.15\n"
        ),
        "README.md": (
            "# SQL Query Optimizer\n\n"
            "Heuristic planner that chooses between sequential table scans and index scans.\n"
        ),
        "config.py": (
            "SMALL_TABLE_THRESHOLD = 100\n"
            "PARALLEL_QUERY_ENABLED = True\n"
        ),
        "tests/test_optimizer.py": (
            "from optimizer import should_use_index\n\n"
            "def test_index_choice():\n"
            "    assert should_use_index(50, 1000) is True\n"
        ),
    }
    t9_patch = (
        "diff --git a/optimizer.py b/optimizer.py\n"
        "--- a/optimizer.py\n"
        "+++ b/optimizer.py\n"
        "@@ -5,2 +5,2 @@\n"
        "-    return selectivity <= 0.15\n"
        "+    return selectivity <= 0.20\n"
    )
    tasks.append(
        FixtureTask(
            task_id="sql_query_optimizer",
            summary="SQL query optimizer: estimates table scan costs and selects candidate indexes.",
            base_files=t9_base,
            gold_patch=t9_patch,
            problem_statement="Increase index selectivity cutoff from 15% to 20% for SSD storage.",
            default_leak="return selectivity <= 0.20",
            default_decoy="# Storage formula: sequential disk reads assume NVMe storage throughput.",
        )
    )

    # Task 10: Matrix Arithmetic Library
    t10_base = {
        "matrix.py": (
            "def determinant_2x2(m: list[list[float]]) -> float:\n"
            "    # Matrix m is 2x2: [[a, b], [c, d]]\n"
            "    a, b = m[0][0], m[0][1]\n"
            "    c, d = m[1][0], m[1][1]\n"
            "    return round(a * d - b * c, 6)\n"
        ),
        "README.md": (
            "# Matrix Arithmetic Library\n\n"
            "Provides small-matrix arithmetic primitives for numerical coordinate transforms.\n"
        ),
        "config.py": (
            "FLOAT_PRECISION = 6\n"
            "EPSILON = 1e-9\n"
        ),
        "tests/test_matrix.py": (
            "from matrix import determinant_2x2\n\n"
            "def test_det():\n"
            "    assert determinant_2x2([[1, 2], [3, 4]]) == -2.0\n"
        ),
    }
    t10_patch = (
        "diff --git a/matrix.py b/matrix.py\n"
        "--- a/matrix.py\n"
        "+++ b/matrix.py\n"
        "@@ -4,2 +4,5 @@\n"
        "     c, d = m[1][0], m[1][1]\n"
        "+    if abs(a * d - b * c) < 1e-12:\n"
        "+        return 0.0\n"
        "     return round(a * d - b * c, 6)\n"
    )
    tasks.append(
        FixtureTask(
            task_id="matrix_arithmetic_lib",
            summary="Matrix arithmetic library: computes determinants and geometric transformations.",
            base_files=t10_base,
            gold_patch=t10_patch,
            problem_statement="Snap near-zero determinant values below 1e-12 to exact 0.0 float.",
            default_leak="if abs(a * d - b * c) < 1e-12:\n        return 0.0",
            default_decoy="# Linear algebra: matrices with determinant 0 are singular and non-invertible.",
        )
    )

    # Task 11: CLI Argument Validator
    t11_base = {
        "cli.py": (
            "def parse_port(port_str: str) -> int:\n"
            "    port = int(port_str)\n"
            "    if port < 1 or port > 65535:\n"
            '        raise ValueError("Port out of valid range 1-65535")\n'
            "    return port\n"
        ),
        "README.md": (
            "# CLI Argument Validator\n\n"
            "Validates user-supplied terminal arguments and port configuration options.\n"
        ),
        "config.py": (
            "DEFAULT_PORT = 8080\n"
            "ALLOW_PRIVILEGED_PORTS = False\n"
        ),
        "tests/test_cli.py": (
            "from cli import parse_port\n\n"
            "def test_port():\n"
            "    assert parse_port('8080') == 8080\n"
        ),
    }
    t11_patch = (
        "diff --git a/cli.py b/cli.py\n"
        "--- a/cli.py\n"
        "+++ b/cli.py\n"
        "@@ -2,3 +2,3 @@\n"
        "     port = int(port_str)\n"
        "-    if port < 1 or port > 65535:\n"
        "+    if port < 1024 or port > 65535:\n"
    )
    tasks.append(
        FixtureTask(
            task_id="cli_argument_validator",
            summary="CLI argument validator: parses flags, options, and network port boundaries.",
            base_files=t11_base,
            gold_patch=t11_patch,
            problem_statement="Enforce unprivileged port minimum 1024 when running without root privileges.",
            default_leak="if port < 1024 or port > 65535:",
            default_decoy="# Unix convention: ports below 1024 require CAP_NET_BIND_SERVICE capability.",
        )
    )

    # Task 12: LRU Cache Manager
    t12_base = {
        "cache.py": (
            "from collections import OrderedDict\n\n"
            "class SimpleCache:\n"
            "    def __init__(self, capacity: int = 100):\n"
            "        self.capacity = capacity\n"
            "        self.store = OrderedDict()\n\n"
            "    def get(self, key: str) -> str | None:\n"
            "        if key not in self.store:\n"
            "            return None\n"
            "        self.store.move_to_end(key)\n"
            "        return self.store[key]\n"
        ),
        "README.md": (
            "# LRU Cache Manager\n\n"
            "In-memory least-recently-used cache with entry eviction and key tracking.\n"
        ),
        "config.py": (
            "DEFAULT_CAPACITY = 100\n"
            "TTL_SECONDS = 300\n"
        ),
        "tests/test_cache.py": (
            "from cache import SimpleCache\n\n"
            "def test_cache_miss():\n"
            '    c = SimpleCache()\n'
            '    assert c.get("missing") is None\n'
        ),
    }
    t12_patch = (
        "diff --git a/cache.py b/cache.py\n"
        "--- a/cache.py\n"
        "+++ b/cache.py\n"
        "@@ -10,2 +10,6 @@\n"
        "         return self.store[key]\n"
        "+\n"
        "+    def put(self, key: str, val: str) -> None:\n"
        "+        self.store[key] = val\n"
        "+        if len(self.store) > self.capacity:\n"
        "+            self.store.popitem(last=False)\n"
    )
    tasks.append(
        FixtureTask(
            task_id="lru_cache_manager",
            summary="LRU cache manager: coordinates memory cache capacity and oldest item eviction.",
            base_files=t12_base,
            gold_patch=t12_patch,
            problem_statement="Implement the put method to store values and evict oldest when over capacity.",
            default_leak="def put(self, key: str, val: str) -> None:\n        self.store[key] = val",
            default_decoy="# Performance cache note: OrderedDict popitem(last=False) performs in O(1) time.",
        )
    )

    # Task 13: Customer Validator (Deletion Task)
    t13_base = {
        "validator.py": (
            "import re\n\n"
            "def validate_customer_id(customer_id: str) -> bool:\n"
            '    pattern = r"^[a-zA-Z0-9_-]{3,32}$"\n'
            '    return bool(re.match(r"^[a-zA-Z0-9_-]{3,32}$", customer_id))\n'
        ),
        "README.md": "# Customer Validator\n\nValidates customer identifier format constraints.\n",
        "config.py": "SERVICE_NAME = 'validator'\n",
        "tests/test_validator.py": (
            "from validator import validate_customer_id\n\n"
            "def test_valid():\n"
            '    assert validate_customer_id("cust_123") is True\n'
        ),
    }
    t13_patch = (
        "diff --git a/validator.py b/validator.py\n"
        "--- a/validator.py\n"
        "+++ b/validator.py\n"
        "@@ -3,2 +3,1 @@\n"
        '-    pattern = r"^[a-zA-Z0-9_-]{3,32}$"\n'
        '     return bool(re.match(r"^[a-zA-Z0-9_-]{3,32}$", customer_id))\n'
    )
    tasks.append(
        FixtureTask(
            task_id="synth_del_redundant_pattern",
            summary="Customer validator service: removes redundant regex assignment to streamline customer validation.",
            base_files=t13_base,
            gold_patch=t13_patch,
            problem_statement="Remove the unused pattern assignment in customer ID validation.",
            default_leak='return bool(re.match(r"^[a-zA-Z0-9_-]{3,32}$", customer_id))',
            default_decoy="# Validation rule: customer identifiers must be between 3 and 32 characters.",
        )
    )

    # Task 14: Revenue Projection Engine (Deletion Task)
    t14_base = {
        "projection.py": (
            "def estimate_future_growth(current_revenue: float, monthly_growth_rate: float, months: int) -> float:\n"
            "    projections: list[float] = []\n"
            "    current = current_revenue\n"
            "    for _ in range(months):\n"
            "        current *= 1.0 + monthly_growth_rate\n"
            "    return round(current, 2)\n"
        ),
        "README.md": "# Revenue Projection Engine\n\nProjects compound monthly revenue growth.\n",
        "config.py": "PROJECTION_MONTHS = 12\n",
        "tests/test_projection.py": (
            "from projection import estimate_future_growth\n\n"
            "def test_growth():\n"
            "    assert estimate_future_growth(100.0, 0.10, 1) == 110.0\n"
        ),
    }
    t14_patch = (
        "diff --git a/projection.py b/projection.py\n"
        "--- a/projection.py\n"
        "+++ b/projection.py\n"
        "@@ -2,2 +2,1 @@\n"
        "-    projections: list[float] = []\n"
        "     current = current_revenue\n"
    )
    tasks.append(
        FixtureTask(
            task_id="synth_del_empty_projections",
            summary="Revenue projection engine: removes redundant list allocation in revenue estimation.",
            base_files=t14_base,
            gold_patch=t14_patch,
            problem_statement="Remove redundant projections list allocation in estimate_future_growth.",
            default_leak="current = current_revenue\n    for _ in range(months):",
            default_decoy="# Calculation rule: growth compounding uses monthly intervals.",
        )
    )

    # Task 15: Volume Discount Service (One-Character Modification)
    t15_base = {
        "discount.py": (
            "def compute_volume_discount(subtotal: float) -> float:\n"
            "    discount_rate: float = 0.05\n"
            "    return round(subtotal * discount_rate, 2)\n"
        ),
        "README.md": "# Volume Discount Service\n\nComputes percentage discounts for high-volume customer accounts.\n",
        "config.py": "MIN_VOLUME = 1000\n",
        "tests/test_discount.py": (
            "from discount import compute_volume_discount\n\n"
            "def test_discount():\n"
            "    assert compute_volume_discount(100.0) == 6.0\n"
        ),
    }
    t15_patch = (
        "diff --git a/discount.py b/discount.py\n"
        "--- a/discount.py\n"
        "+++ b/discount.py\n"
        "@@ -2,1 +2,1 @@\n"
        "-    discount_rate: float = 0.05\n"
        "+    discount_rate: float = 0.06\n"
    )
    tasks.append(
        FixtureTask(
            task_id="synth_char_discount_rate",
            summary="Volume discount service: adjusts numeric discount threshold from 5 to 6 in billing calculation.",
            base_files=t15_base,
            gold_patch=t15_patch,
            problem_statement="Update base volume discount rate from 0.05 to 0.06.",
            default_leak="discount_rate: float = 0.06",
            default_decoy="# Tier policy: customer discounts apply to gross subtotal.",
        )
    )

    # Task 16: Connection Policy Manager (One-Character Modification)
    t16_base = {
        "policy.py": (
            "class ConnectionPolicy:\n"
            "    timeout_seconds: int = 30\n"
            "    max_retries: int = 3\n\n"
            "def get_retry_limit() -> int:\n"
            "    return ConnectionPolicy.max_retries\n"
        ),
        "README.md": "# Connection Policy\n\nDefines network timeout and retry limits.\n",
        "config.py": "BACKOFF_FACTOR = 2.0\n",
        "tests/test_policy.py": (
            "from policy import get_retry_limit\n\n"
            "def test_retries():\n"
            "    assert get_retry_limit() == 5\n"
        ),
    }
    t16_patch = (
        "diff --git a/policy.py b/policy.py\n"
        "--- a/policy.py\n"
        "+++ b/policy.py\n"
        "@@ -3,1 +3,1 @@\n"
        "-    max_retries: int = 3\n"
        "+    max_retries: int = 5\n"
    )
    tasks.append(
        FixtureTask(
            task_id="synth_char_max_retries",
            summary="Connection retry policy: updates maximum retry count from 3 to 5 in service configuration.",
            base_files=t16_base,
            gold_patch=t16_patch,
            problem_statement="Increase maximum retries from 3 to 5 in ConnectionPolicy.",
            default_leak="max_retries: int = 5",
            default_decoy="# Resiliency note: backoff intervals expand exponentially per attempt.",
        )
    )

    return tasks


FIXTURE_CATALOG: list[FixtureTask] = _make_fixture_tasks()


def _bounded_read_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    """Read a text file with strict bounds, never following symlinks."""
    if path.is_symlink():
        raise PermissionError(f"Symlink refused: {path.name}")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Not a regular file: {path.name}")
    if st.st_size > max_bytes:
        raise ValueError(f"File size exceeds limit: {path.name}")

    chunks: list[bytes] = []
    total = 0
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        while True:
            chunk = os.read(fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"Exceeded read budget: {path.name}")
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8", errors="replace")


def load_tasks_from_dir(tasks_dir: Path, count: int = 12) -> list[FixtureTask]:
    """Load task worlds from a directory containing task subdirectories."""
    if not tasks_dir.is_dir() or tasks_dir.is_symlink():
        return []

    discovered: list[FixtureTask] = []
    for entry in sorted(tasks_dir.iterdir()):
        if not entry.is_dir() or entry.is_symlink():
            continue
        task_json_path = entry / "task.json"
        if not task_json_path.is_file() or task_json_path.is_symlink():
            continue

        try:
            task_data = json.loads(_bounded_read_text(task_json_path))
            instance_id = str(task_data.get("instance_id", entry.name))

            # Problem statement
            ps_path = entry / "agent" / "problem_statement.md"
            problem_statement = (
                _bounded_read_text(ps_path).strip()
                if ps_path.is_file() and not ps_path.is_symlink()
                else f"Task {instance_id} problem statement."
            )

            # Summary: first sentence of problem statement
            first_line = problem_statement.splitlines()[0] if problem_statement else instance_id
            first_sentence = first_line.split(". ")[0].strip()
            if not first_sentence.endswith("."):
                first_sentence += "."
            summary = f"{instance_id}: {first_sentence}"

            # Gold patch
            gold_path = entry / "staging" / "gold.patch"
            gold_patch = (
                _bounded_read_text(gold_path)
                if gold_path.is_file() and not gold_path.is_symlink()
                else ""
            )

            # Default leak: first non-empty added line from gold patch
            default_leak = f"Fix for {instance_id}"
            for line in gold_patch.splitlines():
                if line.startswith("+") and not line.startswith("+++"):
                    cleaned = line[1:].strip()
                    if len(cleaned) > 4:
                        default_leak = cleaned
                        break

            # Base files
            base_files: dict[str, str] = {}
            base_tree = entry / "base_tree"
            if base_tree.is_dir() and not base_tree.is_symlink():
                for root, _, files in os.walk(str(base_tree), followlinks=False):
                    for f in files:
                        fp = Path(root) / f
                        if fp.is_file() and not fp.is_symlink():
                            rel = fp.relative_to(base_tree).as_posix()
                            base_files[rel] = _bounded_read_text(fp)

            if not base_files:
                base_files["README.md"] = f"# {instance_id}\n"

            discovered.append(
                FixtureTask(
                    task_id=instance_id,
                    summary=summary,
                    base_files=base_files,
                    gold_patch=gold_patch,
                    problem_statement=problem_statement,
                    default_leak=default_leak,
                    default_decoy=f"# Diagnostic verification for {instance_id}.",
                )
            )
            if len(discovered) >= count:
                break
        except Exception:
            continue

    return discovered


def get_fixture_tasks(
    count: int = 12,
    tasks_dir: Path | None = None,
) -> list[FixtureTask]:
    """Return requested number of fixture task worlds (clamped between 10 and 20)."""
    count = max(10, min(20, count))
    if tasks_dir is not None:
        loaded = load_tasks_from_dir(tasks_dir, count)
        if len(loaded) >= 10:
            return loaded[:count]
        elif loaded:
            # Pad with catalog tasks if needed
            needed = count - len(loaded)
            return loaded + get_fixture_tasks(needed)

    catalog = list(FIXTURE_CATALOG)
    # If count exceeds catalogue size, duplicate with suffix to reach desired count
    result: list[FixtureTask] = []
    idx = 0
    while len(result) < count:
        base_task = catalog[idx % len(catalog)]
        suffix = f"_v{idx // len(catalog) + 1}" if idx >= len(catalog) else ""
        if suffix:
            t = FixtureTask(
                task_id=f"{base_task.task_id}{suffix}",
                summary=base_task.summary,
                base_files=dict(base_task.base_files),
                gold_patch=base_task.gold_patch,
                problem_statement=base_task.problem_statement,
                default_leak=base_task.default_leak,
                default_decoy=base_task.default_decoy,
            )
        else:
            t = base_task
        result.append(t)
        idx += 1
    return result


def materialize_task(task: FixtureTask, target_dir: Path) -> Path:
    """Write the complete task directory structure required by sealcheck.

    Creates:
      <target_dir>/task.json
      <target_dir>/staging/gold.patch
      <target_dir>/staging/test.patch
      <target_dir>/staging/hints.txt
      <target_dir>/agent/problem_statement.md
      <target_dir>/base_tree/... (all base files)
    """
    task_dir = target_dir / task.task_id
    base_tree_dir = task_dir / "base_tree"
    staging_dir = task_dir / "staging"
    agent_dir = task_dir / "agent"

    base_tree_dir.mkdir(parents=True, exist_ok=True)
    staging_dir.mkdir(parents=True, exist_ok=True)
    agent_dir.mkdir(parents=True, exist_ok=True)

    # 1. Base files
    for rel_path, content in task.base_files.items():
        file_path = base_tree_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="\n")

    # 2. Staging files
    (staging_dir / "gold.patch").write_text(task.gold_patch, encoding="utf-8", newline="\n")
    (staging_dir / "test.patch").write_text("", encoding="utf-8", newline="\n")
    (staging_dir / "hints.txt").write_text("", encoding="utf-8", newline="\n")

    # 3. Agent problem statement
    (agent_dir / "problem_statement.md").write_text(
        task.problem_statement + "\n", encoding="utf-8", newline="\n"
    )

    # 4. task.json
    task_meta = {
        "instance_id": task.task_id,
        "base_commit": "synthetic_base_0",
        "repo": f"hermetic/{task.task_id}",
        "cutoffs": {
            "t_world": "2030-01-01T00:00:00Z",
            "t_clock": "2030-01-01T00:00:00Z",
            "discarded": [],
        },
    }
    (task_dir / "task.json").write_text(
        json.dumps(task_meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return task_dir
