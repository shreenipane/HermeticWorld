"""Tests for hermetic_assert_flow.sites."""

from __future__ import annotations

import pytest

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.sites import list_assertion_sites


def test_sites_module_level_and_all_supported_assertion_forms() -> None:
    src = b"""
def helper_not_a_test():
    assert 1 == 1

def test_all_kinds(self):
    assert a == 1, "msg should not matter"
    self.assertEqual(a, b)
    self.assertNotEqual(a, c)
    self.assertTrue(flag)
    self.assertFalse(other_flag)
    self.assertIs(x, y)
    self.assertIsNone(z)
    self.assertIn(item, items)
    self.assertNotIn(item, other_items)  # unsupported -> ignored
"""
    sites = list_assertion_sites(src, "test_all_kinds")
    assert [s.site_id for s in sites] == [
        "test_all_kinds#0",
        "test_all_kinds#1",
        "test_all_kinds#2",
        "test_all_kinds#3",
        "test_all_kinds#4",
        "test_all_kinds#5",
        "test_all_kinds#6",
        "test_all_kinds#7",
    ]
    assert [s.kind for s in sites] == [
        "assert",
        "assertEqual",
        "assertNotEqual",
        "assertTrue",
        "assertFalse",
        "assertIs",
        "assertIsNone",
        "assertIn",
    ]


def test_sites_class_test_method() -> None:
    src = b"""
class NotATest:
    def test_ignored(self):
        assert 1 == 1

class TestSuite:
    def helper(self):
        assert 1 == 1

    def test_behavior(self):
        self.assertEqual(1, 1)
        assert 2 == 2
"""
    sites = list_assertion_sites(src, "TestSuite.test_behavior")
    assert [s.site_id for s in sites] == [
        "TestSuite.test_behavior#0",
        "TestSuite.test_behavior#1",
    ]


def test_sites_rejects_non_test_target_name() -> None:
    src = b"def helper():\n    assert True\n"
    with pytest.raises(FlowError) as exc_info:
        list_assertion_sites(src, "helper")
    assert exc_info.value.code == "INVALID_FUNCTION_NAME"


def test_sites_rejects_missing_function() -> None:
    src = b"def test_existing():\n    assert True\n"
    with pytest.raises(FlowError) as exc_info:
        list_assertion_sites(src, "test_missing")
    assert exc_info.value.code == "FUNCTION_NOT_FOUND"
