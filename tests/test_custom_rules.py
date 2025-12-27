"""Tests for custom rules engine"""

import unittest
import tempfile
from pathlib import Path

from privalyse_scanner.utils.custom_rules import CustomRule, CustomRulesEngine


class TestCustomRules(unittest.TestCase):
    """Test custom rules engine functionality"""

    def test_custom_rule_basic_match(self):
        """Test that a custom rule matches expected patterns"""
        rule = CustomRule(
            id="TEST_TOKEN",
            pattern=r"ACME-[A-Z0-9]{10}",
            severity="critical",
            message="Test token detected"
        )
        
        # Should match
        match = rule.matches("const token = 'ACME-ABC1234567'")
        self.assertIsNotNone(match)
        self.assertEqual(match.group(), "ACME-ABC1234567")
        
        # Should not match
        no_match = rule.matches("const token = 'regular-token'")
        self.assertIsNone(no_match)

    def test_custom_rule_file_patterns(self):
        """Test file pattern filtering"""
        rule = CustomRule(
            id="PY_ONLY",
            pattern=r"DEBUG\s*=\s*True",
            file_patterns=["*.py"],
            exclude_patterns=["*_test.py"]
        )
        
        # Should apply to Python files
        self.assertTrue(rule.applies_to_file("app.py"))
        self.assertTrue(rule.applies_to_file("src/main.py"))
        
        # Should not apply to JS files
        self.assertFalse(rule.applies_to_file("app.js"))
        
        # Should not apply to test files
        self.assertFalse(rule.applies_to_file("app_test.py"))

    def test_custom_rules_engine_from_config(self):
        """Test loading rules from config dict"""
        config = {
            "rules": [
                {
                    "id": "RULE_ONE",
                    "pattern": r"secret_key",
                    "severity": "high",
                    "message": "Secret key found"
                },
                {
                    "id": "RULE_TWO",
                    "pattern": r"password\s*=",
                    "severity": "critical"
                }
            ]
        }
        
        engine = CustomRulesEngine.from_config(config)
        
        self.assertTrue(engine.has_rules())
        self.assertEqual(len(engine.rules), 2)
        self.assertIsNotNone(engine.get_rule("RULE_ONE"))
        self.assertIsNotNone(engine.get_rule("RULE_TWO"))

    def test_custom_rules_engine_scan_text(self):
        """Test scanning text with multiple rules"""
        engine = CustomRulesEngine([
            CustomRule(id="TOKEN", pattern=r"TOKEN-[0-9]+", severity="high", message="Token found"),
            CustomRule(id="DEBUG", pattern=r"DEBUG=True", severity="medium", message="Debug enabled")
        ])
        
        code = """
TOKEN = "TOKEN-12345"
DEBUG=True
print("Hello")
TOKEN_2 = "TOKEN-67890"
"""
        
        matches = engine.scan_text(code, "test.py")
        
        # Should find 3 matches: 2 tokens + 1 debug flag
        self.assertEqual(len(matches), 3)
        
        # Check rule IDs
        rule_ids = [m['rule_id'] for m in matches]
        self.assertEqual(rule_ids.count('TOKEN'), 2)
        self.assertEqual(rule_ids.count('DEBUG'), 1)

    def test_custom_rules_engine_empty_config(self):
        """Test engine with no rules defined"""
        engine = CustomRulesEngine.from_config({})
        
        self.assertFalse(engine.has_rules())
        self.assertEqual(engine.scan_text("any code", "file.py"), [])

    def test_custom_rule_invalid_regex(self):
        """Test that invalid regex is handled gracefully"""
        # This should not raise an exception
        rule = CustomRule(
            id="BAD_REGEX",
            pattern=r"[invalid(",  # Invalid regex
            severity="high"
        )
        
        # Compiled pattern should be None
        self.assertIsNone(rule._compiled)
        
        # matches() should return None
        self.assertIsNone(rule.matches("any text"))

    def test_custom_rules_line_numbers(self):
        """Test that line numbers are correctly calculated"""
        engine = CustomRulesEngine([
            CustomRule(id="FIND_ME", pattern=r"FIND_ME", severity="high")
        ])
        
        code = """line 1
line 2
FIND_ME here
line 4
FIND_ME again
"""
        
        matches = engine.scan_text(code)
        
        self.assertEqual(len(matches), 2)
        self.assertEqual(matches[0]['line'], 3)
        self.assertEqual(matches[1]['line'], 5)


if __name__ == '__main__':
    unittest.main()
