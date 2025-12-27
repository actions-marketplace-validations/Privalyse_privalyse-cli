"""
Custom Rules Engine for Privalyse

Allows users to define their own detection rules in privalyse.toml
while seamlessly merging with built-in rules.
"""

import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class CustomRule:
    """User-defined detection rule"""
    id: str
    pattern: str  # Regex pattern
    severity: str = "medium"
    message: str = ""
    category: str = "custom"
    
    # Optional: Only match in specific contexts
    file_patterns: List[str] = field(default_factory=list)  # e.g., ["*.py", "*.js"]
    exclude_patterns: List[str] = field(default_factory=list)  # e.g., ["*_test.py"]
    
    # Compiled regex (set on post_init)
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)
    
    def __post_init__(self):
        try:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        except re.error as e:
            logger.warning(f"Invalid regex in custom rule '{self.id}': {e}")
            self._compiled = None
    
    def matches(self, text: str) -> Optional[re.Match]:
        """Check if text matches this rule's pattern"""
        if self._compiled is None:
            return None
        return self._compiled.search(text)
    
    def applies_to_file(self, filename: str) -> bool:
        """Check if this rule should apply to the given file"""
        import fnmatch
        
        # If no file patterns specified, apply to all files
        if not self.file_patterns:
            include = True
        else:
            include = any(fnmatch.fnmatch(filename, pat) for pat in self.file_patterns)
        
        # Check exclusions
        if self.exclude_patterns:
            if any(fnmatch.fnmatch(filename, pat) for pat in self.exclude_patterns):
                return False
        
        return include


class CustomRulesEngine:
    """
    Manages custom rules defined in privalyse.toml
    
    Example config:
    ```toml
    [[rules]]
    id = "INTERNAL_TOKEN"
    pattern = "ACME-[A-Z0-9]{10}"
    severity = "critical"
    message = "Internal ACME token detected"
    
    [[rules]]
    id = "DEBUG_FLAG"
    pattern = "DEBUG\\s*=\\s*True"
    severity = "medium"
    message = "Debug flag enabled in production code"
    file_patterns = ["*.py"]
    exclude_patterns = ["*_test.py", "test_*.py"]
    ```
    """
    
    def __init__(self, rules: List[CustomRule] = None):
        self.rules: List[CustomRule] = rules or []
    
    @classmethod
    def from_config(cls, config_data: Dict[str, Any]) -> 'CustomRulesEngine':
        """
        Create engine from parsed TOML config.
        
        Args:
            config_data: Parsed privalyse.toml content
        
        Returns:
            CustomRulesEngine instance with loaded rules
        """
        rules = []
        
        rules_data = config_data.get('rules', [])
        if not isinstance(rules_data, list):
            logger.warning("'rules' in config should be a list of [[rules]] tables")
            return cls([])
        
        for rule_data in rules_data:
            if not isinstance(rule_data, dict):
                continue
            
            # Required fields
            rule_id = rule_data.get('id')
            pattern = rule_data.get('pattern')
            
            if not rule_id or not pattern:
                logger.warning(f"Custom rule missing 'id' or 'pattern': {rule_data}")
                continue
            
            rule = CustomRule(
                id=rule_id,
                pattern=pattern,
                severity=rule_data.get('severity', 'medium').lower(),
                message=rule_data.get('message', f'Custom rule {rule_id} triggered'),
                category=rule_data.get('category', 'custom'),
                file_patterns=rule_data.get('file_patterns', []),
                exclude_patterns=rule_data.get('exclude_patterns', [])
            )
            
            if rule._compiled:  # Only add if regex compiled successfully
                rules.append(rule)
                logger.debug(f"Loaded custom rule: {rule_id}")
        
        if rules:
            logger.info(f"Loaded {len(rules)} custom rules from config")
        
        return cls(rules)
    
    def scan_text(self, text: str, filename: str = "") -> List[Dict[str, Any]]:
        """
        Scan text against all custom rules.
        
        Args:
            text: Code or text to scan
            filename: Optional filename for file-pattern filtering
        
        Returns:
            List of matches with rule info and match details
        """
        matches = []
        
        for rule in self.rules:
            # Check if rule applies to this file
            if filename and not rule.applies_to_file(filename):
                continue
            
            # Find all matches
            if rule._compiled:
                for match in rule._compiled.finditer(text):
                    # Calculate line number
                    line_num = text[:match.start()].count('\n') + 1
                    
                    matches.append({
                        'rule_id': rule.id,
                        'severity': rule.severity,
                        'message': rule.message,
                        'category': rule.category,
                        'match': match.group(),
                        'line': line_num,
                        'start': match.start(),
                        'end': match.end()
                    })
        
        return matches
    
    def has_rules(self) -> bool:
        """Check if any custom rules are loaded"""
        return len(self.rules) > 0
    
    def get_rule(self, rule_id: str) -> Optional[CustomRule]:
        """Get a specific rule by ID"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
