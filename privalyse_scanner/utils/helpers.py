"""Helper utilities for AST processing and filtering"""

import ast
import re
from typing import Optional


def extract_ast_snippet(code: str, node: ast.AST, max_length: int = 200) -> str:
    """
    Extract code snippet from AST node
    
    Args:
        code: Full source code
        node: AST node to extract snippet from
        max_length: Maximum snippet length
    
    Returns:
        Code snippet string
    """
    lines = code.splitlines()
    
    if not hasattr(node, 'lineno'):
        return ""
    
    start_line = max(0, node.lineno - 1)
    end_line = min(len(lines), getattr(node, 'end_lineno', node.lineno))
    
    snippet_lines = lines[start_line:end_line]
    snippet = ' '.join(line.strip() for line in snippet_lines)
    
    if len(snippet) > max_length:
        snippet = snippet[:max_length] + "..."
    
    return snippet


def should_filter_log_finding(snippet: str, context: str) -> bool:
    """
    Determine if a LOG_PII finding should be filtered
    
    Args:
        snippet: Code snippet
        context: Context description
    
    Returns:
        True if should be filtered (ignored)
    """
    system_log_patterns = [
        r"file content truncated:",
        r"permission denied:",
        r"error reading file",
        r"database connection established",
        r"health check passed",
        r"failed to get redis info",
        r"fetched \d+ results",
        r"storing workspace result",
        r"worker started",
        r"task.*completed"
    ]
    
    snippet_lower = snippet.lower()
    
    for pattern in system_log_patterns:
        if re.search(pattern, snippet_lower, re.I):
            return True
    
    return False


def should_filter_db_finding(snippet: str) -> bool:
    """
    Determine if a DB_WRITE finding should be filtered
    
    Args:
        snippet: Code snippet
    
    Returns:
        True if should be filtered (ignored)
    """
    very_safe_patterns = [
        r"select.*count\(\*\)",
        r"select.*version\(\)",
        r"savepoint|rollback|commit",
        r"vacuum|analyze"
    ]
    
    snippet_lower = snippet.lower()
    
    for pattern in very_safe_patterns:
        if re.search(pattern, snippet_lower, re.I):
            return True
    
    return False
