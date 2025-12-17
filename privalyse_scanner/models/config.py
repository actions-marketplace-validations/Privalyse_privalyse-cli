"""Scanner configuration models"""

from dataclasses import dataclass, field
from typing import List, Optional, Set
from pathlib import Path


@dataclass
class ScanConfig:
    """Configuration for scanner execution"""
    
    # Paths and filters
    root_path: Path = field(default_factory=lambda: Path.cwd())
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "*/node_modules/*", "*/venv/*", "*/env/*", "*/.venv/*", "*/dist/*",
        "*/build/*", "*/__pycache__/*", "*/.git/*", "*/site-packages/*",
        "*/demo_stage/*", "*/tests/*", "*/scan_results.json"
    ])
    
    # Performance
    max_workers: int = 8
    max_files: Optional[int] = None
    max_file_size: int = 5_000_000  # 5MB default
    
    # Output
    verbose: bool = False
    debug: bool = False
    
    # Language support
    python_extensions: Set[str] = field(default_factory=lambda: {'.py', '.pyw'})
    js_extensions: Set[str] = field(default_factory=lambda: {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'})
    config_extensions: Set[str] = field(default_factory=lambda: {'.json', '.yaml', '.yml', '.toml', '.ini', '.env'})
    docker_files: Set[str] = field(default_factory=lambda: {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'})
    
    def __post_init__(self):
        """Convert paths to Path objects"""
        if not isinstance(self.root_path, Path):
            self.root_path = Path(self.root_path)
