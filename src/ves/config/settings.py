"""VES Configuration Management with .env file support"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


@dataclass
class VESConfig:
    """VES System Configuration"""
    nvd_api_key: Optional[str] = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    epss_base_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    rate_limit_delay: float = 6.0
    max_concurrent_requests: int = 10
    cache_ttl: int = 3600
    log_level: str = "INFO"
    
    @classmethod
    def from_env(cls, env_file: Optional[str] = None) -> 'VESConfig':
        """Load configuration from environment variables and .env file"""
        
        # Try to load .env file
        if DOTENV_AVAILABLE:
            # Look for .env file in current directory or specified path
            if env_file:
                env_path = Path(env_file)
            else:
                # Look for .env in current directory and parent directories
                current_dir = Path.cwd()
                env_path = None
                
                # Check current directory and up to 3 parent directories
                for path in [current_dir] + list(current_dir.parents)[:3]:
                    potential_env = path / ".env"
                    if potential_env.exists():
                        env_path = potential_env
                        break
            
            # Load the .env file if found
            if env_path and env_path.exists():
                load_dotenv(env_path)
                print(f"🔧 Loaded configuration from {env_path}")
            elif env_file:
                print(f"⚠️  Warning: Specified .env file not found: {env_file}")
        
        return cls(
            nvd_api_key=os.getenv('NVD_API_KEY'),
            nvd_base_url=os.getenv('VES_NVD_BASE_URL', 
                                  "https://services.nvd.nist.gov/rest/json/cves/2.0"),
            epss_base_url=os.getenv('VES_EPSS_BASE_URL', 
                                   "https://api.first.org/data/v1/epss"),
            kev_url=os.getenv('VES_KEV_URL', 
                             "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
            rate_limit_delay=float(os.getenv('VES_RATE_LIMIT_DELAY', '6.0')),
            max_concurrent_requests=int(os.getenv('VES_MAX_CONCURRENT', '10')),
            cache_ttl=int(os.getenv('VES_CACHE_TTL', '3600')),
            log_level=os.getenv('VES_LOG_LEVEL', 'INFO')
        )
    
    def validate(self) -> list[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        if not self.nvd_api_key:
            issues.append("NVD API key not set - will be rate limited to 5 requests/30s")
        
        if self.rate_limit_delay < 6.0 and self.nvd_api_key:
            issues.append("Rate limit delay may be too aggressive for NVD API")
        
        if self.max_concurrent_requests > 10 and not self.nvd_api_key:
            issues.append("High concurrency without API key will cause failures")
        
        if self.rate_limit_delay <= 0:
            issues.append("Rate limit delay must be positive")
        
        if self.max_concurrent_requests <= 0:
            issues.append("Max concurrent requests must be positive")
        
        if self.cache_ttl <= 0:
            issues.append("Cache TTL must be positive")
        
        return issues
