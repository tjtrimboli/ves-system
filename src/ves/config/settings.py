"""VES Configuration Management"""

import os
from dataclasses import dataclass
from typing import Optional


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
    def from_env(cls) -> 'VESConfig':
        """Load configuration from environment variables"""
        return cls(
            nvd_api_key=os.getenv('NVD_API_KEY'),
            rate_limit_delay=float(os.getenv('VES_RATE_LIMIT_DELAY', '6.0')),
            max_concurrent_requests=int(os.getenv('VES_MAX_CONCURRENT', '10')),
            log_level=os.getenv('VES_LOG_LEVEL', 'INFO')
        )
