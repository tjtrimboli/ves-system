"""CISA KEV Catalog Client"""

import logging
import time
from typing import Optional, Set
from aiohttp import ClientSession

from ..config.settings import VESConfig


class KEVClient:
    """CISA KEV Catalog Client"""
    
    def __init__(self, session: ClientSession, config: VESConfig):
        self.session = session
        self.config = config
        self.kev_cache: Optional[Set[str]] = None
        self.cache_timestamp = 0
    
    async def _refresh_kev_cache(self):
        """Refresh KEV catalog cache"""
        if (time.time() - self.cache_timestamp) < self.config.cache_ttl:
            return
        
        try:
            async with self.session.get(self.config.kev_url) as response:
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    self.kev_cache = {vuln['cveID'] for vuln in vulnerabilities}
                    self.cache_timestamp = time.time()
                    logging.info(f"Loaded {len(self.kev_cache)} CVEs from KEV catalog")
        except Exception as e:
            logging.error(f"Failed to load KEV catalog: {e}")
            if self.kev_cache is None:
                self.kev_cache = set()
    
    async def is_kev_vulnerability(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV catalog"""
        await self._refresh_kev_cache()
        return cve_id in self.kev_cache if self.kev_cache else False
