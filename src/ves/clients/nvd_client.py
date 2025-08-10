"""NVD API Client"""

import asyncio
import logging
import time
from typing import Dict, Optional
from aiohttp import ClientSession
from tenacity import retry, stop_after_attempt, wait_exponential

from ..config.settings import VESConfig


class NVDClient:
    """NVD API Client with rate limiting"""
    
    def __init__(self, session: ClientSession, config: VESConfig):
        self.session = session
        self.config = config
        self.last_request_time = 0
    
    async def _rate_limit(self):
        """Enforce rate limiting for NVD API"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.config.rate_limit_delay:
            await asyncio.sleep(self.config.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def get_cve_data(self, cve_id: str) -> Optional[Dict]:
        """Get CVE data from NVD API"""
        await self._rate_limit()
        
        headers = {}
        if self.config.nvd_api_key:
            headers['apiKey'] = self.config.nvd_api_key
        
        url = f"{self.config.nvd_base_url}?cveId={cve_id}"
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('vulnerabilities') and len(data['vulnerabilities']) > 0:
                        return data['vulnerabilities'][0]['cve']
                elif response.status == 404:
                    logging.warning(f"CVE {cve_id} not found in NVD")
                    return None
                else:
                    response.raise_for_status()
        except Exception as e:
            logging.error(f"NVD API error for {cve_id}: {e}")
            raise
        
        return None
