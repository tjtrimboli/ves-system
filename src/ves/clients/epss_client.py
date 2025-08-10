"""FIRST EPSS API Client"""

import logging
from typing import Optional, Tuple
from aiohttp import ClientSession
from tenacity import retry, stop_after_attempt, wait_exponential

from ..config.settings import VESConfig


class EPSSClient:
    """EPSS API Client"""
    
    def __init__(self, session: ClientSession, config: VESConfig):
        self.session = session
        self.config = config
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=8))
    async def get_epss_score(self, cve_id: str) -> Tuple[Optional[float], Optional[float]]:
        """Get current EPSS score and percentile"""
        url = f"{self.config.epss_base_url}?cve={cve_id}"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('data') and len(data['data']) > 0:
                        cve_data = data['data'][0]
                        epss_score = float(cve_data.get('epss', 0.0))
                        percentile = float(cve_data.get('percentile', 0.0))
                        return epss_score, percentile
        except Exception as e:
            logging.error(f"EPSS API error for {cve_id}: {e}")
        
        return None, None
