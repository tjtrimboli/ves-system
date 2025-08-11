"""NIST LEV (Likely Exploited Vulnerabilities) Calculator"""

import logging
from datetime import datetime, timedelta
from typing import Dict
from aiohttp import ClientSession

from ..config.settings import VESConfig


class LEVCalculator:
    """NIST LEV calculation engine"""
    
    def __init__(self, session: ClientSession, config: VESConfig):
        self.session = session
        self.config = config
        self.epss_cache: Dict[str, Dict[str, float]] = {}
    
    async def calculate_lev_score(self, cve_id: str, start_date: datetime, 
                                 end_date: datetime) -> float:
        """Calculate LEV score using NIST methodology"""
        try:
            current_date = start_date
            product_term = 1.0
            
            while current_date <= end_date:
                window_end = min(current_date + timedelta(days=30), end_date)
                window_days = (window_end - current_date).days
                
                epss_score = await self.get_historical_epss(cve_id, current_date)
                weight = window_days / 30.0 if window_days < 30 else 1.0
                
                product_term *= (1 - epss_score * weight)
                current_date = window_end
            
            lev_score = 1 - product_term
            return min(max(lev_score, 0.0), 1.0)
            
        except Exception as e:
            logging.warning(f"LEV calculation failed for {cve_id}: {e}")
            return 0.0
    
    async def get_historical_epss(self, cve_id: str, date: datetime) -> float:
        """Get historical EPSS score for specific CVE and date"""
        date_str = date.strftime('%Y-%m-%d')
        
        if cve_id in self.epss_cache and date_str in self.epss_cache[cve_id]:
            return self.epss_cache[cve_id][date_str]
        
        try:
            url = f"{self.config.epss_base_url}?cve={cve_id}&date={date_str}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('data') and len(data['data']) > 0:
                        epss_score = float(data['data'][0].get('epss', 0.0))
                        
                        if cve_id not in self.epss_cache:
                            self.epss_cache[cve_id] = {}
                        self.epss_cache[cve_id][date_str] = epss_score
                        
                        return epss_score
        except Exception as e:
            logging.warning(f"Failed to get historical EPSS for {cve_id} on {date_str}: {e}")
        
        return 0.0
