"""NIST LEV (Likely Exploited Vulnerabilities) Calculator"""

import asyncio
import logging
import time
from datetime import datetime, timedelta, date
from typing import Dict, List, Optional, Tuple
from aiohttp import ClientSession, ClientTimeout, ClientError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from ..config.settings import VESConfig


# Constants from NIST methodology
EPSS_START_DATE = date(2021, 4, 14)  # EPSS historical data start
WINDOW_DAYS = 30  # NIST LEV uses 30-day windows


class LEVCalculator:
    """Clean NIST LEV calculator with emoji-free logging"""
    
    def __init__(self, session: ClientSession, config: VESConfig):
        self.session = session
        self.config = config
        self.last_request_time = 0
    
    async def calculate_lev_score(self, cve_id: str, published_date: datetime, 
                                 end_date: datetime) -> float:
        """
        Calculate LEV score using proper NIST methodology:
        LEV = 1 - ∏_i (1 - epss(v, d_i) × weight_i)
        where d_i are 30-day window starts and weight_i handles partial windows
        """
        try:
            logging.info(f"Starting NIST LEV calculation for {cve_id}...")
            
            # Convert to date objects for calculation
            d0 = self._clamp_date(published_date.date())
            dn = end_date.date()
            
            if dn < d0:
                logging.warning(f"End date ({dn}) is before start date ({d0})")
                return 0.0
            
            logging.info(f"LEV calculation period:")
            logging.info(f"   d0 (start): {d0}")
            logging.info(f"   dn (end): {dn}")
            logging.info(f"   Total days: {(dn - d0).days}")
            
            # Generate 30-day window start dates
            window_starts = self._daterange(d0, dn, WINDOW_DAYS)
            logging.info(f"Processing {len(window_starts)} windows")
            
            # Fetch EPSS scores for each window start
            epss_by_window = []
            for window_start in window_starts:
                epss_score = await self._get_epss_score_on_date(cve_id, window_start)
                epss_by_window.append((window_start, epss_score))
                logging.debug(f"   Window {window_start}: EPSS = {epss_score:.6f}")
                
                # Small delay between requests for politeness
                await asyncio.sleep(0.5)
            
            # Apply NIST LEV formula
            return self._compute_lev_from_windows(epss_by_window, dn)
            
        except Exception as e:
            logging.error(f"LEV calculation failed for {cve_id}: {e}")
            return 0.0
    
    def _clamp_date(self, d: date) -> date:
        """Clamp date to EPSS availability floor"""
        return max(d, EPSS_START_DATE)
    
    def _daterange(self, start: date, end: date, step_days: int) -> List[date]:
        """Generate window start dates at fixed step until end"""
        dates = []
        d = start
        while d <= end:
            dates.append(d)
            d += timedelta(days=step_days)
        return dates
    
    def _partial_window_weight(self, window_start: date, dn: date, w: int = WINDOW_DAYS) -> float:
        """
        Calculate weight for partial window per NIST methodology:
        - Full windows get weight = 1.0
        - Partial window gets weight = days_in_window / w
        """
        window_end = window_start + timedelta(days=w)
        if dn >= window_end:
            return 1.0  # Full window
        
        # Partial window
        days_in_partial = max(0, (dn - window_start).days)
        return max(0.0, min(1.0, days_in_partial / float(w)))
    
    def _compute_lev_from_windows(self, epss_by_window: List[Tuple[date, float]], dn: date) -> float:
        """
        Apply NIST LEV formula: LEV = 1 - ∏_i (1 - epss_i × weight_i)
        """
        try:
            logging.info("Applying NIST LEV formula:")
            
            product_term = 1.0
            
            for i, (window_start, epss_score) in enumerate(epss_by_window, 1):
                # Calculate weight for this window
                weight = self._partial_window_weight(window_start, dn, WINDOW_DAYS)
                
                # Apply NIST formula for this window
                term = max(0.0, min(1.0, 1.0 - (epss_score * weight)))
                product_term *= term
                
                window_end = min(window_start + timedelta(days=WINDOW_DAYS), dn)
                days_in_window = (window_end - window_start).days
                
                logging.info(f"   Window {i}: {window_start} to {window_end}")
                logging.info(f"     Days: {days_in_window}, EPSS: {epss_score:.6f}, Weight: {weight:.3f}")
                logging.info(f"     Term: (1 - {epss_score:.6f} × {weight:.3f}) = {term:.6f}")
                logging.info(f"     Running product: {product_term:.6f}")
            
            # Final LEV calculation
            lev_score = 1.0 - product_term
            lev_score = max(0.0, min(1.0, lev_score))
            
            logging.info("NIST LEV Result:")
            logging.info(f"   Final product term: {product_term:.6f}")
            logging.info(f"   LEV = 1 - {product_term:.6f} = {lev_score:.6f}")
            logging.info(f"   LEV percentage: {lev_score * 100:.2f}%")
            
            return lev_score
            
        except Exception as e:
            logging.error(f"LEV formula computation failed: {e}")
            return 0.0
    
    async def _get_epss_score_on_date(self, cve_id: str, target_date: date) -> float:
        """
        Get EPSS score for a specific date using EPSS API
        """
        await self._rate_limit()
        
        try:
            params = {
                "cve": cve_id,
                "date": target_date.isoformat()
            }
            
            timeout = ClientTimeout(total=10, connect=5)
            
            async with self.session.get(self.config.epss_base_url, params=params, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    epss_data = data.get("data", [])
                    
                    if epss_data:
                        # Return the EPSS score for this date
                        return float(epss_data[0]["epss"])
                    else:
                        # No score on that date (e.g., pre-publication)
                        logging.debug(f"No EPSS data for {cve_id} on {target_date}")
                        return 0.0
                else:
                    logging.warning(f"EPSS API returned {response.status} for {cve_id} on {target_date}")
                    return 0.0
                    
        except Exception as e:
            logging.warning(f"Failed to get EPSS for {cve_id} on {target_date}: {e}")
            return 0.0
    
    async def _rate_limit(self):
        """Rate limiting for EPSS API calls"""
        elapsed = asyncio.get_event_loop().time() - self.last_request_time
        min_delay = 1.0  # 1 second between calls
        
        if elapsed < min_delay:
            sleep_time = min_delay - elapsed
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = asyncio.get_event_loop().time()
