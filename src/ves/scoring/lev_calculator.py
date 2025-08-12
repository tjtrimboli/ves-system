"""NIST LEV (Likely Exploited Vulnerabilities) Calculator"""

import asyncio
import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from aiohttp import ClientSession, ClientTimeout, ClientError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from ..config.settings import VESConfig


class LEVCalculator:
    """NIST-compliant LEV calculation engine following proper methodology"""
    
    def __init__(self, session: ClientSession, config: VESConfig):
        self.session = session
        self.config = config
        self.epss_cache: Dict[str, List[Dict]] = {}
        self.last_request_time = 0
    
    async def _rate_limit_epss(self):
        """Conservative rate limiting for EPSS API calls"""
        elapsed = asyncio.get_event_loop().time() - self.last_request_time
        min_delay = 3.0  # 3 seconds between calls
        if elapsed < min_delay:
            sleep_time = min_delay - elapsed
            await asyncio.sleep(sleep_time)
        self.last_request_time = asyncio.get_event_loop().time()
    
    async def calculate_lev_score(self, cve_id: str, start_date: datetime, 
                                 end_date: datetime, max_lookback_days: int = 730) -> float:
        """
        Calculate LEV score using proper NIST methodology
        
        NIST LEV Formula:
        LEV(v, d₀, dₙ) ≥ 1 - ∏[∀dᵢ∈dates(d₀,dₙ,30)] (1 - epss(v,dᵢ) × weight(dᵢ,dₙ,30))
        """
        try:
            # Limit lookback for performance
            actual_start = max(start_date, end_date - timedelta(days=max_lookback_days))
            total_days = (end_date - actual_start).days
            
            logging.info(f"📊 NIST LEV calculation: {total_days} days lookback")
            
            # Get EPSS time-series data
            time_series_data = await self._get_epss_time_series_data(cve_id)
            
            if not time_series_data:
                logging.warning(f"⚠️  No EPSS time-series data for LEV calculation")
                return 0.0
            
            # Calculate LEV using proper NIST methodology
            lev_score = self._calculate_nist_lev(time_series_data, actual_start, end_date)
            
            logging.info(f"✅ NIST LEV calculation complete: {lev_score:.6f} ({len(time_series_data)} data points)")
            return lev_score
            
        except Exception as e:
            logging.error(f"💥 LEV calculation failed for {cve_id}: {e}")
            return 0.0
    
    def _calculate_nist_lev(self, time_series_data: List[Dict], 
                           start_date: datetime, end_date: datetime) -> float:
        """
        Calculate LEV using proper NIST methodology with 30-day windows
        
        Formula: LEV ≥ 1 - ∏[∀dᵢ∈windows] (1 - epss(dᵢ) × weight(dᵢ))
        """
        try:
            # Convert time-series data to date-indexed dictionary
            epss_by_date = {}
            for entry in time_series_data:
                date_str = entry.get('date')
                epss_score = float(entry.get('epss', 0.0))
                if date_str:
                    epss_by_date[date_str] = epss_score
            
            if not epss_by_date:
                return 0.0
            
            # Calculate LEV using 30-day windows as per NIST methodology
            product_term = 1.0
            current_date = start_date
            windows_processed = 0
            
            while current_date <= end_date:
                window_end = min(current_date + timedelta(days=30), end_date)
                window_days = (window_end - current_date).days
                
                # Get EPSS score for this window (use most recent available)
                window_epss = self._get_epss_for_window(epss_by_date, current_date, window_end)
                
                # Calculate weight for this window
                weight = self._calculate_window_weight(window_days, 30)
                
                # Apply NIST formula: product *= (1 - epss * weight)
                term = 1 - (window_epss * weight)
                product_term *= term
                
                logging.debug(f"Window {windows_processed + 1}: {current_date.strftime('%Y-%m-%d')} to {window_end.strftime('%Y-%m-%d')}")
                logging.debug(f"  EPSS: {window_epss:.6f}, Weight: {weight:.3f}, Term: {term:.6f}")
                
                current_date = window_end
                windows_processed += 1
            
            # Final LEV calculation: LEV = 1 - product_term
            lev_score = 1 - product_term
            
            # Ensure valid range [0, 1]
            lev_score = max(0.0, min(1.0, lev_score))
            
            logging.info(f"📊 NIST LEV calculation details:")
            logging.info(f"   Windows processed: {windows_processed}")
            logging.info(f"   Product term: {product_term:.6f}")
            logging.info(f"   Final LEV: {lev_score:.6f}")
            
            return lev_score
            
        except Exception as e:
            logging.error(f"💥 NIST LEV calculation error: {e}")
            return 0.0
    
    def _get_epss_for_window(self, epss_by_date: Dict[str, float], 
                            start_date: datetime, end_date: datetime) -> float:
        """Get representative EPSS score for a 30-day window"""
        
        # Collect EPSS scores within the window
        window_scores = []
        current_date = start_date
        
        while current_date <= end_date:
            date_str = current_date.strftime('%Y-%m-%d')
            if date_str in epss_by_date:
                window_scores.append(epss_by_date[date_str])
            current_date += timedelta(days=1)
        
        if window_scores:
            # Use average EPSS score for the window
            return sum(window_scores) / len(window_scores)
        else:
            # If no data in window, use the most recent available score
            available_dates = sorted(epss_by_date.keys())
            if available_dates:
                # Find the most recent date before or equal to window end
                window_end_str = end_date.strftime('%Y-%m-%d')
                relevant_dates = [d for d in available_dates if d <= window_end_str]
                if relevant_dates:
                    return epss_by_date[relevant_dates[-1]]
                else:
                    # Use earliest available if none before window
                    return epss_by_date[available_dates[0]]
            
            return 0.0
    
    def _calculate_window_weight(self, window_days: int, max_days: int = 30) -> float:
        """
        Calculate weight for a window based on its length
        
        NIST methodology uses: weight = window_days / max_days
        """
        if max_days <= 0:
            return 1.0
        
        weight = window_days / max_days
        return min(1.0, max(0.0, weight))
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type((ClientError, asyncio.TimeoutError))
    )
    async def _get_epss_time_series_data(self, cve_id: str) -> List[Dict]:
        """Get EPSS time-series data using the API"""
        # Check cache first
        if cve_id in self.epss_cache:
            return self.epss_cache[cve_id]
        
        await self._rate_limit_epss()
        
        try:
            # Use EPSS time-series API
            url = f"{self.config.epss_base_url}?cve={cve_id}&scope=time-series"
            
            logging.debug(f"📡 EPSS time-series API call: {url}")
            
            timeout = ClientTimeout(total=20, connect=10)
            
            async with self.session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('data') and len(data['data']) > 0:
                        time_series_data = data['data']
                        
                        # Cache the result
                        self.epss_cache[cve_id] = time_series_data
                        
                        logging.debug(f"📊 Retrieved {len(time_series_data)} EPSS time-series points")
                        return time_series_data
                    else:
                        logging.debug(f"🔍 No EPSS time-series data found for {cve_id}")
                        return []
                        
                elif response.status == 404:
                    logging.debug(f"🔍 CVE not found in EPSS: {cve_id}")
                    return []
                    
                else:
                    error_text = await response.text()
                    logging.warning(f"⚠️  EPSS API error {response.status}: {error_text}")
                    return []
                    
        except asyncio.TimeoutError:
            logging.warning(f"⏰ EPSS time-series timeout for {cve_id}")
            return []
        except ClientError as e:
            logging.warning(f"🌐 EPSS time-series network error for {cve_id}: {e}")
            return []
        except Exception as e:
            logging.warning(f"💥 EPSS time-series error for {cve_id}: {e}")
            return []
    
    async def calculate_simplified_lev(self, cve_id: str, start_date: datetime, 
                                     end_date: datetime, sample_periods: int = 1) -> float:
        """
        Simplified LEV calculation using fewer windows for performance
        """
        try:
            # Get time-series data
            time_series_data = await self._get_epss_time_series_data(cve_id)
            
            if not time_series_data:
                logging.debug(f"🔍 No EPSS data for simplified LEV: {cve_id}")
                return 0.0
            
            # Use simplified calculation with fewer windows
            total_days = (end_date - start_date).days
            
            # For simplified, use larger windows (60 days instead of 30)
            product_term = 1.0
            current_date = start_date
            window_size = 60  # Larger windows for simplified calculation
            
            epss_by_date = {}
            for entry in time_series_data:
                date_str = entry.get('date')
                epss_score = float(entry.get('epss', 0.0))
                if date_str:
                    epss_by_date[date_str] = epss_score
            
            while current_date <= end_date:
                window_end = min(current_date + timedelta(days=window_size), end_date)
                window_days = (window_end - current_date).days
                
                # Get EPSS for this larger window
                window_epss = self._get_epss_for_window(epss_by_date, current_date, window_end)
                weight = self._calculate_window_weight(window_days, window_size)
                
                product_term *= (1 - window_epss * weight)
                current_date = window_end
            
            simplified_lev = 1 - product_term
            simplified_lev = max(0.0, min(1.0, simplified_lev))
            
            logging.info(f"✅ Simplified LEV: {simplified_lev:.6f}")
            return simplified_lev
            
        except Exception as e:
            logging.error(f"💥 Simplified LEV calculation failed: {e}")
            return 0.0
