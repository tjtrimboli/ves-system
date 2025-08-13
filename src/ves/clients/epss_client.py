"""FIRST EPSS API Client"""

import asyncio
import logging
from typing import Optional, Tuple
from aiohttp import ClientSession, ClientTimeout, ClientError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from ..config.settings import VESConfig


class EPSSClient:
    """EPSS API Client"""
    
    def __init__(self, session: ClientSession, config: VESConfig):
        self.session = session
        self.config = config
    
    @retry(
        stop=stop_after_attempt(3), 
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type((ClientError, asyncio.TimeoutError))
    )
    async def get_epss_score(self, cve_id: str) -> Tuple[Optional[float], Optional[float]]:
        """Get current EPSS score and percentile with error handling"""
        url = f"{self.config.epss_base_url}?cve={cve_id}"
        
        try:
            logging.info(f"Fetching EPSS score for {cve_id}...")
            
            timeout = ClientTimeout(total=20, connect=5)
            
            async with self.session.get(url, timeout=timeout) as response:
                logging.debug(f"EPSS API response status: {response.status}")
                
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('data') and len(data['data']) > 0:
                        cve_data = data['data'][0]
                        epss_score = float(cve_data.get('epss', 0.0))
                        percentile = float(cve_data.get('percentile', 0.0))
                        
                        logging.info(f"EPSS score for {cve_id}: {epss_score:.6f} ({percentile:.2f}%)")
                        return epss_score, percentile
                    else:
                        logging.warning(f"No EPSS data found for {cve_id}")
                        return None, None
                        
                elif response.status == 404:
                    logging.warning(f"EPSS data not found for {cve_id}")
                    return None, None
                    
                else:
                    error_text = await response.text()
                    logging.warning(f"EPSS API error {response.status}: {error_text}")
                    return None, None
                    
        except asyncio.TimeoutError:
            logging.warning(f"Timeout fetching EPSS data for {cve_id}")
            return None, None
        except ClientError as e:
            logging.warning(f"Network error fetching EPSS for {cve_id}: {e}")
            return None, None
        except Exception as e:
            logging.warning(f"Error fetching EPSS for {cve_id}: {e}")
            return None, None
