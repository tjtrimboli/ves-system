"""NVD API Client"""

import asyncio
import logging
import time
from typing import Dict, Optional, Tuple
from aiohttp import ClientSession, ClientTimeout, ClientError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from ..config.settings import VESConfig


class NVDClient:
    """NVD API Client with clean logging"""
    
    def __init__(self, session: ClientSession, config: VESConfig):
        self.session = session
        self.config = config
        self.last_request_time = 0
    
    async def _rate_limit(self):
        """Enforce rate limiting for NVD API"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.config.rate_limit_delay:
            sleep_time = self.config.rate_limit_delay - elapsed
            logging.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            await asyncio.sleep(sleep_time)
        self.last_request_time = time.time()
    
    @retry(
        stop=stop_after_attempt(3), 
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((ClientError, asyncio.TimeoutError))
    )
    async def get_cve_data(self, cve_id: str) -> Optional[Dict]:
        """Get CVE data from NVD API with comprehensive error handling"""
        await self._rate_limit()
        
        headers = {
            'User-Agent': 'VES-CLI/1.0.0 (Vulnerability Evaluation System)'
        }
        if self.config.nvd_api_key:
            headers['apiKey'] = self.config.nvd_api_key
        
        url = f"{self.config.nvd_base_url}?cveId={cve_id}"
        
        try:
            logging.info(f"Fetching CVE data for {cve_id} from NVD...")
            
            timeout = ClientTimeout(total=30, connect=10)
            
            async with self.session.get(url, headers=headers, timeout=timeout) as response:
                logging.debug(f"NVD API response status: {response.status}")
                
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    if vulnerabilities and len(vulnerabilities) > 0:
                        logging.info(f"Found CVE data for {cve_id}")
                        return vulnerabilities[0]['cve']
                    else:
                        logging.warning(f"NVD returned empty result for {cve_id}")
                        return None
                        
                elif response.status == 404:
                    logging.warning(f"CVE {cve_id} not found in NVD (404)")
                    return None
                    
                elif response.status == 403:
                    error_text = await response.text()
                    logging.error(f"NVD API access forbidden (403): {error_text}")
                    if "API key" in error_text.lower():
                        logging.error("Check your NVD API key configuration")
                    raise ClientError(f"NVD API access forbidden: {error_text}")
                    
                elif response.status == 429:
                    logging.warning("Rate limited by NVD API - will retry")
                    raise ClientError("Rate limited by NVD API")
                    
                else:
                    error_text = await response.text()
                    logging.error(f"NVD API error {response.status}: {error_text}")
                    response.raise_for_status()
                    
        except asyncio.TimeoutError:
            logging.error(f"Timeout fetching CVE data for {cve_id} from NVD")
            raise
        except ClientError as e:
            logging.error(f"Network error for {cve_id}: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error fetching {cve_id} from NVD: {e}")
            raise
        
        return None
