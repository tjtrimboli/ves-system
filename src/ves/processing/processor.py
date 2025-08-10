"""Main VES Processing Engine"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from aiohttp import ClientSession, ClientTimeout

from ..config.settings import VESConfig
from ..core.models import VulnerabilityMetrics, Severity
from ..clients.nvd_client import NVDClient
from ..clients.epss_client import EPSSClient
from ..clients.kev_client import KEVClient
from ..scoring.lev_calculator import LEVCalculator
from ..scoring.ves_scorer import VESScorer


class VESProcessor:
    """Main VES Processing Engine"""
    
    def __init__(self, config: VESConfig):
        self.config = config
        self.session: Optional[ClientSession] = None
        self.nvd_client: Optional[NVDClient] = None
        self.epss_client: Optional[EPSSClient] = None
        self.kev_client: Optional[KEVClient] = None
        self.lev_calculator: Optional[LEVCalculator] = None
        self.scorer = VESScorer()
    
    async def __aenter__(self):
        """Async context manager entry"""
        timeout = ClientTimeout(total=30, connect=10)
        self.session = ClientSession(timeout=timeout)
        
        self.nvd_client = NVDClient(self.session, self.config)
        self.epss_client = EPSSClient(self.session, self.config)
        self.kev_client = KEVClient(self.session, self.config)
        self.lev_calculator = LEVCalculator(self.session, self.config)
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _extract_cvss_data(self, cve_data: Dict) -> Tuple[Optional[float], Optional[str]]:
        """Extract CVSS score and vector from CVE data"""
        try:
            metrics = cve_data.get('metrics', {})
            
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0]['cvssData']
                    score = cvss_data.get('baseScore')
                    vector = cvss_data.get('vectorString')
                    if score:
                        return float(score), vector
        except Exception as e:
            logging.warning(f"Failed to extract CVSS data: {e}")
        
        return None, None
    
    def _extract_publication_dates(self, cve_data: Dict) -> Tuple[Optional[datetime], Optional[datetime]]:
        """Extract publication and modification dates"""
        try:
            published_str = cve_data.get('published')
            modified_str = cve_data.get('lastModified')
            
            published = datetime.fromisoformat(published_str.replace('Z', '+00:00')) if published_str else None
            modified = datetime.fromisoformat(modified_str.replace('Z', '+00:00')) if modified_str else None
            
            return published, modified
        except Exception as e:
            logging.warning(f"Failed to extract dates: {e}")
            return None, None
    
    def _extract_description(self, cve_data: Dict) -> Optional[str]:
        """Extract CVE description"""
        try:
            descriptions = cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    return desc.get('value')
        except Exception:
            pass
        return None
    
    async def process_single_cve(self, cve_id: str) -> VulnerabilityMetrics:
        """Process a single CVE and calculate all metrics"""
        metrics = VulnerabilityMetrics(cve_id=cve_id)
        
        try:
            # Get CVE data from NVD
            cve_data = await self.nvd_client.get_cve_data(cve_id)
            if not cve_data:
                logging.warning(f"No data found for {cve_id}")
                return metrics
            
            # Extract CVSS data
            metrics.cvss_score, metrics.cvss_vector = self._extract_cvss_data(cve_data)
            metrics.severity = self.scorer.calculate_severity(metrics.cvss_score)
            
            # Extract dates and description
            metrics.published_date, metrics.last_modified = self._extract_publication_dates(cve_data)
            metrics.description = self._extract_description(cve_data)
            
            # Get EPSS score
            metrics.epss_score, metrics.epss_percentile = await self.epss_client.get_epss_score(cve_id)
            
            # Check KEV status
            metrics.kev_status = await self.kev_client.is_kev_vulnerability(cve_id)
            
            # Calculate LEV score
            if metrics.published_date:
                end_date = datetime.now()
                metrics.lev_score = await self.lev_calculator.calculate_lev_score(
                    cve_id, metrics.published_date, end_date
                )
            
            # Calculate final VES score
            metrics.ves_score = self.scorer.calculate_ves_score(metrics)
            metrics.priority_level = self.scorer.calculate_priority_level(metrics.ves_score, metrics.kev_status)
            
        except Exception as e:
            logging.error(f"Error processing {cve_id}: {e}")
        
        return metrics
    
    async def process_bulk_cves(self, cve_ids: List[str]) -> List[VulnerabilityMetrics]:
        """Process multiple CVEs concurrently with rate limiting"""
        semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        
        async def process_with_semaphore(cve_id: str) -> VulnerabilityMetrics:
            async with semaphore:
                return await self.process_single_cve(cve_id)
        
        tasks = [process_with_semaphore(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logging.error(f"Failed to process {cve_ids[i]}: {result}")
            else:
                valid_results.append(result)
        
        return valid_results
