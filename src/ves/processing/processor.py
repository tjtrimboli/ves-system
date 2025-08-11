"""Main VES Processing Engine with improved error handling and progress tracking"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import aiohttp
from aiohttp import ClientSession, ClientTimeout

from ..config.settings import VESConfig
from ..core.models import VulnerabilityMetrics, Severity
from ..clients.nvd_client import NVDClient
from ..clients.epss_client import EPSSClient
from ..clients.kev_client import KEVClient
from ..scoring.lev_calculator import LEVCalculator
from ..scoring.ves_scorer import VESScorer


class VESProcessor:
    """Main VES Processing Engine with enhanced error handling"""
    
    def __init__(self, config: VESConfig):
        self.config = config
        self.session: Optional[ClientSession] = None
        self.nvd_client: Optional[NVDClient] = None
        self.epss_client: Optional[EPSSClient] = None
        self.kev_client: Optional[KEVClient] = None
        self.lev_calculator: Optional[LEVCalculator] = None
        self.scorer = VESScorer()
    
    async def __aenter__(self):
        """Async context manager entry with proper timeout configuration"""
        # Set reasonable timeouts
        timeout = ClientTimeout(
            total=60,     # Total timeout for the entire request
            connect=10,   # Timeout for establishing connection
            sock_read=30  # Timeout for reading data
        )
        
        # Configure session with timeout and connection limits
        connector = aiohttp.TCPConnector(
            limit=20,           # Total connection pool size
            limit_per_host=10,  # Max connections per host
            ttl_dns_cache=300,  # DNS cache TTL
            use_dns_cache=True,
        )
        
        self.session = ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': 'VES-CLI/1.0.0 (Vulnerability Evaluation System)'}
        )
        
        self.nvd_client = NVDClient(self.session, self.config)
        self.epss_client = EPSSClient(self.session, self.config)
        self.kev_client = KEVClient(self.session, self.config)
        self.lev_calculator = LEVCalculator(self.session, self.config)
        
        logging.info("🚀 VES processor initialized")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with proper cleanup"""
        if self.session:
            await self.session.close()
            logging.info("🔒 VES processor closed")
    
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
                        logging.debug(f"Found CVSS {version}: {score}")
                        return float(score), vector
                        
            logging.warning("No CVSS data found in CVE")
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
            
            if published:
                logging.debug(f"CVE published: {published.strftime('%Y-%m-%d')}")
            
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
        """Process a single CVE with comprehensive error handling and progress tracking"""
        metrics = VulnerabilityMetrics(cve_id=cve_id)
        
        try:
            logging.info(f"🔍 Processing {cve_id}...")
            
            # Step 1: Get CVE data from NVD
            logging.info(f"📡 Step 1/4: Fetching CVE data from NVD...")
            cve_data = await self.nvd_client.get_cve_data(cve_id)
            
            if not cve_data:
                logging.warning(f"⚠️  No CVE data found for {cve_id} - continuing with limited analysis")
                # Continue processing with other sources even if NVD fails
            else:
                # Extract CVSS data
                metrics.cvss_score, metrics.cvss_vector = self._extract_cvss_data(cve_data)
                metrics.severity = self.scorer.calculate_severity(metrics.cvss_score)
                
                # Extract dates and description
                metrics.published_date, metrics.last_modified = self._extract_publication_dates(cve_data)
                metrics.description = self._extract_description(cve_data)
                
                logging.info(f"✅ CVE data extracted - CVSS: {metrics.cvss_score}, Severity: {metrics.severity.value}")
            
            # Step 2: Get EPSS score
            logging.info(f"📊 Step 2/4: Fetching EPSS data...")
            try:
                metrics.epss_score, metrics.epss_percentile = await self.epss_client.get_epss_score(cve_id)
            except Exception as e:
                logging.warning(f"⚠️  EPSS fetch failed: {e}")
                metrics.epss_score, metrics.epss_percentile = None, None
            
            # Step 3: Check KEV status
            logging.info(f"🚨 Step 3/4: Checking KEV status...")
            try:
                metrics.kev_status = await self.kev_client.is_kev_vulnerability(cve_id)
                kev_status_text = "Yes (Known Exploited)" if metrics.kev_status else "No"
                logging.info(f"🚨 KEV Status: {kev_status_text}")
            except Exception as e:
                logging.warning(f"⚠️  KEV check failed: {e}")
                metrics.kev_status = False
            
            # Step 4: Calculate LEV score
            logging.info(f"📈 Step 4/4: Calculating LEV score...")
            try:
                if metrics.published_date:
                    end_date = datetime.now()
                    metrics.lev_score = await self.lev_calculator.calculate_lev_score(
                        cve_id, metrics.published_date, end_date
                    )
                    logging.info(f"📈 LEV Score: {metrics.lev_score:.6f}")
                else:
                    logging.warning("⚠️  No publication date - skipping LEV calculation")
            except Exception as e:
                logging.warning(f"⚠️  LEV calculation failed: {e}")
                metrics.lev_score = None
            
            # Calculate final VES score
            metrics.ves_score = self.scorer.calculate_ves_score(metrics)
            metrics.priority_level = self.scorer.calculate_priority_level(metrics.ves_score, metrics.kev_status)
            
            logging.info(f"🎯 Final VES Score: {metrics.ves_score:.6f} (Priority {metrics.priority_level})")
            
        except Exception as e:
            logging.error(f"💥 Error processing {cve_id}: {e}")
            # Return partial results even if processing fails
        
        return metrics
    
    async def process_bulk_cves(self, cve_ids: List[str]) -> List[VulnerabilityMetrics]:
        """Process multiple CVEs with progress tracking and error resilience"""
        semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        
        async def process_with_semaphore(cve_id: str) -> VulnerabilityMetrics:
            async with semaphore:
                return await self.process_single_cve(cve_id)
        
        logging.info(f"🚀 Starting bulk processing of {len(cve_ids)} CVEs...")
        
        tasks = [process_with_semaphore(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logging.error(f"💥 Failed to process {cve_ids[i]}: {result}")
                # Create a minimal result for failed CVEs
                failed_metrics = VulnerabilityMetrics(cve_id=cve_ids[i])
                valid_results.append(failed_metrics)
            else:
                valid_results.append(result)
        
        logging.info(f"✅ Bulk processing complete: {len(valid_results)} results")
        return valid_results
