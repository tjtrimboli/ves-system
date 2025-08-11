"""CSV format output formatter"""

import csv
import sys
from typing import List

from ...core.models import VulnerabilityMetrics


class CSVFormatter:
    """CSV format output formatter"""
    
    @staticmethod
    def get_headers() -> List[str]:
        """Get CSV headers"""
        return [
            'cve_id', 'ves_score', 'priority_level', 'severity',
            'cvss_score', 'cvss_vector', 'epss_score', 'epss_percentile', 
            'kev_status', 'lev_score', 'published_date', 'last_modified', 'description'
        ]
    
    @staticmethod
    def format_row(metrics: VulnerabilityMetrics) -> List[str]:
        """Format single result as CSV row"""
        return [
            metrics.cve_id,
            str(metrics.ves_score) if metrics.ves_score is not None else '',
            str(metrics.priority_level),
            metrics.severity.value,
            str(metrics.cvss_score) if metrics.cvss_score is not None else '',
            metrics.cvss_vector or '',
            str(metrics.epss_score) if metrics.epss_score is not None else '',
            str(metrics.epss_percentile) if metrics.epss_percentile is not None else '',
            str(metrics.kev_status),
            str(metrics.lev_score) if metrics.lev_score is not None else '',
            metrics.published_date.strftime('%Y-%m-%d %H:%M:%S') if metrics.published_date else '',
            metrics.last_modified.strftime('%Y-%m-%d %H:%M:%S') if metrics.last_modified else '',
            (metrics.description or '').replace('\n', ' ').replace('\r', ' ')  # Clean description
        ]
    
    @staticmethod
    def save_bulk(results: List[VulnerabilityMetrics], output_path: str = None):
        """Save bulk results to CSV file or stdout"""
        if output_path:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(CSVFormatter.get_headers())
                for result in results:
                    writer.writerow(CSVFormatter.format_row(result))
            print(f"Results saved to {output_path}")
        else:
            writer = csv.writer(sys.stdout)
            writer.writerow(CSVFormatter.get_headers())
            for result in results:
                writer.writerow(CSVFormatter.format_row(result))
