"""Table format output formatter"""

import textwrap
from ...core.models import VulnerabilityMetrics


class TableFormatter:
    """Table format output formatter"""
    
    @staticmethod
    def format_single(metrics: VulnerabilityMetrics) -> str:
        """Format single result as table"""
        lines = [
            f"CVE ID: {metrics.cve_id}",
            f"VES Score: {metrics.ves_score:.4f}" if metrics.ves_score is not None else "VES Score: N/A",
            f"Priority Level: {metrics.priority_level}",
            f"Severity: {metrics.severity.value}",
            f"CVSS Score: {metrics.cvss_score}" if metrics.cvss_score is not None else "CVSS Score: N/A",
            f"EPSS Score: {metrics.epss_score:.6f}" if metrics.epss_score is not None else "EPSS Score: N/A",
            f"EPSS Percentile: {metrics.epss_percentile:.2f}%" if metrics.epss_percentile is not None else "EPSS Percentile: N/A",
            f"KEV Status: {'Yes' if metrics.kev_status else 'No'}",
            f"LEV Score: {metrics.lev_score:.6f}" if metrics.lev_score is not None else "LEV Score: N/A",
        ]
        
        if metrics.published_date:
            lines.append(f"Published: {metrics.published_date.strftime('%Y-%m-%d')}")
        
        if metrics.description:
            # Truncate long descriptions
            desc = metrics.description[:200] + "..." if len(metrics.description) > 200 else metrics.description
            wrapped_desc = textwrap.fill(desc, width=70, initial_indent="Description: ", subsequent_indent="             ")
            lines.append(wrapped_desc)
        
        return "\n".join(lines)
