"""Table format output formatter"""

import textwrap
from datetime import datetime
from ...core.models import VulnerabilityMetrics


class TableFormatter:
    """Clean professional table formatter similar to VulnX output"""
    
    @staticmethod
    def format_single(metrics: VulnerabilityMetrics) -> str:
        """Format single result as clean table"""
        lines = []
        
        # Header with CVE ID and basic info
        severity_text = metrics.severity.value if metrics.severity.value != "NONE" else "Unknown"
        header = f"[{metrics.cve_id}] {severity_text}"
        
        if metrics.description:
            # Truncate description to reasonable length
            desc = metrics.description[:80] + "..." if len(metrics.description) > 80 else metrics.description
            header += f" - {desc}"
        
        lines.append(header)
        lines.append("")
        
        # VES Analysis Section
        lines.append("VES ANALYSIS:")
        if metrics.ves_score is not None:
            lines.append(f"  VES Score: {metrics.ves_score:.4f}")
            priority_text = TableFormatter._get_priority_text(metrics.priority_level)
            lines.append(f"  Priority: {priority_text}")
        else:
            lines.append(f"  VES Score: Unable to calculate")
            lines.append(f"  Priority: Unknown")
        
        lines.append("")
        
        # Component Scores
        lines.append("COMPONENT SCORES:")
        
        # CVSS
        if metrics.cvss_score is not None:
            lines.append(f"  CVSS: {metrics.cvss_score}/10.0 ({metrics.severity.value})")
            if metrics.cvss_vector:
                lines.append(f"  CVSS Vector: {metrics.cvss_vector}")
        else:
            lines.append(f"  CVSS: Not Available")
        
        # EPSS
        if metrics.epss_score is not None:
            epss_risk = TableFormatter._get_epss_risk_level(metrics.epss_percentile)
            lines.append(f"  EPSS: {metrics.epss_score:.6f} ({metrics.epss_percentile:.2f}%) - {epss_risk}")
        else:
            lines.append(f"  EPSS: Not Available")
        
        # LEV
        if metrics.lev_score is not None:
            lev_risk = TableFormatter._get_lev_risk_level(metrics.lev_score)
            lines.append(f"  LEV: {metrics.lev_score:.6f} - {lev_risk}")
        else:
            lines.append(f"  LEV: Not Available")
        
        # KEV
        kev_status = "KNOWN EXPLOITED" if metrics.kev_status else "Not in KEV catalog"
        lines.append(f"  KEV: {kev_status}")
        
        lines.append("")
        
        # Metadata
        lines.append("METADATA:")
        if metrics.published_date:
            age_days = (datetime.now() - metrics.published_date).days
            lines.append(f"  Published: {metrics.published_date.strftime('%Y-%m-%d')} (Age: {age_days} days)")
        else:
            lines.append(f"  Published: Unknown")
        
        if metrics.last_modified:
            lines.append(f"  Last Modified: {metrics.last_modified.strftime('%Y-%m-%d')}")
        
        lines.append("")
        
        # Recommendations
        lines.append("RECOMMENDATIONS:")
        recommendations = TableFormatter._get_recommendations(metrics)
        for rec in recommendations:
            lines.append(f"  {rec}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_bulk_summary(results) -> str:
        """Format bulk results in VulnX-style summary"""
        if not results:
            return "No results to display"
        
        lines = []
        lines.append("VULNERABILITY SCAN RESULTS")
        lines.append("=" * 50)
        lines.append("")
        
        for i, result in enumerate(results, 1):
            # Main CVE line
            severity = result.severity.value if result.severity.value != "NONE" else "Unknown"
            priority = TableFormatter._get_priority_text(result.priority_level)
            
            cve_line = f"[{result.cve_id}] {severity}"
            
            if result.description:
                desc = result.description[:60] + "..." if len(result.description) > 60 else result.description
                cve_line += f" - {desc}"
            
            lines.append(cve_line)
            
            # Details line
            details = []
            details.append(f"Priority: {priority}")
            
            if result.cvss_score is not None:
                details.append(f"CVSS: {result.cvss_score}")
            
            if result.epss_score is not None:
                details.append(f"EPSS: {result.epss_score:.4f}")

            if result.lev_score is not None:
                details.append(f"LEV: {result.lev_score:.4f}")

            if result.kev_status:
                details.append("KEV: EXPLOITED")

            if result.ves_score is not None:
                details.append(f"VES: {result.ves_score:.4f}")
            
            if result.published_date:
                age = (datetime.now() - result.published_date).days
                if age <= 30:
                    details.append(f"Age: {age}d (RECENT)")
                else:
                    details.append(f"Age: {age}d")
            
            lines.append(f"  {' | '.join(details)}")
            lines.append("")
        
        # Summary statistics
        lines.append("-" * 50)
        lines.append(f"Showing {len(results)} vulnerabilities")
        
        # Risk breakdown
        critical_count = sum(1 for r in results if r.severity.value == "CRITICAL")
        high_count = sum(1 for r in results if r.severity.value == "HIGH")
        kev_count = sum(1 for r in results if r.kev_status)
        priority_1 = sum(1 for r in results if r.priority_level == 1)
        
        if critical_count > 0:
            lines.append(f"Critical: {critical_count}")
        if high_count > 0:
            lines.append(f"High: {high_count}")
        if kev_count > 0:
            lines.append(f"Known Exploited: {kev_count}")
        if priority_1 > 0:
            lines.append(f"Priority 1 (Urgent): {priority_1}")
        
        return "\n".join(lines)
    
    @staticmethod
    def _get_priority_text(priority_level: int) -> str:
        """Get priority text description"""
        priority_map = {
            1: "IMMEDIATE",
            2: "HIGH", 
            3: "MEDIUM",
            4: "LOW"
        }
        return priority_map.get(priority_level, "UNKNOWN")
    
    @staticmethod
    def _get_epss_risk_level(epss_score: float, percentile: float = None) -> str:
        """Get EPSS risk level description based on score and percentile"""
        if epss_score is None:
            return "Unknown"
        
        # Primary assessment based on EPSS score (exploitation probability)
        if epss_score >= 0.8:
            return "Very High Risk"
        elif epss_score >= 0.6:
            return "High Risk"
        elif epss_score >= 0.3:
            return "Medium Risk"
        elif epss_score >= 0.1:
            return "Low Risk"
        else:
            return "Very Low Risk"
    
    @staticmethod
    def _get_lev_risk_level(lev_score: float) -> str:
        """Get LEV risk level description"""
        if lev_score >= 0.8:
            return "Very High Historical Risk"
        elif lev_score >= 0.6:
            return "High Historical Risk"
        elif lev_score >= 0.3:
            return "Medium Historical Risk"
        else:
            return "Low Historical Risk"
    
    @staticmethod
    def _get_recommendations(metrics: VulnerabilityMetrics) -> list:
        """Get actionable recommendations"""
        recommendations = []
        
        if metrics.kev_status:
            recommendations.append("URGENT: Patch immediately - actively exploited")
        elif metrics.priority_level == 1:
            recommendations.append("HIGH: Schedule patching within 72 hours")
        elif metrics.priority_level == 2:
            recommendations.append("MEDIUM: Schedule patching within 1 week")
        else:
            recommendations.append("STANDARD: Include in regular patching cycle")
        
        if metrics.epss_score and metrics.epss_score > 0.7:
            recommendations.append("Monitor threat intelligence - high exploitation probability")
        
        if metrics.cvss_score and metrics.cvss_score >= 9.0:
            recommendations.append("Review network segmentation and access controls")
        
        if not recommendations:
            recommendations.append("Follow standard vulnerability management procedures")
        
        return recommendations
