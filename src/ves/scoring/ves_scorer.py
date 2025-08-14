
"""VES Unified Scoring Algorithm with Dynamic Weighting"""

from ..core.models import VulnerabilityMetrics, Severity


class VESScorer:
    """VES unified scoring engine with dynamic weighting support"""
    
    @staticmethod
    def calculate_severity(cvss_score: float) -> Severity:
        """Calculate severity level from CVSS score"""
        if not cvss_score or cvss_score < 0.1:
            return Severity.NONE
        elif cvss_score < 4.0:
            return Severity.LOW
        elif cvss_score < 7.0:
            return Severity.MEDIUM
        elif cvss_score < 9.0:
            return Severity.HIGH
        else:
            return Severity.CRITICAL
    
    @staticmethod
    def calculate_priority_level(ves_score: float, kev_status: bool) -> int:
        """Calculate priority level (1=highest, 4=lowest)"""
        if kev_status:
            return 1
        elif ves_score >= 0.8:
            return 1
        elif ves_score >= 0.6:
            return 2
        elif ves_score >= 0.3:
            return 3
        else:
            return 4
    
    @staticmethod
    def calculate_ves_score(metrics: VulnerabilityMetrics) -> float:
        """Calculate unified VES score using weighted combination with dynamic weighting"""
        cvss_normalized = (metrics.cvss_score or 0) / 10.0
        epss_normalized = metrics.epss_score or 0.0
        lev_normalized = metrics.lev_score or 0.0
        
        # Dynamic weighting based on available data
        if metrics.lev_score is not None:
            # Full VES calculation with all metrics
            base_score = (
                0.4 * epss_normalized +  # Prediction weight (highest)
                0.3 * cvss_normalized +  # Severity weight
                0.3 * lev_normalized     # Historical weight
            )
        else:
            # VES calculation without LEV (fast mode)
            # Redistribute LEV weight between CVSS and EPSS
            base_score = (
                0.55 * epss_normalized +  # Increased prediction weight
                0.45 * cvss_normalized    # Increased severity weight
            )
        
        kev_multiplier = 1.5 if metrics.kev_status else 1.0
        final_score = min(base_score * kev_multiplier, 1.0)
        
        return round(final_score, 6)
