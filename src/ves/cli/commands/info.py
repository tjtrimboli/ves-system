"""Detailed CVE information command"""

import asyncio
import click
from datetime import datetime

from ...processing.processor import VESProcessor


@click.command()
@click.argument('cve_id')
@click.option('--report', is_flag=True, help='Generate professional report format for documentation')
@click.pass_context
def info(ctx, cve_id, report):
    """Get detailed information about a CVE
    
    Examples:
        ves info CVE-2021-44228
        ves info CVE-2021-44228 --report    # Professional report format
    """
    config = ctx.obj['config']
    
    async def process():
        async with VESProcessor(config) as processor:
            click.echo(f"Fetching detailed information for {cve_id}...")
            result = await processor.process_single_cve(cve_id)
            
            if report:
                _display_professional_report(result)
            else:
                _display_standard_analysis(result)
    
    asyncio.run(process())


def _display_standard_analysis(result):
    """Display standard detailed analysis"""
    click.echo(f"\n{'='*70}")
    click.echo(f"CVE DETAILED ANALYSIS: {result.cve_id}")
    click.echo(f"{'='*70}")
    
    # VES Scoring Section
    click.echo(f"\nVES SCORING BREAKDOWN:")
    if result.ves_score is not None:
        click.echo(f"   Final VES Score: {result.ves_score:.6f}")
        click.echo(f"   Priority Level: {result.priority_level} {'(URGENT)' if result.priority_level == 1 else ''}")
        
        # Show scoring components
        click.echo(f"\n   Scoring Components:")
        if result.epss_score is not None:
            epss_contribution = 0.4 * result.epss_score
            click.echo(f"      * EPSS (40% weight): {result.epss_score:.6f} -> {epss_contribution:.6f}")
        
        if result.cvss_score is not None:
            cvss_normalized = result.cvss_score / 10.0
            cvss_contribution = 0.3 * cvss_normalized
            click.echo(f"      * CVSS (30% weight): {result.cvss_score}/10.0 -> {cvss_contribution:.6f}")
        
        if result.lev_score is not None:
            lev_contribution = 0.3 * result.lev_score
            click.echo(f"      * LEV (30% weight):  {result.lev_score:.6f} -> {lev_contribution:.6f}")
        
        if result.kev_status:
            click.echo(f"      * KEV Multiplier: 1.5x (Known Exploited)")
    else:
        click.echo(f"   VES Score: Unable to calculate")
    
    # Individual Metrics Section
    click.echo(f"\nINDIVIDUAL METRICS:")
    
    # CVSS Information
    click.echo(f"   CVSS Analysis:")
    if result.cvss_score is not None:
        click.echo(f"      Score: {result.cvss_score}/10.0")
        click.echo(f"      Severity: {result.severity.value}")
        if result.cvss_vector:
            click.echo(f"      Vector: {result.cvss_vector}")
    else:
        click.echo(f"      Score: Not Available")
    
    # EPSS Information
    click.echo(f"   EPSS Analysis:")
    if result.epss_score is not None:
        click.echo(f"      Score: {result.epss_score:.6f} ({result.epss_score*100:.2f}% exploitation probability)")
        if result.epss_percentile is not None:
            percentile_display = result.epss_percentile * 100 if result.epss_percentile <= 1.0 else result.epss_percentile
            click.echo(f"      Percentile: {percentile_display:.2f}%")
        _interpret_epss_score(result.epss_score, result.epss_percentile)
    else:
        click.echo(f"      Score: Not Available")
    
    # KEV Status
    click.echo(f"   KEV Status:")
    if result.kev_status:
        click.echo(f"      Status: KNOWN EXPLOITED VULNERABILITY")
        click.echo(f"      WARNING: This CVE is actively being exploited in the wild")
    else:
        click.echo(f"      Status: Not in KEV catalog")
    
    # LEV Analysis
    click.echo(f"   LEV Analysis:")
    if result.lev_score is not None:
        click.echo(f"      Score: {result.lev_score:.6f}")
        _interpret_lev_score(result.lev_score)
    else:
        click.echo(f"      Score: Unable to calculate (insufficient data)")
    
    # Timeline Section
    click.echo(f"\nVULNERABILITY TIMELINE:")
    if result.published_date:
        click.echo(f"   Published: {result.published_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        days_old = (datetime.now() - result.published_date.replace(tzinfo=None)).days
        click.echo(f"   Age: {days_old} days old")
    else:
        click.echo(f"   Published: Unknown")
    
    if result.last_modified:
        click.echo(f"   Last Modified: {result.last_modified.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    
    # Description Section
    if result.description:
        click.echo(f"\nDESCRIPTION:")
        import textwrap
        wrapped_desc = textwrap.fill(result.description, width=65, initial_indent="   ", subsequent_indent="   ")
        click.echo(wrapped_desc)
    
    # Recommendations Section
    click.echo(f"\nRECOMMENDATIONS:")
    _provide_recommendations(result)


def _display_professional_report(result):
    """Display professional report format suitable for Word documents"""
    current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Report Header
    click.echo("="*80)
    click.echo("VULNERABILITY ANALYSIS REPORT")
    click.echo("="*80)
    click.echo(f"CVE ID: {result.cve_id}")
    click.echo(f"Analysis Date: {current_date}")
    click.echo(f"Report Generated by: VES (Vulnerability Evaluation System)")
    click.echo("="*80)
    
    # Executive Summary
    click.echo("\nEXECUTIVE SUMMARY")
    click.echo("-" * 40)
    
    if result.ves_score is not None:
        risk_level = _get_risk_level_text(result.ves_score, result.kev_status)
        click.echo(f"Overall Risk Level: {risk_level}")
        click.echo(f"VES Score: {result.ves_score:.4f} (Scale: 0.0000 - 1.0000)")
        click.echo(f"Priority Level: {result.priority_level} ({_get_priority_text(result.priority_level)})")
    else:
        click.echo(f"Overall Risk Level: Unable to determine")
        click.echo(f"VES Score: Calculation failed")
    
    if result.kev_status:
        click.echo(f"KEV Status: ACTIVE EXPLOITATION CONFIRMED")
        click.echo(f"CRITICAL: This vulnerability is being exploited in the wild")
    
    # Vulnerability Details
    click.echo(f"\nVULNERABILITY DETAILS")
    click.echo("-" * 40)
    
    if result.published_date:
        days_old = (datetime.now() - result.published_date.replace(tzinfo=None)).days
        click.echo(f"Publication Date: {result.published_date.strftime('%Y-%m-%d')}")
        click.echo(f"Vulnerability Age: {days_old} days")
    
    if result.description:
        click.echo(f"Description:")
        import textwrap
        wrapped_desc = textwrap.fill(result.description, width=70, initial_indent="  ", subsequent_indent="  ")
        click.echo(wrapped_desc)
    
    # Technical Assessment
    click.echo(f"\nTECHNICAL ASSESSMENT")
    click.echo("-" * 40)
    
    # CVSS Analysis
    click.echo(f"CVSS Analysis:")
    if result.cvss_score is not None:
        click.echo(f"  Score: {result.cvss_score}/10.0")
        click.echo(f"  Severity: {result.severity.value}")
        click.echo(f"  Impact: {_get_cvss_impact_description(result.cvss_score)}")
        if result.cvss_vector:
            click.echo(f"  Vector String: {result.cvss_vector}")
    else:
        click.echo(f"  Score: Not available from NVD")
    
    click.echo()
    
    # EPSS Analysis
    click.echo(f"EPSS (Exploit Prediction) Analysis:")
    if result.epss_score is not None:
        click.echo(f"  Probability Score: {result.epss_score:.6f}")
        click.echo(f"  Exploitation Likelihood: {result.epss_score*100:.2f}% within 30 days")
        click.echo(f"  Risk Category: {_get_epss_risk_category(result.epss_score)}")
        if result.epss_percentile is not None:
            percentile_display = result.epss_percentile * 100 if result.epss_percentile <= 1.0 else result.epss_percentile
            click.echo(f"  Percentile Ranking: {percentile_display:.2f}%")
    else:
        click.echo(f"  Score: Not available from EPSS API")
    
    click.echo()
    
    # LEV Analysis
    click.echo(f"LEV (Likely Exploited Vulnerabilities) Analysis:")
    if result.lev_score is not None:
        click.echo(f"  LEV Score: {result.lev_score:.6f}")
        click.echo(f"  Historical Risk: {_get_lev_risk_category(result.lev_score)}")
        click.echo(f"  Methodology: NIST CSWP 41 (May 2025)")
    else:
        click.echo(f"  Score: Unable to calculate (insufficient historical data)")
    
    # VES Calculation Details
    if result.ves_score is not None:
        click.echo(f"\nVES CALCULATION METHODOLOGY")
        click.echo("-" * 40)
        click.echo(f"VES uses a weighted combination of security metrics:")
        
        if result.lev_score is not None:
            click.echo(f"  * EPSS (40%): Predictive exploitation probability")
            click.echo(f"  * CVSS (30%): Technical severity assessment")
            click.echo(f"  * LEV (30%):  Historical exploitation evidence")
        else:
            click.echo(f"  * EPSS (55%): Predictive exploitation probability")
            click.echo(f"  * CVSS (45%): Technical severity assessment")
            click.echo(f"  * LEV: Not available (using fast calculation mode)")
        
        if result.kev_status:
            click.echo(f"  * KEV Multiplier: 1.5x applied for confirmed exploitation")
        
        click.echo(f"Final VES Score: {result.ves_score:.6f}")
    
    # Risk Assessment and Recommendations
    click.echo(f"\nRISK ASSESSMENT & RECOMMENDATIONS")
    click.echo("-" * 40)
    
    recommendations = _get_professional_recommendations(result)
    for category, items in recommendations.items():
        click.echo(f"{category}:")
        for item in items:
            click.echo(f"  * {item}")
        click.echo()
    
    # Footer
    click.echo("="*80)
    click.echo("End of Report")
    click.echo(f"Generated by VES CLI v1.0.0")
    click.echo(f"Data Sources: NVD, FIRST EPSS, CISA KEV")
    click.echo("="*80)


def _interpret_epss_score(epss_score, percentile):
    """Provide interpretation of EPSS score based on probability"""
    if epss_score >= 0.8:
        click.echo(f"      Extremely High Risk - {epss_score*100:.1f}% exploitation probability")
    elif epss_score >= 0.6:
        click.echo(f"      Very High Risk - {epss_score*100:.1f}% exploitation probability")
    elif epss_score >= 0.3:
        click.echo(f"      High Risk - {epss_score*100:.1f}% exploitation probability")
    elif epss_score >= 0.1:
        click.echo(f"      Medium Risk - {epss_score*100:.1f}% exploitation probability")
    else:
        click.echo(f"      Lower Risk - {epss_score*100:.2f}% exploitation probability")


def _interpret_lev_score(lev_score):
    """Provide interpretation of LEV score"""
    if lev_score >= 0.8:
        click.echo(f"      Very High - Strong evidence of historical exploitation")
    elif lev_score >= 0.6:
        click.echo(f"      High - Moderate evidence of historical exploitation")
    elif lev_score >= 0.3:
        click.echo(f"      Medium - Some evidence of historical exploitation")
    else:
        click.echo(f"      Low - Limited evidence of historical exploitation")


def _provide_recommendations(result):
    """Provide actionable recommendations"""
    if result.kev_status:
        click.echo(f"   URGENT: Patch immediately - actively exploited")
        click.echo(f"   Check CISA KEV catalog for required action date")
    elif result.priority_level == 1:
        click.echo(f"   HIGH PRIORITY: Schedule patching within 72 hours")
    elif result.priority_level == 2:
        click.echo(f"   MEDIUM PRIORITY: Schedule patching within 1 week")
    else:
        click.echo(f"   STANDARD: Include in regular patching cycle")
    
    if result.epss_score and result.epss_score > 0.7:
        click.echo(f"   Monitor threat intelligence - high exploitation probability")
    
    if result.cvss_score and result.cvss_score >= 9.0:
        click.echo(f"   Review network segmentation and access controls")


# Professional report helper functions
def _get_risk_level_text(ves_score, kev_status):
    """Get overall risk level text for professional reports"""
    if kev_status:
        return "CRITICAL (Active Exploitation)"
    elif ves_score >= 0.8:
        return "CRITICAL"
    elif ves_score >= 0.6:
        return "HIGH"
    elif ves_score >= 0.3:
        return "MEDIUM"
    else:
        return "LOW"


def _get_priority_text(priority_level):
    """Get priority text for professional reports"""
    priority_map = {
        1: "Immediate Action Required",
        2: "High Priority", 
        3: "Medium Priority",
        4: "Low Priority"
    }
    return priority_map.get(priority_level, "Unknown")


def _get_cvss_impact_description(cvss_score):
    """Get CVSS impact description for professional reports"""
    if cvss_score >= 9.0:
        return "Critical impact to confidentiality, integrity, or availability"
    elif cvss_score >= 7.0:
        return "High impact to confidentiality, integrity, or availability"
    elif cvss_score >= 4.0:
        return "Medium impact to confidentiality, integrity, or availability"
    else:
        return "Low impact to confidentiality, integrity, or availability"


def _get_epss_risk_category(epss_score):
    """Get EPSS risk category for professional reports"""
    if epss_score >= 0.8:
        return "Extremely High Risk"
    elif epss_score >= 0.6:
        return "Very High Risk"
    elif epss_score >= 0.3:
        return "High Risk"
    elif epss_score >= 0.1:
        return "Medium Risk"
    else:
        return "Low Risk"


def _get_lev_risk_category(lev_score):
    """Get LEV risk category for professional reports"""
    if lev_score >= 0.8:
        return "Very High Historical Risk"
    elif lev_score >= 0.6:
        return "High Historical Risk"
    elif lev_score >= 0.3:
        return "Medium Historical Risk"
    else:
        return "Low Historical Risk"


def _get_professional_recommendations(result):
    """Get structured recommendations for professional reports"""
    recommendations = {
        "Immediate Actions": [],
        "Short-term Actions (1-7 days)": [],
        "Long-term Actions": [],
        "Monitoring Requirements": []
    }
    
    if result.kev_status:
        recommendations["Immediate Actions"].append("Apply security patch immediately - vulnerability is actively exploited")
        recommendations["Immediate Actions"].append("Review CISA KEV catalog for specific action timeline")
        recommendations["Immediate Actions"].append("Implement emergency controls if patching is not immediately possible")
    elif result.priority_level == 1:
        recommendations["Immediate Actions"].append("Schedule emergency patching within 72 hours")
        recommendations["Short-term Actions (1-7 days)"].append("Verify patch deployment across all affected systems")
    elif result.priority_level == 2:
        recommendations["Short-term Actions (1-7 days)"].append("Schedule patching within one week")
        recommendations["Short-term Actions (1-7 days)"].append("Prioritize internet-facing and critical systems")
    else:
        recommendations["Long-term Actions"].append("Include in regular patch management cycle")
    
    if result.epss_score and result.epss_score > 0.7:
        recommendations["Monitoring Requirements"].append("Monitor threat intelligence for exploitation activity")
        recommendations["Monitoring Requirements"].append("Implement additional detection rules for this vulnerability")
    
    if result.cvss_score and result.cvss_score >= 9.0:
        recommendations["Short-term Actions (1-7 days)"].append("Review network segmentation controls")
        recommendations["Short-term Actions (1-7 days)"].append("Verify access controls for affected systems")
    
    if result.ves_score and result.ves_score >= 0.8:
        recommendations["Immediate Actions"].append("Conduct impact assessment for affected systems")
        recommendations["Short-term Actions (1-7 days)"].append("Review security controls for affected asset classes")
    
    # Remove empty categories
    return {k: v for k, v in recommendations.items() if v}
