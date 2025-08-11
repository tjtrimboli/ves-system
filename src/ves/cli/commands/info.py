"""Detailed CVE information command"""

import asyncio
import click

from ...processing.processor import VESProcessor


@click.command()
@click.argument('cve_id')
@click.pass_context
def info(ctx, cve_id):
    """Get detailed information about a CVE
    
    Example:
        ves info CVE-2021-44228
    """
    config = ctx.obj['config']
    
    async def process():
        async with VESProcessor(config) as processor:
            click.echo(f"Fetching detailed information for {cve_id}...")
            result = await processor.process_single_cve(cve_id)
            
            # Display detailed information
            click.echo(f"\n{'='*70}")
            click.echo(f"CVE DETAILED ANALYSIS: {cve_id}")
            click.echo(f"{'='*70}")
            
            # VES Scoring Section
            click.echo(f"\n📊 VES SCORING BREAKDOWN:")
            if result.ves_score is not None:
                click.echo(f"   🎯 Final VES Score: {result.ves_score:.6f}")
                click.echo(f"   📋 Priority Level: {result.priority_level} {'(URGENT!)' if result.priority_level == 1 else ''}")
                
                # Show scoring components
                click.echo(f"\n   📐 Scoring Components:")
                if result.epss_score is not None:
                    epss_contribution = 0.4 * result.epss_score
                    click.echo(f"      • EPSS (40% weight): {result.epss_score:.6f} → {epss_contribution:.6f}")
                
                if result.cvss_score is not None:
                    cvss_normalized = result.cvss_score / 10.0
                    cvss_contribution = 0.3 * cvss_normalized
                    click.echo(f"      • CVSS (30% weight): {result.cvss_score}/10.0 → {cvss_contribution:.6f}")
                
                if result.lev_score is not None:
                    lev_contribution = 0.3 * result.lev_score
                    click.echo(f"      • LEV (30% weight):  {result.lev_score:.6f} → {lev_contribution:.6f}")
                
                if result.kev_status:
                    click.echo(f"      • KEV Multiplier: 1.5x (Known Exploited!)")
            else:
                click.echo(f"   ❌ VES Score: Unable to calculate")
            
            # Individual Metrics Section
            click.echo(f"\n🔍 INDIVIDUAL METRICS:")
            
            # CVSS Information
            click.echo(f"   🛡️  CVSS Analysis:")
            if result.cvss_score is not None:
                click.echo(f"      Score: {result.cvss_score}/10.0")
                click.echo(f"      Severity: {result.severity.value}")
                if result.cvss_vector:
                    click.echo(f"      Vector: {result.cvss_vector}")
            else:
                click.echo(f"      Score: Not Available")
            
            # EPSS Information
            click.echo(f"   📈 EPSS Analysis:")
            if result.epss_score is not None:
                click.echo(f"      Score: {result.epss_score:.6f}")
                if result.epss_percentile is not None:
                    click.echo(f"      Percentile: {result.epss_percentile:.2f}%")
                    _interpret_epss_score(result.epss_score, result.epss_percentile)
            else:
                click.echo(f"      Score: Not Available")
            
            # KEV Status
            click.echo(f"   🚨 KEV Status:")
            if result.kev_status:
                click.echo(f"      Status: 🔴 KNOWN EXPLOITED VULNERABILITY")
                click.echo(f"      ⚠️  This CVE is actively being exploited in the wild!")
            else:
                click.echo(f"      Status: ✅ Not in KEV catalog")
            
            # LEV Analysis
            click.echo(f"   📊 LEV Analysis:")
            if result.lev_score is not None:
                click.echo(f"      Score: {result.lev_score:.6f}")
                _interpret_lev_score(result.lev_score)
            else:
                click.echo(f"      Score: Unable to calculate (insufficient data)")
            
            # Timeline Section
            click.echo(f"\n📅 VULNERABILITY TIMELINE:")
            if result.published_date:
                click.echo(f"   📅 Published: {result.published_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                days_old = (asyncio.get_event_loop().time() - result.published_date.timestamp()) / 86400
                click.echo(f"   ⏰ Age: {int(days_old)} days old")
            else:
                click.echo(f"   📅 Published: Unknown")
            
            if result.last_modified:
                click.echo(f"   🔄 Last Modified: {result.last_modified.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            
            # Description Section
            if result.description:
                click.echo(f"\n📝 DESCRIPTION:")
                # Word wrap the description
                import textwrap
                wrapped_desc = textwrap.fill(result.description, width=65, initial_indent="   ", subsequent_indent="   ")
                click.echo(wrapped_desc)
            
            # Recommendations Section
            click.echo(f"\n💡 RECOMMENDATIONS:")
            _provide_recommendations(result)
    
    asyncio.run(process())


def _interpret_epss_score(epss_score, percentile):
    """Provide interpretation of EPSS score"""
    if percentile >= 99:
        click.echo(f"      🔴 Extremely High Risk - Top 1% most likely to be exploited")
    elif percentile >= 95:
        click.echo(f"      🟠 Very High Risk - Top 5% most likely to be exploited")
    elif percentile >= 80:
        click.echo(f"      🟡 High Risk - Top 20% most likely to be exploited")
    elif percentile >= 50:
        click.echo(f"      🟢 Medium Risk - Above average exploitation likelihood")
    else:
        click.echo(f"      ⚪ Lower Risk - Below average exploitation likelihood")


def _interpret_lev_score(lev_score):
    """Provide interpretation of LEV score"""
    if lev_score >= 0.8:
        click.echo(f"      🔴 Very High - Strong evidence of historical exploitation")
    elif lev_score >= 0.6:
        click.echo(f"      🟠 High - Moderate evidence of historical exploitation")
    elif lev_score >= 0.3:
        click.echo(f"      🟡 Medium - Some evidence of historical exploitation")
    else:
        click.echo(f"      🟢 Low - Limited evidence of historical exploitation")


def _provide_recommendations(result):
    """Provide actionable recommendations based on analysis"""
    if result.kev_status:
        click.echo(f"   🚨 URGENT: Patch immediately - actively exploited!")
        click.echo(f"   📋 Check CISA KEV catalog for required action date")
    elif result.priority_level == 1:
        click.echo(f"   ⚡ HIGH PRIORITY: Schedule patching within 72 hours")
    elif result.priority_level == 2:
        click.echo(f"   🔥 MEDIUM PRIORITY: Schedule patching within 1 week")
    else:
        click.echo(f"   📅 STANDARD: Include in regular patching cycle")
    
    if result.epss_score and result.epss_score > 0.7:
        click.echo(f"   🎯 Monitor threat intelligence - high exploitation probability")
    
    if result.cvss_score and result.cvss_score >= 9.0:
        click.echo(f"   🛡️  Review network segmentation and access controls")
