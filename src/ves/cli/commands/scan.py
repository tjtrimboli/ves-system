"""Single CVE scan command"""

import asyncio
import logging
import click

from ...processing.processor import VESProcessor
from ..formatters.table import TableFormatter
from ..formatters.json import JSONFormatter


@click.command()
@click.argument('cve_id')
@click.option('--format', type=click.Choice(['json', 'table']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.option('--timeout', default=180, help='Timeout in seconds (default: 180)')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--skip-lev', is_flag=True, help='Skip LEV calculation for faster results')
@click.option('--fast', is_flag=True, help='Use fast mode (skips LEV, shorter timeouts)')
@click.pass_context
def scan(ctx, cve_id, format, output, timeout, debug, skip_lev, fast):
    """Scan a single CVE and calculate VES score
    
    Examples:
        ves scan CVE-2021-44228                    # Full analysis with LEV
        ves scan CVE-2021-44228 --fast             # Quick analysis, skips LEV
        ves scan CVE-2021-44228 --skip-lev         # Skip only LEV calculation
        ves scan CVE-2021-44228 --format json      # JSON output
        ves scan CVE-2021-44228 --debug            # Verbose logging
    """
    config = ctx.obj['config']
    
    # Fast mode implies skip LEV and shorter timeout
    if fast:
        skip_lev = True
        timeout = min(timeout, 60)  # Max 60 seconds in fast mode
        click.echo("🚀 Fast mode enabled - LEV calculation disabled for speed")
    
    # Enable debug logging if requested
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        config.log_level = 'DEBUG'
    
    async def process():
        try:
            # Validate CVE format
            if not cve_id.upper().startswith('CVE-'):
                click.echo(f"⚠️  Warning: '{cve_id}' doesn't follow CVE format (CVE-YYYY-NNNNN)")
                click.echo("Proceeding anyway...")
            
            # Show processing info
            mode_text = "🚀 FAST MODE" if fast else "🔍 FULL ANALYSIS"
            if skip_lev and not fast:
                mode_text += " (LEV disabled)"
            
            click.echo(f"{mode_text}")
            click.echo(f"🔍 Processing {cve_id.upper()}...")
            click.echo(f"⏰ Timeout set to {timeout} seconds")
            
            if skip_lev:
                click.echo("📊 LEV calculation disabled - using CVSS, EPSS, and KEV only")
            else:
                click.echo("📊 Full VES analysis with LEV calculation")
            
            async with VESProcessor(config) as processor:
                # Use asyncio.wait_for to enforce timeout
                result = await asyncio.wait_for(
                    processor.process_single_cve(cve_id.upper(), skip_lev=skip_lev),
                    timeout=timeout
                )
                
                # Format output
                if format == 'json':
                    output_text = JSONFormatter.format_single(result)
                else:
                    output_text = TableFormatter.format_single(result)
                
                # Save or display results
                if output:
                    with open(output, 'w') as f:
                        f.write(output_text)
                    click.echo(f"💾 Results saved to {output}")
                else:
                    click.echo("\n" + "="*60)
                    if skip_lev:
                        click.echo("🎯 VES ANALYSIS RESULTS (LEV DISABLED)")
                    else:
                        click.echo("🎯 VES ANALYSIS RESULTS")
                    click.echo("="*60)
                    click.echo(output_text)
                
                # Show enhanced summary
                click.echo(f"\n📊 Analysis Summary:")
                click.echo(f"   VES Score: {result.ves_score:.4f}" if result.ves_score else "   VES Score: Unable to calculate")
                click.echo(f"   Priority Level: {result.priority_level}")
                
                # Priority explanation
                if result.priority_level == 1:
                    if result.kev_status:
                        click.echo(f"   🚨 URGENT: Known Exploited Vulnerability!")
                    else:
                        click.echo(f"   🚨 URGENT: Very High Risk")
                elif result.priority_level == 2:
                    click.echo(f"   🔥 HIGH: Prioritize for patching")
                elif result.priority_level == 3:
                    click.echo(f"   🟡 MEDIUM: Include in regular cycle")
                else:
                    click.echo(f"   ✅ LOW: Standard priority")
                
                # Component breakdown
                click.echo(f"\n🔍 Component Scores:")
                if result.cvss_score:
                    click.echo(f"   CVSS: {result.cvss_score}/10.0 ({result.severity.value})")
                if result.epss_score:
                    click.echo(f"   EPSS: {result.epss_score:.6f} ({result.epss_percentile:.2f}%)")
                if result.lev_score:
                    click.echo(f"   LEV:  {result.lev_score:.6f}")
                elif not skip_lev:
                    click.echo(f"   LEV:  Unable to calculate")
                
                if result.kev_status:
                    click.echo(f"   KEV:  🚨 KNOWN EXPLOITED")
                
                # Performance tips
                if not fast and not skip_lev:
                    click.echo(f"\n💡 Performance tip: Use --fast for quicker scans")
                
        except asyncio.TimeoutError:
            click.echo(f"\n⏰ Operation timed out after {timeout} seconds")
            click.echo("💡 Try one of these options:")
            click.echo("   • Use fast mode: --fast")
            click.echo("   • Skip LEV calculation: --skip-lev")
            click.echo("   • Increase timeout: --timeout 300")
            click.echo("   • Enable debug mode: --debug") 
            click.echo("   • Check network connectivity")
            click.echo("   • Verify CVE exists: https://nvd.nist.gov/vuln/detail/" + cve_id)
        except Exception as e:
            click.echo(f"\n💥 Error: {e}")
            if debug:
                import traceback
                click.echo("\n🔍 Debug traceback:")
                click.echo(traceback.format_exc())
            else:
                click.echo("\n💡 Use --debug for detailed error information")
    
    asyncio.run(process())
