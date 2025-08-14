"""Single CVE scan command"""

import asyncio
import logging
import sys
import click

from ...processing.processor import VESProcessor
from ..formatters.table import TableFormatter
from ..formatters.json import JSONFormatter
from ..formatters.csv import CSVFormatter


@click.command()
@click.argument('cve_id')
@click.option('--format', type=click.Choice(['json', 'table', 'csv']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.option('--timeout', default=180, help='Timeout in seconds (default: 180)')
@click.option('--debug', is_flag=True, help='Enable debug logging for this command')
@click.option('--skip-lev', is_flag=True, help='Skip LEV calculation for faster results')
@click.option('--fast', is_flag=True, help='Use fast mode (skips LEV, shorter timeouts)')
@click.option('--lev-timeout', default=30, help='Timeout for LEV calculation only (default: 30)')
@click.pass_context
def scan(ctx, cve_id, format, output, timeout, debug, skip_lev, fast, lev_timeout):
    """Scan a single CVE and calculate VES score
    
    Examples:
        ves scan CVE-2021-44228                    # Full analysis with LEV
        ves scan CVE-2021-44228 --fast             # Quick analysis, skips LEV  
        ves scan CVE-2021-44228 --skip-lev         # Skip only LEV calculation
        ves scan CVE-2021-44228 --format csv       # CSV output format
        ves scan CVE-2021-44228 --debug            # Enable debug logging
        ves scan CVE-2021-44228 --lev-timeout 15   # Shorter LEV timeout
        ves scan CVE-2021-44228 --timeout 60       # Overall timeout
    """
    config = ctx.obj['config']
    
    # Fast mode implies skip LEV and shorter timeouts
    if fast:
        skip_lev = True
        timeout = min(timeout, 60)
        lev_timeout = min(lev_timeout, 15)
        click.echo("Fast mode enabled - LEV calculation disabled for speed")
    
    # Force debug logging if requested
    if debug or config.log_level.upper() == 'DEBUG':
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        if not root_logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            root_logger.addHandler(handler)
        
        for handler in root_logger.handlers:
            handler.setLevel(logging.DEBUG)
        
        config.log_level = 'DEBUG'
        click.echo("Debug logging enabled")
    
    async def process():
        try:
            # Validate CVE format
            if not cve_id.upper().startswith('CVE-'):
                click.echo(f"Warning: '{cve_id}' doesn't follow CVE format (CVE-YYYY-NNNNN)")
                click.echo("Proceeding anyway...")
            
            # Show processing info
            mode_text = "FAST MODE" if fast else "FULL ANALYSIS"
            if skip_lev and not fast:
                mode_text += " (LEV disabled)"
            
            click.echo(f"VES {mode_text}")
            click.echo(f"Processing {cve_id.upper()}...")
            click.echo(f"Timeout: {timeout} seconds")
            
            if skip_lev:
                click.echo("LEV calculation disabled - using CVSS, EPSS, and KEV only")
            else:
                click.echo(f"Full VES analysis with LEV (LEV timeout: {lev_timeout}s)")
            
            # Store LEV timeout in config for processor to use
            config.lev_timeout = lev_timeout
            
            async with VESProcessor(config) as processor:
                try:
                    result = await asyncio.wait_for(
                        processor.process_single_cve(cve_id.upper(), skip_lev=skip_lev),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    click.echo(f"\nOperation timed out after {timeout} seconds")
                    click.echo("\nTry these options to resolve the issue:")
                    click.echo("  - Fast mode: ves scan CVE-2021-44228 --fast")
                    click.echo("  - Skip LEV: ves scan CVE-2021-44228 --skip-lev") 
                    click.echo("  - Shorter LEV timeout: ves scan CVE-2021-44228 --lev-timeout 15")
                    click.echo("  - Debug mode: ves scan CVE-2021-44228 --debug")
                    click.echo("  - Check network connectivity")
                    click.echo(f"  - Verify CVE exists: https://nvd.nist.gov/vuln/detail/{cve_id}")
                    
                    # Run diagnostic
                    click.echo("\nRunning quick diagnostic...")
                    await _run_quick_diagnostic(cve_id)
                    return
                
                # Format output
                if format == 'json':
                    output_text = JSONFormatter.format_single(result)
                elif format == 'csv':
                    # For CSV, create headers and single row
                    import io
                    import csv
                    output_buffer = io.StringIO()
                    writer = csv.writer(output_buffer)
                    writer.writerow(CSVFormatter.get_headers())
                    writer.writerow(CSVFormatter.format_row(result))
                    output_text = output_buffer.getvalue().strip()
                else:
                    output_text = TableFormatter.format_single(result)
                
                # Save or display results
                if output:
                    with open(output, 'w') as f:
                        f.write(output_text)
                    click.echo(f"Results saved to {output}")
                else:
                    if format == 'csv':
                        click.echo(output_text)
                    else:
                        click.echo("\n" + "="*60)
                        if skip_lev:
                            click.echo("VES ANALYSIS RESULTS (LEV DISABLED)")
                        else:
                            click.echo("VES ANALYSIS RESULTS")
                        click.echo("="*60)
                        click.echo(output_text)
                
                # Enhanced summary (skip for CSV format to keep it clean)
                if format != 'csv':
                    _display_clean_summary(result, skip_lev, fast)
                
        except Exception as e:
            click.echo(f"\nError: {e}")
            if debug or config.log_level.upper() == 'DEBUG':
                import traceback
                click.echo("\nDebug traceback:")
                click.echo(traceback.format_exc())
            else:
                click.echo("\nUse --debug for detailed error information")
                click.echo("Or try --fast mode for quicker results")
    
    asyncio.run(process())


async def _run_quick_diagnostic(cve_id):
    """Quick diagnostic to identify the issue"""
    import aiohttp
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            # Test NVD API
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            try:
                async with session.get(nvd_url) as response:
                    click.echo(f"   NVD API: {response.status} (working)")
            except:
                click.echo(f"   NVD API: Failed")
            
            # Test EPSS current API
            epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            try:
                async with session.get(epss_url) as response:
                    click.echo(f"   EPSS API: {response.status} (working)")
            except:
                click.echo(f"   EPSS API: Failed")
            
            # Test EPSS time-series API
            time_series_url = f"https://api.first.org/data/v1/epss?cve={cve_id}&scope=time-series"
            try:
                async with session.get(time_series_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    click.echo(f"   EPSS Time-series: {response.status} (working)")
            except asyncio.TimeoutError:
                click.echo(f"   EPSS Time-series: TIMEOUT (this is the problem)")
            except Exception as e:
                click.echo(f"   EPSS Time-series: Failed ({str(e)[:50]})")
            
    except Exception:
        click.echo("   Diagnostic failed")
    
    click.echo("\nQuick fix: Use --skip-lev flag to bypass the problematic time-series API")


def _display_clean_summary(result, skip_lev, fast):
    """Display clean analysis summary without emojis"""
    click.echo(f"\nSUMMARY:")
    
    if result.ves_score is not None:
        click.echo(f"VES Score: {result.ves_score:.4f}")
    else:
        click.echo(f"VES Score: Unable to calculate")
    
    priority_text = {1: "IMMEDIATE", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}.get(result.priority_level, "UNKNOWN")
    click.echo(f"Priority Level: {result.priority_level} ({priority_text})")
    
    # Priority explanation
    if result.priority_level == 1:
        if result.kev_status:
            click.echo(f"URGENT: Known Exploited Vulnerability in CISA KEV")
            click.echo(f"This vulnerability is being actively exploited")
        else:
            click.echo(f"URGENT: Very High Risk (VES >= 0.8)")
            click.echo(f"Prioritize for immediate patching")
    elif result.priority_level == 2:
        click.echo(f"HIGH: Prioritize for patching within 1 week")
    elif result.priority_level == 3:
        click.echo(f"MEDIUM: Include in regular patching cycle")
    else:
        click.echo(f"LOW: Standard priority")
    
    # Performance notes
    if skip_lev or fast:
        click.echo(f"\nPerformance Notes:")
        if fast:
            click.echo(f"Fast mode completed quickly without LEV")
        else:
            click.echo(f"LEV calculation skipped for speed")
        click.echo(f"VES score calculated using CVSS, EPSS, and KEV only")
        
    if result.priority_level <= 2:
        click.echo(f"\nACTION REQUIRED: This vulnerability needs attention")
        if result.kev_status:
            click.echo(f"Check CISA KEV for required action timeline")
    
    # Next steps
    click.echo(f"\nNext Steps:")
    if result.kev_status:
        click.echo(f"IMMEDIATE: Patch this CVE - it's actively exploited")
    elif result.priority_level == 1:
        click.echo(f"HIGH: Schedule patching within 72 hours")
    elif result.priority_level == 2:
        click.echo(f"MEDIUM: Schedule patching within 1 week") 
    else:
        click.echo(f"STANDARD: Include in regular patching cycle")
    
    if result.epss_score and result.epss_score > 0.7:
        click.echo(f"Monitor threat intelligence - high exploitation probability")
    
    if result.cvss_score and result.cvss_score >= 9.0:
        click.echo(f"Review network segmentation and access controls")
