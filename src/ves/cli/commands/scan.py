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
@click.option('--timeout', default=120, help='Timeout in seconds (default: 120)')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.pass_context
def scan(ctx, cve_id, format, output, timeout, debug):
    """Scan a single CVE and calculate VES score
    
    Example:
        ves scan CVE-2021-44228
        ves scan CVE-2021-44228 --format json
        ves scan CVE-2021-44228 --output results.json --debug
    """
    config = ctx.obj['config']
    
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
            
            click.echo(f"🔍 Processing {cve_id.upper()}...")
            click.echo(f"⏰ Timeout set to {timeout} seconds")
            
            async with VESProcessor(config) as processor:
                # Use asyncio.wait_for to enforce timeout
                result = await asyncio.wait_for(
                    processor.process_single_cve(cve_id.upper()),
                    timeout=timeout
                )
                
                if format == 'json':
                    output_text = JSONFormatter.format_single(result)
                else:
                    output_text = TableFormatter.format_single(result)
                
                if output:
                    with open(output, 'w') as f:
                        f.write(output_text)
                    click.echo(f"💾 Results saved to {output}")
                else:
                    click.echo("\n" + "="*60)
                    click.echo("🎯 VES ANALYSIS RESULTS")
                    click.echo("="*60)
                    click.echo(output_text)
                
                # Show summary
                if result.ves_score:
                    click.echo(f"\n📊 Quick Summary:")
                    click.echo(f"   VES Score: {result.ves_score:.4f}")
                    click.echo(f"   Priority: {result.priority_level}")
                    if result.kev_status:
                        click.echo(f"   🚨 WARNING: Known Exploited Vulnerability!")
                
        except asyncio.TimeoutError:
            click.echo(f"\n⏰ Operation timed out after {timeout} seconds")
            click.echo("💡 Try:")
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
    
    asyncio.run(process())
